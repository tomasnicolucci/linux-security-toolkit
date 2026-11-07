import json
import re
import shutil
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from src.audit import comparison, runner
from src.audit.adapters import (
    MAX_FILES_PER_KIND,
    AuditOptions,
    run_integrity,
    run_logs,
    run_network,
    run_users,
)
from src.audit.models import (
    OVERALL_ATTENTION,
    OVERALL_CRITICAL,
    OVERALL_INCONCLUSIVE,
    OVERALL_OK,
    AdapterResult,
    AuditError,
    AuditFinding,
    AuditReport,
    ModuleRun,
)
from src.audit.render import (
    render_console,
    render_markdown,
    report_to_dict,
    write_reports,
)
from src.audit.runner import parse_module_list, run_audit, select_modules
from src.integrity.baseline import create_baseline_data, save_json
from src.integrity.scanner import scan_target
from src.logs.ip_history import save_known_ips
from src.network.baseline import create_baseline
from src.network.procfs import collect_snapshot
from tests.helpers import PROJECT_ROOT, requires_linux, run_cli
from tests.logs_support import failed_login
from tests.proc_fixtures import ANY, FakeProc, scenario

SAMPLE = PROJECT_ROOT / "samples" / "system"
BASH = shutil.which("bash") is not None

requires_bash = unittest.skipUnless(BASH, "bash is required")


def finding(module="users", rule="UA-001", severity="HIGH", subject="x",
            title="Title", detail="Detail", fix="Fix it"):
    return AuditFinding(module, rule, severity, subject, title, detail, fix)


def moment(minutes=0):
    return datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)


def make_report(findings=(), runs=None, comparison_result=None):
    runs = runs if runs is not None else [ModuleRun("users", "ok", findings=len(findings))]

    return AuditReport(
        host="server1",
        started_at=moment(),
        finished_at=moment(1),
        modules=runs,
        findings=list(findings),
        comparison=comparison_result,
    )


class TemporaryTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def proc(self, name="proc", build=None):
        fake = scenario(self.root / name) if build is None else build(FakeProc(self.root / name))

        if build is not None:
            fake.write()

        return self.root / name

    def options(self, **overrides):
        values = dict(
            root=SAMPLE,
            proc_root=self.root / "proc",
            integrity_dir=self.root / "integrity",
            network_baseline=self.root / "missing-baseline.json",
            no_permission_checks=True,
        )
        values.update(overrides)

        return AuditOptions(**values)

    def integrity_baseline(self, name="ssh", files=None):
        target = self.root / f"target-{name}"
        target.mkdir(exist_ok=True)

        for filename, content in (files or {"sshd_config": "a", "hosts": "b"}).items():
            (target / filename).write_text(content)

        scan = scan_target(target, recursive=True, exclusions=[])
        directory = self.root / "integrity"
        save_json(
            directory / f"{name}.json",
            create_baseline_data(target, True, [], scan.files),
        )

        return target


class FingerprintTests(unittest.TestCase):
    def test_same_problem_has_the_same_identity_when_counters_change(self):
        first = finding("users", "UA-016", title="Password of 'bob' has not changed for 120 days")
        later = finding("users", "UA-016", title="Password of 'bob' has not changed for 150 days")

        self.assertEqual(first.fingerprint, later.fingerprint)

    def test_process_ids_do_not_change_the_identity(self):
        before = finding("network", "NC-002", subject="evil (pid 800)")
        after = finding("network", "NC-002", subject="evil (pid 4242)")

        self.assertEqual(before.fingerprint, after.fingerprint)

    def test_different_problems_have_different_identities(self):
        base = finding("users", "UA-022", subject="/etc/sudoers.d/a:2", title="sudo rule allows 'find'")

        for other in (
            finding("users", "UA-022", subject="/etc/sudoers.d/a:2", title="sudo rule allows 'less'"),
            finding("users", "UA-022", subject="/etc/sudoers.d/b:2", title="sudo rule allows 'find'"),
            finding("users", "UA-020", subject="/etc/sudoers.d/a:2", title="sudo rule allows 'find'"),
            finding("network", "UA-022", subject="/etc/sudoers.d/a:2", title="sudo rule allows 'find'"),
        ):
            self.assertNotEqual(base.fingerprint, other.fingerprint)


@requires_linux
@requires_bash
class UsersAdapterTests(TemporaryTestCase):
    def test_sample_tree(self):
        result = run_users(self.options())

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.findings), 33)
        self.assertEqual({item.module for item in result.findings}, {"users"})

        critical = {item.rule_id for item in result.findings if item.severity == "CRITICAL"}

        self.assertEqual(critical, {"UA-001", "UA-002"})

    def test_password_hashes_never_reach_the_findings(self):
        text = json.dumps([vars(item) for item in run_users(self.options()).findings])

        for secret in ("FAKEHASH", "$1$evesalt", "$6$", "$y$"):
            self.assertNotIn(secret, text)

    def test_the_hash_option_is_never_requested(self):
        import subprocess

        commands = []
        real_run = subprocess.run

        def record(command, *args, **kwargs):
            commands.append(command)
            return real_run(command, *args, **kwargs)

        with mock.patch("src.audit.adapters.subprocess.run", side_effect=record):
            run_users(self.options())

        self.assertEqual(len(commands), 1)
        self.assertNotIn("--show-hashes", commands[0])
        self.assertIn("--json", commands[0])

    def test_missing_files_are_an_error(self):
        result = run_users(self.options(root=self.root / "empty"))

        self.assertEqual(result.status, "error")
        self.assertTrue(result.message)

    def test_bash_may_not_be_available(self):
        with mock.patch("src.audit.adapters.shutil.which", return_value=None):
            result = run_users(self.options())

        self.assertEqual(result.status, "error")
        self.assertIn("bash", result.message)

    def test_a_script_that_takes_too_long_is_stopped(self):
        import subprocess

        with mock.patch(
            "src.audit.adapters.subprocess.run",
            side_effect=subprocess.TimeoutExpired("bash", 1),
        ):
            result = run_users(self.options())

        self.assertEqual(result.status, "error")
        self.assertIn("too long", result.message)

    def test_missing_optional_files_make_the_result_limited(self):
        tree = self.root / "minimal"
        (tree / "etc").mkdir(parents=True)

        for name in ("passwd", "group", "shadow"):
            shutil.copy(SAMPLE / "etc" / name, tree / "etc" / name)

        result = run_users(self.options(root=tree))

        self.assertEqual(result.status, "limited")
        self.assertTrue(result.notes)


@requires_linux
class NetworkAdapterTests(TemporaryTestCase):
    def test_findings_of_a_suspicious_server(self):
        self.proc()

        result = run_network(self.options())

        rules = sorted({item.rule_id for item in result.findings})

        self.assertEqual(len(result.findings), 14)
        self.assertEqual(
            rules,
            ["NC-001", "NC-002", "NC-003", "NC-006", "NC-007", "NC-008", "NC-009"],
        )
        self.assertEqual({item.module for item in result.findings}, {"network"})

    def test_missing_baseline_limits_the_result(self):
        self.proc()

        result = run_network(self.options())

        self.assertEqual(result.status, "limited")
        self.assertTrue(any("baseline" in note for note in result.notes))

    def test_baseline_is_used_when_it_exists(self):
        proc = self.proc()
        path = self.root / "baseline.json"
        create_baseline(collect_snapshot(proc), path, force=False)

        unchanged = run_network(self.options(network_baseline=path))

        self.assertEqual(unchanged.status, "ok")
        self.assertEqual(len(unchanged.findings), 14)

        changed_proc = self.proc("changed")
        table = changed_proc / "net" / "tcp"
        table.write_text(
            table.read_text()
            + "  99: 00000000:1F40 00000000:0000 0A 00000000:00000000 "
            "00:00000000 00000000     0        0 55555 1 "
            "0000000000000000 100 0 0 10 0\n"
        )

        changed = run_network(
            self.options(proc_root=changed_proc, network_baseline=path)
        )

        self.assertTrue(
            any(item.rule_id == "NC-004" for item in changed.findings)
        )

    def test_unreadable_proc_is_an_error(self):
        result = run_network(self.options(proc_root=self.root / "nowhere"))

        self.assertEqual(result.status, "error")


@requires_linux
class LogsAdapterTests(TemporaryTestCase):
    def lines(self):
        return [failed_login(minute, "198.51.100.7") for minute in range(6)]

    def write(self, lines=None):
        path = self.root / "auth.log"
        path.write_text("\n".join(lines or self.lines()) + "\n")

        return path

    def config(self, with_baseline):
        config = self.root / "config.yaml"
        baseline = self.root / "known.json"
        config.write_text(f"ip_history_path: {baseline}\n")

        if with_baseline:
            save_known_ips(baseline, {"10.0.0.5"})

        return config

    def test_findings_are_converted(self):
        result = run_logs(self.options(
            logs=self.write(), year=2026, config=self.config(True),
        ))

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.findings), 1)

        item = result.findings[0]

        self.assertEqual((item.module, item.rule_id, item.subject), ("logs", "brute_force", "198.51.100.7/-"))
        self.assertIn("Events: 6", item.detail)
        self.assertIn("brute-force", item.title)

    def test_missing_baseline_limits_the_result(self):
        result = run_logs(self.options(
            logs=self.write(), year=2026, config=self.config(False),
        ))

        self.assertEqual(result.status, "limited")
        self.assertTrue(result.notes)

    def test_errors(self):
        self.assertEqual(run_logs(self.options(logs=None)).status, "error")
        self.assertEqual(
            run_logs(self.options(logs=self.root / "nothing.log", config=self.config(True))).status,
            "error",
        )

        bad = self.root / "bad.yaml"
        bad.write_text("unknown_key: 1\n")

        self.assertEqual(
            run_logs(self.options(logs=self.write(), config=bad)).status,
            "error",
        )

    def test_unreadable_lines_are_reported_as_a_note(self):
        lines = self.lines() + ["Foo 14 10:00:00 srv sshd[1]: x"]

        result = run_logs(self.options(
            logs=self.write(lines), year=2026, config=self.config(True),
        ))

        self.assertEqual(result.status, "limited")
        self.assertTrue(any("could not be read" in note for note in result.notes))


class IntegrityAdapterTests(TemporaryTestCase):
    def test_no_baselines_means_skipped(self):
        result = run_integrity(self.options())

        self.assertEqual(result.status, "skipped")
        self.assertIn("No integrity baselines", result.message)

    def test_unchanged_files_have_no_findings(self):
        self.integrity_baseline()

        result = run_integrity(self.options())

        self.assertEqual((result.status, result.findings), ("ok", []))

    def test_changes_and_their_severity(self):
        target = self.integrity_baseline()
        (target / "sshd_config").write_text("changed")
        (target / "hosts").unlink()
        (target / "new.conf").write_text("x")

        result = run_integrity(self.options())
        severities = {item.rule_id: item.severity for item in result.findings}

        self.assertEqual(severities, {"INT-001": "HIGH", "INT-002": "MEDIUM", "INT-003": "MEDIUM"})
        self.assertEqual(
            sorted(item.title for item in result.findings),
            ["File added: new.conf", "File deleted: hosts", "File modified: sshd_config"],
        )
        self.assertIn("integrity update --name ssh", result.findings[0].recommendation)

    def test_long_lists_are_summarized(self):
        target = self.integrity_baseline()

        for index in range(MAX_FILES_PER_KIND + 7):
            (target / f"extra{index:03d}.conf").write_text("x")

        result = run_integrity(self.options())
        added = [item for item in result.findings if item.rule_id == "INT-002"]

        self.assertEqual(len(added), MAX_FILES_PER_KIND + 1)
        self.assertIn("7 more files added", added[-1].title)

    def test_problems_with_a_baseline_are_notes(self):
        target = self.integrity_baseline("good")
        (target / "hosts").write_text("changed")
        directory = self.root / "integrity"
        (directory / "broken.json").write_text("not json")
        save_json(
            directory / "gone.json",
            create_baseline_data(self.root / "does-not-exist", True, [], {}),
        )

        result = run_integrity(self.options())

        self.assertEqual(result.status, "limited")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.notes), 2)

    def test_when_nothing_can_be_checked_it_is_an_error(self):
        directory = self.root / "integrity"
        directory.mkdir()
        (directory / "broken.json").write_text("not json")

        self.assertEqual(run_integrity(self.options()).status, "error")


class RunnerTests(TemporaryTestCase):
    def test_module_selection(self):
        self.assertEqual(select_modules((), (), False), ("users", "network", "integrity"))
        self.assertEqual(select_modules((), (), True), ("users", "network", "integrity", "logs"))
        self.assertEqual(select_modules(("network", "users"), (), False), ("users", "network"))
        self.assertEqual(select_modules((), ("network",), False), ("users", "integrity"))

    def test_invalid_selections(self):
        for arguments in (
            (("logs",), (), False),
            ((), ("users", "network", "integrity"), False),
            (("users",), ("users",), False),
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(AuditError):
                    select_modules(*arguments)

    def test_module_lists(self):
        self.assertEqual(parse_module_list("users, network", "--only"), ("users", "network"))
        self.assertEqual(parse_module_list(None, "--only"), ())

        with self.assertRaises(AuditError):
            parse_module_list("users,nothing", "--only")

    def test_a_failing_module_does_not_hide_the_others(self):
        def broken(options):
            raise RuntimeError("boom")

        adapters_map = {
            "users": lambda options: AdapterResult([finding()], "ok"),
            "network": broken,
        }

        with mock.patch.dict(runner.ADAPTERS, adapters_map):
            report = run_audit(("users", "network"), self.options())

        states = {run.name: run for run in report.modules}

        self.assertEqual(states["users"].status, "ok")
        self.assertEqual(states["network"].status, "error")
        self.assertIn("RuntimeError: boom", states["network"].message)
        self.assertEqual(len(report.findings), 1)

    def test_findings_are_sorted_and_unknown_severities_are_normalized(self):
        users_found = [
            finding("users", "UA-1", "CRITICAL"),
            finding("users", "UA-2", "INFO"),
        ]
        network_found = [
            finding("network", "NC-1", "LOW"),
            finding("network", "NC-2", "HIGH"),
        ]

        with mock.patch.dict(runner.ADAPTERS, {
            "users": lambda options: AdapterResult(users_found),
            "network": lambda options: AdapterResult(network_found),
        }):
            report = run_audit(("users", "network"), self.options())

        self.assertEqual(
            [(item.rule_id, item.severity) for item in report.findings],
            [
                ("UA-1", "CRITICAL"),
                ("NC-2", "HIGH"),
                ("UA-2", "LOW"),
                ("NC-1", "LOW"),
            ],
        )

    def test_overall_status(self):
        def status(*severities, runs=None):
            return make_report([finding(severity=level) for level in severities], runs).status

        self.assertEqual(status("CRITICAL", "LOW"), OVERALL_CRITICAL)
        self.assertEqual(status("HIGH", "MEDIUM"), OVERALL_ATTENTION)
        self.assertEqual(status("MEDIUM", "LOW"), OVERALL_OK)
        self.assertEqual(status(), OVERALL_OK)
        self.assertEqual(
            status(runs=[ModuleRun("users", "error"), ModuleRun("network", "skipped")]),
            OVERALL_INCONCLUSIVE,
        )

    def test_coverage_is_complete_only_when_every_module_is_ok(self):
        self.assertTrue(make_report(runs=[ModuleRun("users", "ok")]).complete)
        self.assertFalse(make_report(runs=[ModuleRun("users", "ok"), ModuleRun("network", "limited")]).complete)
        self.assertFalse(make_report(runs=[ModuleRun("users", "skipped")]).complete)

    def test_host_comes_from_the_audited_system(self):
        self.assertEqual(runner.detect_host(SAMPLE), "hostname-demo")
        self.assertTrue(runner.detect_host(self.root))


class ComparisonTests(TemporaryTestCase):
    def previous(self, findings, runs=None, **extra):
        report = make_report(findings, runs)
        data = report_to_dict(report)
        data.update(extra)

        return data

    def test_new_unchanged_and_resolved(self):
        kept = finding(rule="UA-1", subject="a")
        fixed = finding(rule="UA-2", subject="b")
        added = finding(rule="UA-3", subject="c")

        result = comparison.compare(
            [kept, added],
            [ModuleRun("users", "ok")],
            self.previous([kept, fixed]),
            "old.json",
        )

        self.assertEqual((result.new, result.unchanged), (1, 1))
        self.assertEqual([item.rule_id for item in result.resolved], ["UA-2"])
        self.assertEqual(result.states[added.fingerprint], "new")
        self.assertEqual(result.states[kept.fingerprint], "unchanged")

    def test_a_module_that_did_not_run_is_not_compared(self):
        old = finding("network", "NC-1", subject="x")

        result = comparison.compare(
            [],
            [ModuleRun("users", "ok"), ModuleRun("network", "skipped")],
            self.previous(
                [old],
                runs=[ModuleRun("users", "ok"), ModuleRun("network", "ok")],
            ),
            "old.json",
        )

        self.assertEqual(result.resolved, [])
        self.assertEqual(result.not_comparable, ["network"])

    def test_a_module_that_was_missing_before_is_not_compared(self):
        now = finding("network", "NC-1")

        result = comparison.compare(
            [now],
            [ModuleRun("users", "ok"), ModuleRun("network", "ok")],
            self.previous([], runs=[ModuleRun("users", "ok")]),
            "old.json",
        )

        self.assertEqual(result.new, 0)
        self.assertEqual(result.states, {})
        self.assertEqual(result.not_comparable, ["network"])

    def test_limited_modules_are_compared(self):
        old = finding("network", "NC-1")

        result = comparison.compare(
            [],
            [ModuleRun("network", "limited")],
            self.previous([old], runs=[ModuleRun("network", "limited")]),
            "old.json",
        )

        self.assertEqual(len(result.resolved), 1)

    def test_load_previous_rejects_invalid_files(self):
        path = self.root / "previous.json"

        for content in (
            "not json",
            "[]",
            json.dumps({"tool": "other", "version": 1, "findings": [], "modules": []}),
            json.dumps({"tool": comparison.REPORT_TOOL, "version": 9, "findings": [], "modules": []}),
            json.dumps({"tool": comparison.REPORT_TOOL, "version": 1, "findings": [{}], "modules": []}),
        ):
            with self.subTest(content=content[:30]):
                path.write_text(content)

                with self.assertRaises(AuditError):
                    comparison.load_previous(path)

        with self.assertRaises(AuditError):
            comparison.load_previous(self.root / "missing.json")

    def test_latest_report(self):
        self.assertIsNone(comparison.find_latest(self.root / "nowhere"))
        self.assertIsNone(comparison.find_latest(self.root))

        for name in ("audit-20261101-100000.json", "audit-20261105-100000.json", "audit-20261103-100000.json", "other.json"):
            (self.root / name).write_text("{}")

        self.assertEqual(comparison.find_latest(self.root).name, "audit-20261105-100000.json")

        for name in ("audit-20261105-100000-2.json", "audit-20261105-100000-10.json", "audit-notes.json"):
            (self.root / name).write_text("{}")

        # Same second: the highest counter is the newest, and a plain
        # text sort would have put "-10" and "-2" before the first one.
        self.assertEqual(comparison.find_latest(self.root).name, "audit-20261105-100000-10.json")


class RenderTests(TemporaryTestCase):
    def hostile_report(self):
        bad = finding(
            subject="<img src=x> [click](http://evil.example)",
            title="<script>alert(1)</script> | a *bold* `code`",
            detail="line\x1b[31m red [x](http://evil.example)",
            fix="Fix\x00it",
        )

        return make_report([bad])

    def test_json_report_contents(self):
        data = report_to_dict(make_report([finding(severity="CRITICAL")]))

        self.assertEqual(data["status"], OVERALL_CRITICAL)
        self.assertEqual(data["summary"]["CRITICAL"], 1)
        self.assertEqual(data["started_at"], "2026-11-07T12:00:00Z")
        self.assertEqual(data["modules"][0]["name"], "users")
        self.assertEqual(len(data["findings"][0]["fingerprint"]), 16)
        self.assertIsNone(data["findings"][0]["state"])
        self.assertIsNone(data["comparison"])
        json.dumps(data)

    def test_markdown_cannot_inject_html_or_links(self):
        text = render_markdown(self.hostile_report())

        # Every "<" and "]" that came from the system must be escaped.
        self.assertIsNone(re.search(r"(?<!\\)<", text))
        self.assertIsNone(re.search(r"(?<!\\)\]\(", text))
        self.assertIsNone(re.search(r"(?<!\\)\[click", text))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x00", text)
        self.assertIn("\\<script\\>", text)

    def test_console_output_has_no_control_characters(self):
        text = render_console(self.hostile_report())

        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x00", text)

    def test_markdown_structure(self):
        found = [finding(severity="CRITICAL", rule="UA-1"), finding(severity="LOW", rule="UA-2", title="Small")]
        runs = [ModuleRun("users", "ok", findings=2), ModuleRun("network", "skipped", message="No baseline")]

        text = render_markdown(make_report(found, runs))

        self.assertIn("# Security Audit Report", text)
        self.assertIn("**Host:** server1", text)
        self.assertIn("| network | skipped | 0 | No baseline |", text)
        self.assertIn("**Coverage:** incomplete", text)
        self.assertIn("## Critical findings (1)", text)
        self.assertIn("## Low findings (1)", text)
        self.assertNotIn("## High findings", text)

    def test_comparison_sections(self):
        old = finding(rule="UA-9", subject="gone", title="Old problem")
        current = finding(rule="UA-1", subject="a")
        result = comparison.compare(
            [current],
            [ModuleRun("users", "ok")],
            report_to_dict(make_report([old])),
            "audit-previous.json",
        )

        report = make_report([current], comparison_result=result)
        text = render_markdown(report)
        console = render_console(report)
        data = report_to_dict(report)

        self.assertIn("## Changes since the previous report", text)
        self.assertIn("**New findings:** 1", text)
        self.assertIn("Since the previous report:** new", text)
        self.assertIn("Old problem", text)
        self.assertIn("1 new, 0 unchanged, 1 resolved", console)
        self.assertEqual(data["findings"][0]["state"], "new")
        self.assertEqual(data["comparison"]["resolved"][0]["rule_id"], "UA-9")

    def test_report_files_are_private_and_never_replaced(self):
        report = make_report([finding()])
        directory = self.root / "reports" / "audit"

        first = write_reports(report, directory, ("md", "json"))
        second = write_reports(report, directory, ("md", "json"))

        self.assertEqual(len(set(first + second)), 4)
        self.assertTrue(first[0].name.startswith("audit-20261107-120000"))
        self.assertIn("-2", second[0].name)

        for path in first + second:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        json.loads(first[1].read_text())

    def test_selected_formats_only(self):
        report = make_report([finding()])

        self.assertEqual([p.suffix for p in write_reports(report, self.root / "a", ("json",))], [".json"])
        self.assertEqual(write_reports(report, self.root / "b", ()), [])


@requires_linux
@requires_bash
class CommandLineTests(TemporaryTestCase):
    def audit(self, *args, proc="proc", **kwargs):
        defaults = [
            "--root", SAMPLE,
            "--proc-root", self.root / proc,
            "--integrity-dir", self.root / "integrity",
            "--network-baseline", self.root / "no-baseline.json",
            "--output-dir", self.root / "reports",
            "--no-permission-checks",
        ]

        return run_cli("audit", "run", *defaults, *args)

    def setUp(self):
        super().setUp()
        self.proc()

    def test_full_run_saves_both_reports(self):
        code, output = self.audit()

        self.assertEqual(code, 0, output)
        self.assertIn("Status: CRITICAL", output)
        self.assertIn("users", output)
        self.assertIn("Reports saved:", output)

        reports = sorted((self.root / "reports").iterdir())
        data = json.loads(reports[0].read_text())

        self.assertEqual([p.suffix for p in reports], [".json", ".md"])
        self.assertEqual({m["name"] for m in data["modules"]}, {"users", "network", "integrity"})
        self.assertEqual(data["modules"][2]["status"], "skipped")
        self.assertFalse(data["complete"])

    def test_no_secrets_in_the_reports(self):
        self.audit()

        text = "".join(p.read_text() for p in (self.root / "reports").iterdir())

        for secret in ("FAKEHASH", "$1$evesalt", "$6$rootsalt"):
            self.assertNotIn(secret, text)

    def test_format_none_saves_nothing(self):
        code, output = self.audit("--format", "none")

        self.assertEqual(code, 0, output)
        self.assertNotIn("Reports saved", output)
        self.assertFalse((self.root / "reports").exists())

    def test_fail_on(self):
        self.assertEqual(self.audit("--fail-on", "critical")[0], 1)
        self.assertEqual(self.audit("--only", "network", "--fail-on", "critical")[0], 1)

    def test_clean_system_passes(self):
        tree = self.root / "healthy"
        (tree / "etc" / "ssh").mkdir(parents=True)
        (tree / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
        (tree / "etc" / "shadow").write_text("root:$y$j9T$s$h:20600:0:90:7:::\n")
        (tree / "etc" / "group").write_text("root:x:0:\n")
        (tree / "etc" / "sudoers").write_text("root ALL=(ALL:ALL) ALL\n")
        (tree / "etc" / "login.defs").write_text("UID_MIN 1000\nUID_MAX 60000\nPASS_MAX_DAYS 90\n")
        (tree / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin no\nPasswordAuthentication no\n")

        def quiet(fake):
            fake.process(300, "sshd", "/usr/sbin/sshd", "sshd", 0)
            fake.socket("tcp", (ANY, 22), (ANY, 0), "0A", 300)
            return fake

        self.proc("quiet", build=quiet)

        code, output = run_cli(
            "audit", "run", "--root", tree, "--proc-root", self.root / "quiet",
            "--skip", "integrity", "--network-baseline", self.root / "none.json",
            "--output-dir", self.root / "reports2", "--no-permission-checks",
            "--fail-on", "low",
        )

        self.assertEqual(code, 0, output)
        self.assertIn("NO SERIOUS PROBLEMS", output)

    def test_when_nothing_can_run_the_exit_code_is_2(self):
        code, output = run_cli(
            "audit", "run", "--only", "network", "--proc-root", self.root / "nowhere",
            "--output-dir", self.root / "reports", "--fail-on", "low",
        )

        self.assertEqual(code, 2)
        self.assertIn("No module could be audited", output)
        self.assertIn("INCONCLUSIVE", output)

    def test_comparison_with_the_latest_report(self):
        self.audit("--only", "network")

        def calmer(fake):
            fake.process(300, "sshd", "/usr/sbin/sshd", "sshd", 0)
            fake.socket("tcp", (ANY, 22), (ANY, 0), "0A", 300)
            fake.process(200, "redis-server", "/usr/bin/redis-server", "redis-server", 999)
            fake.socket("tcp", (ANY, 6379), (ANY, 0), "0A", 200, 999)
            return fake

        self.proc("calmer", build=calmer)

        code, output = self.audit("--only", "network", "--previous", "latest", proc="calmer")

        self.assertEqual(code, 0, output)
        self.assertIn("Changes since the previous report", output)
        self.assertIn("0 new, 1 unchanged, 13 resolved", output)

    def test_first_run_with_latest_has_nothing_to_compare(self):
        code, output = self.audit("--only", "network", "--previous", "latest")

        self.assertEqual(code, 0, output)
        self.assertIn("No previous report was found", output)

    def test_usage_errors(self):
        for arguments in (
            ("--only", "logs"),
            ("--only", "nothing"),
            ("--skip", "users,network,integrity"),
            ("--previous", str(self.root / "missing.json")),
            ("--fail-on", "extreme"),
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.audit(*arguments)[0], 2)


@requires_linux
@requires_bash
class UsersCommandTests(TemporaryTestCase):
    def users(self, *args):
        return run_cli("users", "audit", "--root", SAMPLE, "--no-permission-checks", "--no-color", *args)

    def test_it_runs_the_user_auditor(self):
        code, output = self.users("--min-severity", "critical")

        self.assertEqual(code, 0, output)
        self.assertIn("UA-001", output)
        self.assertNotIn("UA-015", output)

    def test_exit_codes_come_from_the_script(self):
        self.assertEqual(self.users("--fail-on", "critical")[0], 1)
        self.assertEqual(self.users("--min-severity", "extreme")[0], 2)

    def test_json_export_and_hashes_are_opt_in(self):
        report = self.root / "users.json"

        code, output = self.users("--json", report)

        self.assertEqual(code, 0, output)
        self.assertNotIn("FAKEHASH", report.read_text())

        code, output = self.users("--show-hashes")

        self.assertIn("Password hashes (SENSITIVE", output)

    def test_missing_bash(self):
        import argparse

        from src.users import cli as users_cli

        with mock.patch("src.users.cli.shutil.which", return_value=None):
            with self.assertRaises(ValueError):
                users_cli.run_users_audit(argparse.Namespace(**{
                    name: None for name, _ in users_cli.VALUE_OPTIONS
                }, **{name: False for name, _ in users_cli.FLAG_OPTIONS}))


if __name__ == "__main__":
    unittest.main()