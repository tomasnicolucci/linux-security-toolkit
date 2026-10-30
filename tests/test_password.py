import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.network import procfs, watch
from src.network.baseline import (
    compare_baseline,
    create_baseline,
    load_baseline,
)
from src.network.models import NetworkError
from src.network.procfs import bind_scope, collect_snapshot, decode_address
from src.network.rules import RuleOptions, analyze, sort_findings
from src.network.service import (
    public_remote_ips,
    select_sockets,
    state_counts,
)
from tests.helpers import requires_linux, run_module
from tests.proc_fixtures import ANY, FakeProc, scenario


def find(findings, rule_id, text=""):
    return [f for f in findings if f.rule_id == rule_id and text in f.title + f.subject]


@requires_linux
class NetworkTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.directory = directory
        cls.root = Path(directory.name)
        cls.proc = scenario(cls.root / "proc")

        with mock.patch.object(procfs, "user_name", lambda uid: f"user{uid}"):
            cls.snapshot = collect_snapshot(cls.root / "proc")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()


class ParsingTests(unittest.TestCase):
    def test_ipv4_and_ipv6_addresses(self):
        from tests.proc_fixtures import encode

        for ip, port in (("192.0.2.10", 443), ("127.0.0.1", 22), ("0.0.0.0", 0),
                         ("2001:db8::10", 8080), ("::", 0), ("::1", 25)):
            with self.subTest(ip=ip):
                self.assertEqual(decode_address(encode(ip, port), 6 if ":" in ip else 4), (ip, port))

    def test_ipv4_mapped_addresses_become_ipv4(self):
        from tests.proc_fixtures import encode

        self.assertEqual(decode_address(encode("::ffff:10.1.2.3", 80), 6), ("10.1.2.3", 80))

    def test_bind_scope(self):
        self.assertEqual(bind_scope("0.0.0.0"), "all")
        self.assertEqual(bind_scope("::"), "all")
        self.assertEqual(bind_scope("127.0.0.1"), "loopback")
        self.assertEqual(bind_scope("::1"), "loopback")
        self.assertEqual(bind_scope("192.168.1.5"), "specific")

    def test_malformed_lines_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            table = Path(directory) / "tcp"
            table.write_text("header\nthis is not a socket\n  0: ZZZZ:00 00:00 0A\n")

            self.assertEqual(procfs.read_table(table, "tcp", 4), [])

    @requires_linux
    def test_missing_tables_are_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(NetworkError):
                collect_snapshot(Path(directory))

    @requires_linux
    def test_works_on_the_real_system(self):
        snapshot = collect_snapshot()

        self.assertIsInstance(snapshot.sockets, list)
        self.assertTrue(snapshot.host)


class SnapshotTests(NetworkTestCase):
    def test_listeners_and_ephemeral_udp(self):
        ports = {(item.proto, item.local_port) for item in self.snapshot.listeners}

        self.assertIn(("tcp", 22), ports)
        self.assertIn(("udp", 53), ports)
        self.assertNotIn(("udp", 45000), ports)

    def test_processes_are_linked_to_sockets(self):
        nginx = [s for s in self.snapshot.listeners if s.local_port == 80][0]

        self.assertEqual(nginx.process.name, "nginx")
        self.assertEqual(nginx.pids, (100, 101))
        self.assertEqual(nginx.process.pid, 100)
        self.assertEqual(nginx.scope, "all")
        self.assertEqual(nginx.process.user, "user0")

    def test_scopes(self):
        scopes = {s.local_port: s.scope for s in self.snapshot.listeners if s.proto == "tcp"}

        self.assertEqual(scopes[5432], "loopback")
        self.assertEqual(scopes[7000], "loopback")
        self.assertEqual(scopes[6379], "all")

    def test_command_lines_and_deleted_programs(self):
        by_pid = {s.process.pid: s.process for s in self.snapshot.sockets if s.process}

        self.assertEqual(by_pid[200].cmdline, "redis-server *:6379")
        self.assertTrue(by_pid[700].deleted)
        self.assertFalse(by_pid[100].deleted)

    def test_sockets_without_owner(self):
        nfs = [s for s in self.snapshot.listeners if s.local_port == 2049][0]

        self.assertIsNone(nfs.process)
        self.assertEqual(nfs.pids, ())

    def test_hostile_text_is_sanitized(self):
        p = FakeProc(self.root / "hostile")
        p.process(1, "bad\x1b[31mname", "/usr/bin/x", "run \x1b[2J now", 0)
        p.socket("tcp", (ANY, 80), (ANY, 0), "0A", 1)
        p.write()

        process = collect_snapshot(self.root / "hostile").sockets[0].process

        self.assertNotIn("\x1b", process.name + process.cmdline)

    def test_unreadable_processes_are_counted(self):
        real = os.listdir

        def deny(path, *args):
            if str(path).endswith("/300/fd"):
                raise PermissionError(13, "denied")

            return real(path, *args)

        with mock.patch("src.network.procfs.os.listdir", side_effect=deny):
            snapshot = collect_snapshot(self.root / "proc")

        self.assertEqual(snapshot.unreadable_processes, 1)
        self.assertTrue(any("could not be inspected" in w for w in snapshot.warnings))

    def test_large_tables_are_read_quickly(self):
        import time

        p = FakeProc(self.root / "big")

        for i in range(20_000):
            p.socket("tcp", (ANY, 80), (f"10.{(i >> 8) & 255}.{i & 255}.1", 1024 + i % 60000), "01")

        p.write()
        started = time.time()
        snapshot = collect_snapshot(self.root / "big")

        self.assertEqual(len(snapshot.sockets), 20_000)
        self.assertLess(time.time() - started, 10)


class RuleTests(NetworkTestCase):
    def setUp(self):
        self.findings = sort_findings(analyze(self.snapshot, RuleOptions()))

    def test_risky_services_exposed(self):
        exposed = {f.title.split(" is ")[0]: f.severity for f in find(self.findings, "NC-001")}

        self.assertEqual(
            exposed,
            {"Docker API": "CRITICAL", "Redis": "HIGH", "Memcached": "HIGH", "NFS": "MEDIUM"},
        )

    def test_services_that_are_fine_are_not_reported(self):
        text = " ".join(f.subject + f.title for f in self.findings)

        for name in ("nginx", "sshd", "postgres", "dnsmasq"):
            with self.subTest(name=name):
                self.assertNotIn(name, text)

    def test_loopback_services_are_never_exposed(self):
        p = FakeProc(self.root / "local")
        p.socket("tcp", ("127.0.0.1", 6379), (ANY, 0), "0A")
        p.write()

        self.assertEqual(find(analyze(collect_snapshot(self.root / "local"), RuleOptions()), "NC-001"), [])

    def test_deleted_programs(self):
        by_process = {f.subject.split(" ")[0]: f.severity for f in find(self.findings, "NC-002")}

        self.assertEqual(by_process, {"apache2": "LOW", "evil": "CRITICAL", "kworker-x": "CRITICAL"})
        self.assertIn("memory only", find(self.findings, "NC-002", "kworker")[0].title)

    def test_programs_in_temporary_directories(self):
        names = sorted(f.subject.split(" ")[0] for f in find(self.findings, "NC-003"))

        self.assertEqual(names, [".x", "evil"])

    def test_shells_and_network_tools(self):
        names = sorted(f.subject.split(" ")[0] for f in find(self.findings, "NC-009"))

        self.assertEqual(names, ["bash", "nc"])

    def test_many_connections_from_one_address(self):
        found = find(self.findings, "NC-006")

        self.assertEqual([f.subject for f in found], ["198.51.100.99"])
        self.assertEqual(find(analyze(self.snapshot, RuleOptions(max_per_ip=500)), "NC-006"), [])

    def test_half_open_connections(self):
        found = find(self.findings, "NC-007")

        self.assertEqual([f.subject for f in found], ["tcp 80"])
        self.assertEqual(find(analyze(self.snapshot, RuleOptions(syn_threshold=100)), "NC-007"), [])

    def test_listener_without_a_visible_process(self):
        found = find(self.findings, "NC-008")

        self.assertEqual(len(found), 1)
        self.assertIn("2049", found[0].title)

    def test_no_orphan_finding_when_processes_could_not_be_inspected(self):
        snapshot = collect_snapshot(self.root / "proc")
        snapshot.unreadable_processes = 3

        self.assertEqual(find(analyze(snapshot, RuleOptions()), "NC-008"), [])

    def test_findings_are_sorted_by_severity(self):
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        values = [order[f.severity] for f in self.findings]

        self.assertEqual(values, sorted(values, reverse=True))
        self.assertEqual(len(self.findings), 14)


class ServiceTests(NetworkTestCase):
    def select(self, **kwargs):
        options = dict(listening_only=False, established_only=False, proto=None, port=None, pid=None)
        options.update(kwargs)

        return select_sockets(self.snapshot, **options)

    def test_filters(self):
        self.assertEqual({s.proto for s in self.select(listening_only=True, proto="udp").listeners}, {"udp"})
        self.assertEqual(self.select(listening_only=True).connections, [])
        self.assertEqual(self.select(established_only=True).listeners, [])
        self.assertEqual([s.process.pid for s in self.select(established_only=True, pid=500).connections], [500])
        self.assertEqual([s.local_port for s in self.select(listening_only=True, port=6379).listeners], [6379])

    def test_idle_and_closing_sockets_are_not_connections(self):
        states = {s.state for s in self.select().connections}

        self.assertNotIn("TIME_WAIT", states)
        self.assertNotIn("LISTEN", states)

    def test_state_counts(self):
        counts = state_counts(self.snapshot)

        self.assertEqual(counts["SYN_RECV"], 60)
        self.assertEqual(counts["TIME_WAIT"], 30)

    def test_public_remote_addresses_mix_versions_without_errors(self):
        p = FakeProc(self.root / "public")
        p.socket("tcp", ("192.0.2.10", 1), ("8.8.8.8", 443), "01")
        p.socket("tcp", ("192.0.2.10", 2), ("8.8.8.8", 80), "01")
        p.socket("tcp", ("192.0.2.10", 3), ("1.1.1.1", 443), "01")
        p.socket("tcp", ("192.0.2.10", 4), ("10.0.0.5", 22), "01")
        p.socket("tcp", ("192.0.2.10", 5), ("203.0.113.9", 22), "01")
        p.socket("tcp6", ("2001:db8::10", 6), ("2606:4700:4700::1111", 443), "01")
        p.write()

        snapshot = collect_snapshot(self.root / "public")

        self.assertEqual(
            public_remote_ips(snapshot.sockets),
            ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"],
        )


class BaselineTests(NetworkTestCase):
    def setUp(self):
        self.path = self.root / "baseline" / "baseline.json"

        if self.path.exists():
            self.path.unlink()

    def changed_snapshot(self, edit):
        p = scenario(self.root / "changed")
        edit(p)
        p.write()

        return collect_snapshot(self.root / "changed")

    def test_create_and_load(self):
        total = create_baseline(self.snapshot, self.path, force=False)
        loaded = load_baseline(self.path)

        self.assertEqual(total, len(loaded.entries))
        self.assertIn(("tcp", 22, "all"), {e.key for e in loaded.entries})
        self.assertEqual([f for f in compare_baseline(self.snapshot, loaded)], [])

    def test_existing_baseline_is_protected(self):
        create_baseline(self.snapshot, self.path, force=False)

        with self.assertRaises(NetworkError):
            create_baseline(self.snapshot, self.path, force=False)

        create_baseline(self.snapshot, self.path, force=True)

        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["baseline.json"])

    def test_new_listeners(self):
        create_baseline(self.snapshot, self.path, force=False)

        def edit(p):
            p.process(1300, "python3", "/usr/bin/python3", "python3 -m http.server", 1000)
            p.socket("tcp", (ANY, 8000), (ANY, 0), "0A", 1300, 1000)
            p.socket("tcp", ("127.0.0.1", 3000), (ANY, 0), "0A")

        findings = compare_baseline(self.changed_snapshot(edit), load_baseline(self.path))
        severities = {f.subject: f.severity for f in findings if f.rule_id == "NC-004"}

        self.assertEqual(severities["tcp 0.0.0.0:8000"], "HIGH")
        self.assertEqual(severities["tcp 127.0.0.1:3000"], "MEDIUM")

    def test_exposure_wider_than_the_baseline(self):
        create_baseline(self.snapshot, self.path, force=False)

        def edit(p):
            p.rows["tcp"] = [r for r in p.rows["tcp"] if "0100007F:1538" not in r]
            p.socket("tcp", (ANY, 5432), (ANY, 0), "0A", 210, 114)

        findings = compare_baseline(self.changed_snapshot(edit), load_baseline(self.path))
        wider = [f for f in findings if "exposed beyond" in f.title]

        self.assertEqual(len(wider), 1)
        self.assertEqual(wider[0].severity, "HIGH")
        # The loopback listener that "disappeared" is not reported again.
        self.assertEqual([f for f in findings if f.rule_id == "NC-005"], [])

    def test_service_stopped_and_process_changed(self):
        create_baseline(self.snapshot, self.path, force=False)

        def edit(p):
            p.rows["tcp"] = [r for r in p.rows["tcp"] if ":0016 " not in r.split()[1] + " "]
            p.rows["tcp6"] = [r for r in p.rows["tcp6"] if ":0016 " not in r.split()[1] + " "]
            p.rows["tcp"] = [r for r in p.rows["tcp"] if not r.split()[1].endswith(":01BB")]
            p.process(1500, "haproxy", "/usr/sbin/haproxy", "haproxy", 0)
            p.socket("tcp", (ANY, 443), (ANY, 0), "0A", 1500)

        findings = compare_baseline(self.changed_snapshot(edit), load_baseline(self.path))

        self.assertEqual([f.subject for f in findings if f.rule_id == "NC-005"], ["tcp 22"])
        changed = [f for f in findings if "now served by" in f.title]

        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0].severity, "MEDIUM")

    def test_invalid_files(self):
        self.path.parent.mkdir(exist_ok=True)

        for content in ("not json", '{"version": 1, "entries": [{"proto": "tcp"}]}',
                        '{"version": 9, "entries": []}', "[]"):
            with self.subTest(content=content):
                self.path.write_text(content)

                with self.assertRaises(NetworkError):
                    load_baseline(self.path)

        with self.assertRaises(NetworkError):
            load_baseline(self.root / "missing.json")


class WatchTests(NetworkTestCase):
    def run_watch(self, snapshots, include_loopback=False, log=None, base=None):
        output = []
        feed = iter(snapshots)

        with mock.patch.object(watch, "collect_snapshot", side_effect=lambda root: next(feed)), \
                mock.patch.object(watch.time, "sleep"):
            totals = watch.watch(
                Path("/unused"), 1.0, len(snapshots), log, include_loopback, base, output.append
            )

        return totals, output

    def snapshot_with(self, edit):
        p = scenario(self.root / "w")
        edit(p)
        p.write()

        return collect_snapshot(self.root / "w")

    def test_reports_new_and_closed_sockets_with_alerts(self):
        def add(p):
            p.process(2000, "bash", "/usr/bin/bash", "bash -i", 1000)
            p.socket("tcp", ("192.0.2.10", 53000), ("8.8.4.4", 9001), "01", 2000, 1000)
            p.process(2100, "redis-server", "/usr/bin/redis-server", "redis-server", 999)
            p.socket("tcp", (ANY, 6379), (ANY, 0), "0A", 2100, 999)

        first = self.snapshot
        second = self.snapshot_with(add)
        totals, output = self.run_watch([first, second, first])
        text = "\n".join(output)

        self.assertEqual(totals["connection_new"], 1)
        self.assertEqual(totals["connection_closed"], 1)
        self.assertIn("CONNECTION NEW tcp 192.0.2.10:53000 -> 8.8.4.4:9001 (bash", text)
        self.assertIn("NC-009", text)
        self.assertIn("CONNECTION CLOSED", text)

    def test_local_connections_are_ignored_unless_requested(self):
        def add(p):
            p.socket("tcp", ("127.0.0.1", 40000), ("127.0.0.1", 5432), "01")

        second = self.snapshot_with(add)

        self.assertEqual(self.run_watch([self.snapshot, second])[0]["connection_new"], 0)
        self.assertEqual(
            self.run_watch([self.snapshot, second], include_loopback=True)[0]["connection_new"], 1
        )

    def test_events_are_logged_as_json_lines(self):
        def add(p):
            p.socket("tcp", ("192.0.2.10", 53000), ("8.8.4.4", 9001), "01")

        log = self.root / "logs" / "events.jsonl"
        self.run_watch([self.snapshot, self.snapshot_with(add)], log=log)

        records = [json.loads(line) for line in log.read_text().splitlines()]

        self.assertEqual(records[0]["event"], "connection_new")
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_new_listeners_are_compared_with_the_baseline(self):
        path = self.root / "watch-baseline.json"
        create_baseline(self.snapshot, path, force=True)

        def add(p):
            p.socket("tcp", (ANY, 8000), (ANY, 0), "0A")

        _, output = self.run_watch(
            [self.snapshot, self.snapshot_with(add)], base=load_baseline(path)
        )

        self.assertIn("NC-004", "\n".join(output))

    def test_interrupt_stops_cleanly(self):
        with mock.patch.object(watch, "collect_snapshot", return_value=self.snapshot), \
                mock.patch.object(watch.time, "sleep", side_effect=KeyboardInterrupt):
            output = []
            watch.watch(Path("/unused"), 1.0, 0, None, False, None, output.append)

        self.assertIn("Stopped.", "\n".join(output))


class CommandLineTests(NetworkTestCase):
    def run_scan(self, *args):
        return run_module("src.network", "scan", "--proc-root", self.root / "proc", *args)

    def test_report(self):
        code, output = self.run_scan("--min-severity", "high")

        self.assertEqual(code, 0, output)
        self.assertIn("Listening sockets (", output)
        self.assertIn("NC-001", output)
        self.assertNotIn("NC-006", output)

    def test_it_is_also_available_in_the_toolkit_cli(self):
        from tests.helpers import run_cli

        code, output = run_cli("network", "scan", "--proc-root", self.root / "proc", "--listening")

        self.assertEqual(code, 0, output)
        self.assertIn("Redis", output)

    def test_fail_on_gives_exit_code_1(self):
        self.assertEqual(self.run_scan("--fail-on", "critical")[0], 1)
        self.assertEqual(self.run_scan("--fail-on", "critical", "--max-per-ip", "500")[0], 1)

    def test_clean_system_does_not_fail(self):
        p = FakeProc(self.root / "clean")
        p.process(300, "sshd", "/usr/sbin/sshd", "sshd", 0)
        p.socket("tcp", (ANY, 22), (ANY, 0), "0A", 300)
        p.write()

        code, output = run_module("src.network", "scan", "--proc-root", self.root / "clean", "--fail-on", "low")

        self.assertEqual(code, 0, output)
        self.assertIn("No findings.", output)

    def test_json_export(self):
        report = self.root / "scan.json"

        self.run_scan("--json", report, "--min-severity", "high")
        data = json.loads(report.read_text())

        self.assertEqual(data["summary"]["listeners"], len(data["listeners"]))
        self.assertTrue(all(f["severity"] in ("HIGH", "CRITICAL") for f in data["findings"]))
        self.assertEqual(
            [item["process"]["name"] for item in data["listeners"] if item["local_port"] == 6379],
            ["redis-server"],
        )

    def test_remote_addresses_are_printed_one_per_line(self):
        p = FakeProc(self.root / "remote")
        p.socket("tcp", ("192.0.2.10", 1), ("8.8.8.8", 443), "01")
        p.socket("tcp6", ("2001:db8::10", 2), ("2606:4700:4700::1111", 443), "01")
        p.write()

        code, output = run_module("src.network", "scan", "--proc-root", self.root / "remote", "--remote-ips")

        self.assertEqual(code, 0)
        self.assertEqual(output.split(), ["8.8.8.8", "2606:4700:4700::1111"])

    def test_baseline_commands(self):
        path = self.root / "cli-baseline.json"

        code, output = run_module("src.network", "baseline", "create", "--proc-root", self.root / "proc", "--path", path)
        self.assertEqual(code, 0, output)
        self.assertEqual(run_module("src.network", "baseline", "create", "--proc-root", self.root / "proc", "--path", path)[0], 2)

        code, output = run_module("src.network", "baseline", "show", "--path", path)
        self.assertIn("Expected listeners:", output)

        code, output = self.run_scan("--baseline", path, "--listening")
        self.assertNotIn("NC-004", output)

    def test_invalid_usage(self):
        for args in (("--listening", "--established"), ("--limit", "0"), ("--baseline", "/nope.json")):
            with self.subTest(args=args):
                self.assertEqual(self.run_scan(*args)[0], 2)

        self.assertEqual(run_module("src.network", "watch", "--interval", "0.1")[0], 2)

    def test_pipelines_can_close_early(self):
        import subprocess
        import sys
        from tests.helpers import project_env, PROJECT_ROOT

        scan = subprocess.Popen(
            [sys.executable, "-m", "src.network", "scan", "--proc-root", str(self.root / "proc")],
            cwd=PROJECT_ROOT, env=project_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        scan.stdout.readline()
        scan.stdout.close()

        self.assertIn(scan.wait(timeout=30), (0, 141, -13))

        with scan.stderr:
            self.assertNotIn(b"Traceback", scan.stderr.read())


if __name__ == "__main__":
    unittest.main()
