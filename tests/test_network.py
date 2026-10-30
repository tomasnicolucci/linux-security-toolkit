import gzip
import json
import random
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from src.logs.config import AVAILABLE_RULES, load_config
from src.logs.correlation import (
    deduplicate_ssh_failures,
    find_event_windows,
    find_success_after_failures,
)
from src.logs.filters import create_filters, filter_events
from src.logs.ip_history import (
    approve_ips,
    load_known_ips,
    revoke_ips,
    save_known_ips,
)
from src.logs.models import EventType, SecurityEvent
from src.logs.parser import parse_log_line
from src.logs.reader import discover_log_files, read_log_lines, LogLine
from tests.helpers import requires_linux, run_cli
from tests.logs_support import LogTestCase, failed_login, syslog

BUENOS_AIRES = ZoneInfo("America/Argentina/Buenos_Aires")


def parse(content, **kwargs):
    return parse_log_line(LogLine("test.log", 1, content), **kwargs)


def event(seconds, ip="1.1.1.1", user="root", kind=EventType.SSH_LOGIN_FAILED,
          pid=None):
    base = datetime(2026, 10, 14, tzinfo=timezone.utc)

    return SecurityEvent(
        timestamp=base + timedelta(seconds=seconds),
        event_type=kind,
        source="t.log",
        line_number=seconds,
        service="sshd",
        message="x",
        source_ip=ip,
        username=user,
        process_id=pid,
    )


class ParserTests(unittest.TestCase):
    def test_ssh_events(self):
        failed = parse(
            "Oct 14 03:00:00 srv sshd[10]: Failed password for root "
            "from 198.51.100.7 port 22 ssh2",
            year=2026,
        )
        invalid = parse(
            "Oct 14 03:00:00 srv sshd[10]: Invalid user zed "
            "from 198.51.100.7 port 22",
            year=2026,
        )
        accepted = parse(
            "Oct 14 03:00:00 srv sshd[10]: Accepted publickey for alice "
            "from 2001:db8::1 port 22 ssh2",
            year=2026,
        )

        self.assertEqual(failed.event_type, EventType.SSH_LOGIN_FAILED)
        self.assertEqual((failed.username, failed.source_ip), ("root", "198.51.100.7"))
        self.assertEqual(failed.process_id, 10)
        self.assertEqual(invalid.event_type, EventType.SSH_INVALID_USER)
        self.assertEqual(invalid.username, "zed")
        self.assertEqual(accepted.event_type, EventType.SSH_LOGIN_SUCCESS)
        self.assertEqual(accepted.source_ip, "2001:db8::1")

    def test_failure_for_invalid_user_keeps_the_user_name(self):
        item = parse(
            "Oct 14 03:00:00 srv sshd[10]: Failed password for invalid "
            "user guest from 198.51.100.7 port 22 ssh2",
            year=2026,
        )

        self.assertEqual(item.username, "guest")

    def test_privilege_and_account_events(self):
        cases = {
            "sudo[1]: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls":
                EventType.SUDO_COMMAND,
            "sudo[1]: alice : 3 incorrect password attempts ; COMMAND=/bin/ls":
                EventType.SUDO_AUTH_FAILED,
            "su[1]: Successful su for root by alice": EventType.SU_SUCCESS,
            "su[1]: FAILED SU (to root) alice on pts/0": EventType.SU_FAILED,
            "useradd[1]: new user: name=bob, UID=1001, GID=1001":
                EventType.USER_CREATED,
            "userdel[1]: delete user 'bob'": EventType.USER_DELETED,
            "passwd[1]: password changed for alice":
                EventType.PASSWORD_CHANGED,
            "groupadd[1]: new group: name=ops, GID=1100":
                EventType.GROUP_CREATED,
            "nginx[1]: connect() failed: error": EventType.SERVICE_ERROR,
            "cron[1]: job started": EventType.UNKNOWN,
        }

        for message, expected in cases.items():
            with self.subTest(message=message):
                item = parse(f"Oct 14 10:00:00 srv {message}", year=2026)
                self.assertEqual(item.event_type, expected)

    def test_refused_sudo_attempts_are_failures_even_with_a_command(self):
        # Real sudo logs the refused command too ("COMMAND=...").
        cases = {
            "alice : 3 incorrect password attempts ; TTY=pts/0 ; "
            "PWD=/ ; USER=root ; COMMAND=/bin/ls": "alice",
            "alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; "
            "USER=root ; COMMAND=/bin/ls": "alice",
            "pam_unix(sudo:auth): authentication failure; logname=bob "
            "uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob": "bob",
        }

        for message, user in cases.items():
            with self.subTest(message=message):
                item = parse(f"Oct 14 10:00:00 srv sudo[1]: {message}", year=2026)

                self.assertEqual(item.event_type, EventType.SUDO_AUTH_FAILED)
                self.assertEqual(item.username, user)

    def test_a_command_that_mentions_failure_words_is_still_a_command(self):
        item = parse(
            "Oct 14 10:00:00 srv sudo[1]: alice : TTY=pts/0 ; USER=root ; "
            "COMMAND=/bin/echo incorrect password",
            year=2026,
        )

        self.assertEqual(item.event_type, EventType.SUDO_COMMAND)

    def test_sudo_command_is_recorded(self):
        item = parse(
            "Oct 14 10:00:00 srv sudo[1]: alice : TTY=pts/0 ; "
            "USER=root ; COMMAND=/bin/ls -l",
            year=2026,
        )

        self.assertEqual(item.username, "alice")
        self.assertEqual(item.metadata["command"], "/bin/ls -l")

    def test_lines_that_are_not_logs_are_ignored(self):
        self.assertIsNone(parse("this is not a log line"))
        self.assertIsNone(parse("   "))

    def test_month_names(self):
        self.assertEqual(parse("Ene 19 12:00:00 srv sshd[1]: x", year=2026).timestamp.month, 1)

        with self.assertRaises(ValueError):
            parse("Foo 19 12:00:00 srv sshd[1]: x", year=2026)

        with self.assertRaises(ValueError):
            parse("Oct 32 12:00:00 srv sshd[1]: x", year=2026)

    def test_timestamps_use_the_configured_zone(self):
        expected = datetime(2026, 10, 19, 15, 0, tzinfo=timezone.utc)

        syslog_item = parse("Oct 19 12:00:00 srv sshd[1]: x", year=2026, tz=BUENOS_AIRES)
        naive_iso = parse("2026-10-19T12:00:00 srv sshd[1]: x", tz=BUENOS_AIRES)
        offset_iso = parse("2026-10-19T12:00:00-03:00 srv sshd[1]: x", tz=BUENOS_AIRES)

        self.assertEqual(syslog_item.timestamp, expected)
        self.assertEqual(naive_iso.timestamp, expected)
        self.assertEqual(offset_iso.timestamp, expected)

    def test_journal_json_lines(self):
        line = json.dumps({
            "MESSAGE": "Failed password for root from 203.0.113.2 port 1 ssh2",
            "__REALTIME_TIMESTAMP": "1792400000000000",
            "SYSLOG_IDENTIFIER": "sshd",
            "_PID": "9",
            "_HOSTNAME": "srv",
        })

        item = parse(line)

        self.assertEqual(item.event_type, EventType.SSH_LOGIN_FAILED)
        self.assertEqual(item.process_id, 9)
        self.assertEqual(item.timestamp.tzinfo, timezone.utc)


class CorrelationTests(unittest.TestCase):
    @staticmethod
    def reference(events, minutes, threshold, key=None):
        """Straightforward (slow) implementation used as a reference."""
        ordered = sorted(events, key=lambda e: (e.timestamp, e.source, e.line_number))
        duration = timedelta(minutes=minutes)
        matches, left, start, end = [], 0, None, None

        for right, current in enumerate(ordered):
            while current.timestamp - ordered[left].timestamp > duration:
                left += 1

            window = ordered[left:right + 1]
            count = len(window) if key is None else len({key(i) for i in window})

            if count >= threshold:
                start = left if start is None else start
                end = right
            elif start is not None:
                matches.append(ordered[start:end + 1])
                start = end = None

        if start is not None:
            matches.append(ordered[start:end + 1])

        return matches

    def test_windows_match_the_reference_implementation(self):
        generator = random.Random(7)

        for _ in range(150):
            events = [
                event(generator.randint(0, 3000), ip=f"10.0.0.{generator.randint(1, 6)}")
                for _ in range(generator.randint(0, 50))
            ]

            for key in (None, lambda item: item.source_ip):
                for threshold in (2, 4):
                    self.assertEqual(
                        find_event_windows(events, 10, threshold, key),
                        self.reference(events, 10, threshold, key),
                    )

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            find_event_windows([], 0, 5)

        with self.assertRaises(ValueError):
            find_event_windows([], 5, 0)

    def test_large_inputs_are_processed_in_linear_time(self):
        events = [event(i // 10) for i in range(40_000)]

        self.assertEqual(len(find_event_windows(events, 10, 5)), 1)

    def test_invalid_user_and_failure_of_one_attempt_count_once(self):
        events = [
            event(0, kind=EventType.SSH_INVALID_USER, pid=7),
            event(1, kind=EventType.SSH_LOGIN_FAILED, pid=7),
            event(2, kind=EventType.SSH_LOGIN_FAILED, pid=8),
            event(3, kind=EventType.SSH_LOGIN_FAILED, pid=9),
        ]

        self.assertEqual(len(deduplicate_ssh_failures(events)), 3)

    def test_success_after_failures(self):
        events = [event(i * 10) for i in range(3)]
        events.append(event(60, kind=EventType.SSH_LOGIN_SUCCESS))

        found = find_success_after_failures(events, 3, 15)

        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0][1]), 3)
        self.assertEqual(find_success_after_failures(events, 4, 15), [])


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            event(0, ip="1.1.1.1", user="root"),
            event(60, ip="2.2.2.2", user="alice"),
            event(120, ip="2.2.2.2", user="alice", kind=EventType.SSH_LOGIN_SUCCESS),
        ]

    def test_by_address_user_and_type(self):
        by_ip = filter_events(self.events, create_filters(source_ip="2.2.2.2"))
        by_user = filter_events(self.events, create_filters(username="root"))
        by_type = filter_events(
            self.events,
            create_filters(event_types=["ssh_login_success"]),
        )

        self.assertEqual(len(by_ip), 2)
        self.assertEqual(len(by_user), 1)
        self.assertEqual(len(by_type), 1)

    def test_by_time_range_in_the_configured_zone(self):
        filters = create_filters(
            start_date="2026-10-13T21:00:30",   # 00:00:30 UTC
            end_date="2026-10-13T21:01:30",
            timezone_name="America/Argentina/Buenos_Aires",
        )

        self.assertEqual(len(filter_events(self.events, filters)), 1)

    def test_invalid_values(self):
        for kwargs in (
            {"source_ip": "999.1.1.1"},
            {"event_types": ["not_a_type"]},
            {"start_date": "yesterday"},
            {"start_date": "2026-10-15", "end_date": "2026-10-14"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    create_filters(**kwargs)


class ReaderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_discovers_log_files_and_rotations(self):
        for name in ("auth.log", "auth.log.1", "syslog", "app.log", "notes.txt"):
            (self.root / name).write_text("x\n")

        with gzip.open(self.root / "auth.log.2.gz", "wt") as stream:
            stream.write("x\n")

        found = {path.name for path in discover_log_files(self.root).files}

        self.assertEqual(
            found,
            {"auth.log", "auth.log.1", "auth.log.2.gz", "syslog", "app.log"},
        )

    def test_recursive_discovery(self):
        (self.root / "sub").mkdir()
        (self.root / "sub" / "auth.log").write_text("x\n")

        self.assertEqual(discover_log_files(self.root).files, [])
        self.assertEqual(len(discover_log_files(self.root, recursive=True).files), 1)

    @requires_linux
    def test_symbolic_links_are_skipped(self):
        (self.root / "real.log").write_text("x\n")
        (self.root / "link.log").symlink_to(self.root / "real.log")

        found = {path.name for path in discover_log_files(self.root).files}

        self.assertEqual(found, {"real.log"})

    def test_reads_plain_and_compressed_files(self):
        plain = self.root / "a.log"
        plain.write_text("one\ntwo\n")
        packed = self.root / "b.log.gz"

        with gzip.open(packed, "wt") as stream:
            stream.write("three\n")

        self.assertEqual([line.content for line in read_log_lines(plain)], ["one", "two"])
        self.assertEqual([line.content for line in read_log_lines(packed)], ["three"])

    def test_missing_target(self):
        with self.assertRaises(ValueError):
            discover_log_files(self.root / "missing")


class DetectorTests(LogTestCase):
    def test_brute_force(self):
        lines = [failed_login(minute, "198.51.100.7") for minute in range(6)]

        findings = self.analyze(lines).findings

        self.assertEqual([f.rule_id for f in findings], ["brute_force"])
        self.assertEqual(findings[0].source_ip, "198.51.100.7")
        self.assertEqual(findings[0].event_count, 6)

    def test_slow_or_small_attempts_are_not_brute_force(self):
        few = [failed_login(minute, "198.51.100.7") for minute in range(4)]
        slow = [failed_login(minute * 5, "198.51.100.7") for minute in range(6)]

        self.assertEqual(self.rules(few), [])
        self.assertEqual(self.rules(slow), [])

    def test_threshold_is_configurable(self):
        from src.logs.config import ThresholdConfig

        lines = [failed_login(minute, "198.51.100.7") for minute in range(3)]

        self.assertEqual(
            self.rules(lines, brute_force=ThresholdConfig(3, 10)),
            ["brute_force"],
        )

    def test_password_spraying(self):
        lines = [
            failed_login(minute, "198.51.100.7", user=f"user{minute}")
            for minute in range(6)
        ]

        self.assertIn("password_spraying", self.rules(lines))

    def test_distributed_attack(self):
        lines = [
            failed_login(minute, f"192.0.2.{10 + minute}", user="admin")
            for minute in range(6)
        ]

        findings = self.analyze(lines).findings

        self.assertEqual([f.rule_id for f in findings], ["distributed_attack"])
        self.assertEqual(findings[0].username, "admin")
        self.assertEqual(findings[0].severity.value, "HIGH")

    def test_success_after_failures(self):
        lines = [failed_login(minute, "198.51.100.9", user="alice", hour=10) for minute in range(3)]
        lines.append(syslog(14, 10, 5, 0, "sshd", "Accepted password for alice from 198.51.100.9 port 1 ssh2", 200))

        findings = self.analyze(lines).findings

        self.assertEqual([f.rule_id for f in findings], ["successful_after_failures"])
        self.assertEqual(findings[0].severity.value, "HIGH")

    def test_login_outside_business_hours(self):
        sunday = syslog(18, 3, 0, 0, "sshd", "Accepted publickey for alice from 10.0.0.5 port 22 ssh2")
        weekday = syslog(14, 10, 0, 0, "sshd", "Accepted publickey for alice from 10.0.0.5 port 22 ssh2")

        self.assertEqual(self.rules([sunday]), ["outside_business_hours"])
        self.assertEqual(self.rules([weekday]), [])

    def test_new_source_ip_needs_a_baseline(self):
        login = syslog(14, 10, 0, 0, "sshd", "Accepted publickey for alice from 203.0.113.9 port 22 ssh2")

        without = self.analyze([login])
        known = self.analyze([login], known_ips={"10.0.0.5"})
        approved = self.analyze([login], known_ips={"203.0.113.9"})

        self.assertEqual(without.findings, [])
        self.assertTrue(any("baseline" in warning for warning in without.warnings))
        self.assertEqual([f.rule_id for f in known.findings], ["new_source_ip"])
        self.assertEqual(approved.findings, [])

    def test_privileged_activity(self):
        sudo = syslog(14, 10, 0, 0, "sudo", "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", 300)
        root = syslog(14, 10, 0, 0, "sshd", "Accepted publickey for root from 10.0.0.5 port 22 ssh2", 500)

        self.assertEqual(self.rules([sudo]), ["privileged_activity"])
        self.assertEqual(self.analyze([root]).findings[0].severity.value, "HIGH")

    def test_account_changes(self):
        line = syslog(14, 10, 0, 0, "useradd", "new user: name=bob, UID=1001, GID=1001, home=/home/bob", 600)

        findings = self.analyze([line]).findings

        self.assertEqual([f.rule_id for f in findings], ["account_changes"])
        self.assertEqual(findings[0].username, "bob")

    def test_repeated_service_errors(self):
        lines = [syslog(14, 10, i, 0, "nginx", "connect() failed: error", 700 + i) for i in range(6)]

        self.assertEqual(self.rules(lines), ["service_errors"])

    def test_disabled_rules_are_skipped(self):
        lines = [failed_login(minute, "198.51.100.7") for minute in range(6)]

        self.assertEqual(self.rules(lines, enabled_rules=frozenset({"service_errors"})), [])

    def test_counts_unparsed_lines(self):
        result = self.analyze(["garbage", failed_login(0, "1.2.3.4")])

        self.assertEqual(result.lines_unparsed, 1)
        self.assertEqual(len(result.events), 1)

    def test_invalid_month_is_reported_without_stopping(self):
        result = self.analyze(["Foo 14 10:00:00 srv sshd[1]: x", failed_login(0, "1.2.3.4")])

        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.errors), 1)


class IpHistoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "nested" / "known.json"

    def test_missing_file_means_no_baseline(self):
        self.assertIsNone(load_known_ips(self.path))

    def test_save_load_approve_and_revoke(self):
        save_known_ips(self.path, {"10.0.0.5"})

        self.assertEqual(load_known_ips(self.path), {"10.0.0.5"})
        self.assertEqual(
            approve_ips(self.path, ["10.0.0.6", "2001:db8::1"]),
            {"10.0.0.5", "10.0.0.6", "2001:db8::1"},
        )
        self.assertEqual(revoke_ips(self.path, ["10.0.0.5"]), {"10.0.0.6", "2001:db8::1"})

    def test_rejects_invalid_addresses(self):
        with self.assertRaises(ValueError):
            approve_ips(self.path, ["not-an-ip"])


class ConfigTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, text):
        path = self.root / "config.yaml"
        path.write_text(text)
        return path

    def test_defaults(self):
        config = load_config(None)

        self.assertEqual(config.timezone, "UTC")
        self.assertEqual(config.brute_force.threshold, 5)
        self.assertEqual(config.enabled_rules, frozenset(AVAILABLE_RULES))

    def test_overrides(self):
        config = load_config(self.write(
            "timezone: America/Argentina/Buenos_Aires\n"
            "brute_force:\n  threshold: 3\n  window_minutes: 20\n"
        ))

        self.assertEqual(config.timezone, "America/Argentina/Buenos_Aires")
        self.assertEqual(config.brute_force.threshold, 3)
        self.assertEqual(config.brute_force.window_minutes, 20)

    def test_invalid_configuration(self):
        for text in (
            "unknown_key: 1\n",
            "timezone: Not/AZone\n",
            "brute_force:\n  threshold: 0\n  window_minutes: 5\n",
            "brute_force: 5\n",
            "- a list\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    load_config(self.write(text))


class CommandLineTests(LogTestCase):
    def test_analyze_and_export_json(self):
        log = self.write_log([failed_login(minute, "198.51.100.7") for minute in range(6)])
        config = self.root / "config.yaml"
        config.write_text(f"ip_history_path: {self.baseline_path}\n")
        report = self.root / "report.json"

        code, output = run_cli(
            "logs", "--config", config, "analyze", log,
            "--year", 2026, "--json", report,
        )

        self.assertEqual(code, 0, output)
        self.assertIn("brute-force", output.lower())
        data = json.loads(report.read_text())
        self.assertEqual([f["rule_id"] for f in data["findings"]], ["brute_force"])
        self.assertIn("warnings", data)

    def test_errors_are_reported_with_exit_code_2(self):
        code, output = run_cli("logs", "analyze", self.root / "missing.log")

        self.assertNotEqual(code, 0)
        self.assertIn("Error", output)

    def test_baseline_management(self):
        config = self.root / "config.yaml"
        config.write_text(f"ip_history_path: {self.baseline_path}\n")

        self.assertEqual(run_cli("logs", "--config", config, "ips", "init")[0], 0)
        self.assertNotEqual(run_cli("logs", "--config", config, "ips", "init")[0], 0)
        run_cli("logs", "--config", config, "ips", "approve", "10.0.0.5")

        code, output = run_cli("logs", "--config", config, "ips", "list")

        self.assertEqual(code, 0)
        self.assertIn("10.0.0.5", output)


if __name__ == "__main__":
    unittest.main()
