import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from src.logs.config import LogAnalyzerConfig
from src.statistics.analyzer import analyze_statistics
from src.statistics.metrics import MAX_BUCKETS
from src.statistics.periods import (
    SECOND,
    build_period,
    previous_period,
    resolve_period,
)
from src.statistics.comparison import percent_change
from src.logs.filters import parse_filter_date
from tests.helpers import run_cli
from tests.logs_support import syslog

A, B, C, D = "203.0.113.10", "203.0.113.11", "198.51.100.5", "192.0.2.77"


def failure(day, hour, minute, ip, user, pid):
    return syslog(day, hour, minute, 5, "sshd", f"Failed password for {user} from {ip} port 1 ssh2", pid)


def success(day, hour, minute, pid):
    return syslog(day, hour, minute, 0, "sshd", f"Accepted publickey for alice from {C} port 22 ssh2", pid)


def two_days():
    """Day 18 is the 'previous' period and day 19 the analyzed one."""
    lines = []
    pid = [1000]

    def next_pid():
        pid[0] += 1
        return pid[0]

    # Day 18
    lines += [failure(18, 3, m, A, "root", next_pid()) for m in range(10)]
    lines += [failure(18, 14, m, B, "admin", next_pid()) for m in range(4)]
    lines += [success(18, 9, m * 10, next_pid()) for m in range(3)]
    lines += [syslog(18, 10, m, 0, "sudo", "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", next_pid()) for m in range(2)]
    # Day 19
    lines += [failure(19, 2, m, A, "root", next_pid()) for m in range(20)]
    lines += [failure(19, 14, m, D, "test", next_pid()) for m in range(6)]
    lines += [success(19, 9, m * 10, next_pid()) for m in range(2)]
    lines += [syslog(19, 10, 0, 0, "sudo", "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", next_pid())]
    lines += [syslog(19, 11, 0, 0, "useradd", "new user: name=bob, UID=1001, GID=1001, home=/home/bob", next_pid())]
    lines += [syslog(19, 12, m, 0, "systemd", "Failed to start backup.service: error", next_pid()) for m in range(3)]

    return lines


class StatisticsTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def log(self, lines=None, name="auth.log"):
        path = self.root / name
        path.write_text("\n".join(lines if lines is not None else two_days()) + "\n")
        return path

    def stats(self, lines=None, **kwargs):
        options = {"year": 2026}
        options.update(kwargs)

        return analyze_statistics(self.log(lines), LogAnalyzerConfig(), **options)


class PeriodTests(unittest.TestCase):
    def test_end_is_inclusive_and_duration_is_exact(self):
        start = parse_filter_date("2026-10-19T00:00:00", "UTC")
        end = parse_filter_date("2026-10-19T23:59:59", "UTC")

        period = build_period(start, end)

        self.assertEqual(period.duration, timedelta(days=1))
        self.assertEqual(period.end, end)
        self.assertTrue(period.contains(end))
        self.assertFalse(period.contains(end + SECOND))

    def test_previous_period_ends_where_the_current_one_starts(self):
        start = parse_filter_date("2026-10-19T00:00:00", "UTC")
        end = parse_filter_date("2026-10-19T23:59:59", "UTC")
        period = build_period(start, end)

        previous = previous_period(period)

        self.assertEqual(previous.end_exclusive, period.start)
        self.assertEqual(previous.duration, period.duration)

    def test_start_cannot_be_after_end(self):
        start = parse_filter_date("2026-10-20T00:00:00", "UTC")
        end = parse_filter_date("2026-10-19T00:00:00", "UTC")

        with self.assertRaises(ValueError):
            build_period(start, end)

    def test_open_limits_use_the_observed_range(self):
        from src.logs.models import EventType, SecurityEvent
        from datetime import datetime, timezone

        def make(second):
            return SecurityEvent(
                timestamp=datetime(2026, 10, 19, 0, 0, second, tzinfo=timezone.utc),
                event_type=EventType.UNKNOWN,
                source="t",
                line_number=second,
                service="x",
                message="m",
            )

        events = [make(10), make(50)]

        period = resolve_period(events, None, None, "UTC")

        self.assertEqual(period.start, events[0].timestamp)
        self.assertTrue(period.contains(events[1].timestamp))


class MetricsTests(StatisticsTestCase):
    def test_period_metrics(self):
        result = self.stats(start_text="2026-10-19T00:00:00", end_text="2026-10-19T23:59:59")

        self.assertEqual(
            result.period.metrics,
            {
                "total_events": 33,
                "ssh_failed": 26,
                "ssh_success": 2,
                "privilege_use": 1,
                "privilege_failures": 0,
                "account_changes": 1,
                "service_errors": 3,
                "unique_source_ips": 3,
                "unique_users": 4,
            },
        )
        self.assertEqual(result.period.ssh_success_rate, 7.1)

    def test_top_lists_show_failures_and_successes(self):
        result = self.stats(start_text="2026-10-19T00:00:00", end_text="2026-10-19T23:59:59")

        top_ip = result.period.top_ips[0]
        top_user = result.period.top_users[0]

        self.assertEqual((top_ip.name, top_ip.events, top_ip.failed), (A, 20, 20))
        self.assertEqual((top_user.name, top_user.events), ("root", 20))
        alice = [u for u in result.period.top_users if u.name == "alice"][0]
        self.assertEqual((alice.success, alice.failed), (2, 0))

    def test_top_limit(self):
        result = self.stats(top=1)

        self.assertEqual(len(result.period.top_ips), 1)

    def test_refused_sudo_counts_as_a_privilege_failure(self):
        lines = [
            syslog(19, 10, 0, 0, "sudo", "alice : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/ls", 1),
            syslog(19, 10, 1, 0, "sudo", "alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls", 2),
        ]

        metrics = self.stats(lines).period.metrics

        self.assertEqual(metrics["privilege_failures"], 1)
        self.assertEqual(metrics["privilege_use"], 1)

    def test_duplicate_ssh_failure_records_are_counted_once(self):
        lines = [
            syslog(19, 3, 0, 0, "sshd", f"Invalid user zed from {A} port 1", 7),
            syslog(19, 3, 0, 1, "sshd", f"Failed password for invalid user zed from {A} port 1 ssh2", 7),
        ]

        self.assertEqual(self.stats(lines).period.metrics["ssh_failed"], 1)


class TrendTests(StatisticsTestCase):
    def test_hourly_buckets_for_one_day(self):
        result = self.stats(start_text="2026-10-19T00:00:00", end_text="2026-10-19T23:59:59")
        buckets = result.trend.buckets

        self.assertEqual(result.trend.granularity, "hour")
        self.assertEqual(len(buckets), 24)
        self.assertEqual([b.events for b in buckets].count(0), 18)
        self.assertEqual((result.trend.peak_label, result.trend.peak_events), ("2026-10-19 02:00", 20))
        self.assertEqual(buckets[2].failed, 20)

    def test_daily_buckets_for_long_periods(self):
        result = self.stats(start_text="2026-10-01T00:00:00", end_text="2026-10-19T23:59:59")

        self.assertEqual(result.trend.granularity, "day")
        self.assertEqual(len(result.trend.buckets), 19)

    def test_bucket_labels_follow_the_configured_zone(self):
        lines = [syslog(19, 2, 30, 0, "sshd", f"Failed password for root from {A} port 1 ssh2", 5)]
        config = LogAnalyzerConfig(timezone="America/Argentina/Buenos_Aires")
        path = self.log(lines)

        result = analyze_statistics(path, config, year=2026)

        # 02:30 Buenos Aires time stays 02:30 for the labels, and the
        # reported period uses the configured zone (UTC-3).
        self.assertEqual(result.trend.peak_label, "2026-10-19 02:00")
        self.assertEqual(result.period.start.utcoffset(), timedelta(hours=-3))

    def test_too_many_buckets_are_rejected(self):
        with self.assertRaises(ValueError):
            self.stats(start_text="2026-01-01T00:00:00", end_text="2026-10-19T23:59:59", granularity="hour")

        self.assertGreater(MAX_BUCKETS, 0)


class ComparisonTests(StatisticsTestCase):
    def compare(self, **kwargs):
        return self.stats(
            start_text="2026-10-19T00:00:00",
            end_text="2026-10-19T23:59:59",
            compare_previous=True,
            **kwargs,
        ).comparison

    def test_changes_between_periods(self):
        changes = {change.name: change for change in self.compare().changes}

        failed = changes["ssh_failed"]
        errors = changes["service_errors"]

        self.assertEqual((failed.current, failed.previous, failed.difference), (26, 14, 12))
        self.assertEqual(failed.change_percent, 85.7)
        self.assertEqual((errors.previous, errors.change_percent), (0, None))
        self.assertEqual(changes["ssh_success"].difference, -1)

    def test_new_and_vanished_addresses_and_users(self):
        comparison = self.compare()

        self.assertEqual([i.name for i in comparison.new_ips], [D])
        self.assertEqual([i.name for i in comparison.gone_ips], [B])
        self.assertEqual(comparison.new_users_total, 2)
        self.assertEqual([u.name for u in comparison.gone_users], ["admin"])

    def test_explicit_comparison_period(self):
        result = self.stats(
            start_text="2026-10-19T00:00:00",
            end_text="2026-10-19T23:59:59",
            compare_with=("2026-10-18T00:00:00", "2026-10-18T23:59:59"),
        )

        self.assertEqual(result.comparison.previous.metrics["total_events"], 19)

    def test_percent_change(self):
        self.assertIsNone(percent_change(5, 0))
        self.assertEqual(percent_change(150, 100), 50.0)
        self.assertEqual(percent_change(50, 100), -50.0)
        self.assertEqual(percent_change(0, 10), -100.0)

    def test_warns_when_the_logs_do_not_cover_the_comparison_period(self):
        result = self.stats(
            [failure(19, 3, 0, A, "root", 1)],
            start_text="2026-10-19T00:00:00",
            end_text="2026-10-19T23:59:59",
            compare_previous=True,
        )

        text = " ".join(result.warnings)

        self.assertIn("No events found in the comparison period", text)
        self.assertIn("may be incomplete", text)

    def test_warns_about_overlapping_periods(self):
        result = self.stats(
            start_text="2026-10-19T00:00:00",
            end_text="2026-10-19T23:59:59",
            compare_with=("2026-10-19T12:00:00", "2026-10-20T12:00:00"),
        )

        self.assertTrue(any("overlaps" in warning for warning in result.warnings))


class InputTests(StatisticsTestCase):
    def test_no_events_is_an_error(self):
        with self.assertRaises(ValueError):
            self.stats(["not a log line"])

    def test_bad_lines_are_reported_but_do_not_stop_the_analysis(self):
        result = self.stats(["Foo 19 12:00:00 srv sshd[1]: x", failure(19, 3, 0, A, "root", 2)])

        self.assertEqual(result.period.metrics["total_events"], 1)
        self.assertEqual(len(result.errors), 1)

    def test_rotated_files_in_a_directory(self):
        import gzip

        previous = [line for line in two_days() if line.startswith("Oct 18")]
        current = [line for line in two_days() if line.startswith("Oct 19")]
        directory = self.root / "logs"
        directory.mkdir()
        (directory / "auth.log").write_text("\n".join(current) + "\n")

        with gzip.open(directory / "auth.log.1.gz", "wt") as stream:
            stream.write("\n".join(previous) + "\n")

        result = analyze_statistics(
            directory,
            LogAnalyzerConfig(),
            year=2026,
            start_text="2026-10-19T00:00:00",
            end_text="2026-10-19T23:59:59",
            compare_previous=True,
        )

        self.assertEqual(result.comparison.previous.metrics["total_events"], 19)
        self.assertFalse(any("No events" in warning for warning in result.warnings))


class CommandLineTests(StatisticsTestCase):
    def test_report_and_json_export(self):
        log = self.log()
        report = self.root / "stats.json"

        code, output = run_cli(
            "stats", "analyze", log, "--year", 2026,
            "--from", "2026-10-19T00:00:00", "--to", "2026-10-19T23:59:59",
            "--compare-previous", "--json", report,
        )

        self.assertEqual(code, 0, output)
        self.assertIn("Trend by hour", output)
        self.assertIn("New source IPs: 1", output)
        data = json.loads(report.read_text())
        self.assertEqual(data["period"]["metrics"]["total_events"], 33)
        self.assertEqual(data["comparison"]["new_ips_total"], 1)

    def test_invalid_options(self):
        log = self.log()

        self.assertNotEqual(run_cli("stats", "analyze", log, "--top", 0)[0], 0)
        self.assertNotEqual(
            run_cli("stats", "analyze", log, "--compare-previous", "--compare-with", "a", "b")[0], 0
        )
        self.assertNotEqual(run_cli("stats", "analyze", self.root / "missing.log")[0], 0)


if __name__ == "__main__":
    unittest.main()
