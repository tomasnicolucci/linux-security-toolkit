"""Helpers shared by the log analyzer and statistics tests."""

import argparse
import tempfile
import unittest
from pathlib import Path

from src.logs.cli import analyze_logs
from src.logs.config import LogAnalyzerConfig
from src.logs.ip_history import save_known_ips


def syslog(day, hour, minute, second, service, message, pid=100):
    """A traditional syslog line of October (2026: the 14th is a Wednesday)."""
    return (
        f"Oct {day} {hour:02d}:{minute:02d}:{second:02d} "
        f"srv {service}[{pid}]: {message}"
    )


def failed_login(minute, ip, user="root", day=14, hour=3, pid=None):
    return syslog(
        day,
        hour,
        minute,
        0,
        "sshd",
        f"Failed password for {user} from {ip} port 1 ssh2",
        pid if pid is not None else 100 + minute,
    )


class LogTestCase(unittest.TestCase):
    """Creates a temporary directory and runs the analyzer on log lines."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.baseline_path = self.root / "known_ips.json"

    def write_log(self, lines, name="auth.log"):
        path = self.root / name
        path.write_text("\n".join(lines) + "\n")
        return path

    def config(self, **overrides):
        return LogAnalyzerConfig(
            ip_history_path=str(self.baseline_path),
            **overrides,
        )

    def analyze(self, lines, known_ips=None, **overrides):
        """Run the analyzer; returns the AnalysisResult."""
        if known_ips is not None:
            save_known_ips(self.baseline_path, set(known_ips))

        arguments = argparse.Namespace(
            target=self.write_log(lines),
            recursive=False,
            year=2026,
            source_ip=None,
            username=None,
            event_types=None,
            start_date=None,
            end_date=None,
        )

        return analyze_logs(arguments, self.config(**overrides))

    def rules(self, lines, **kwargs):
        return sorted(
            finding.rule_id
            for finding in self.analyze(lines, **kwargs).findings
        )
