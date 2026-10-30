import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.helpers import PROJECT_ROOT, requires_linux

SCRIPT = PROJECT_ROOT / "src" / "users" / "user_auditor.sh"
SAMPLE = PROJECT_ROOT / "samples" / "system"
NOW = "1792540800"  # 2026-10-21, fixes the age of passwords

# Findings the sample tree is designed to produce.
SAMPLE_FINDINGS = {
    "UA-001": 1, "UA-002": 1, "UA-003": 1, "UA-004": 2, "UA-005": 1,
    "UA-006": 1, "UA-007": 1, "UA-008": 2, "UA-010": 1, "UA-012": 1,
    "UA-013": 1, "UA-014": 1, "UA-015": 3, "UA-016": 4, "UA-018": 1,
    "UA-020": 3, "UA-022": 3, "UA-023": 1, "UA-025": 1, "UA-040": 1,
    "UA-042": 1, "UA-050": 1,
}

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    "bob:x:1001:1001:Bob:/home/bob:/bin/bash\n"
)
SHADOW = (
    "root:$6$salt$hash:20600:0:90:7:::\n"
    "daemon:*:20600:0:99999:7:::\n"
    "alice:$y$j9T$salt$hash:20600:0:90:7:::\n"
    "bob:$y$j9T$salt$hash:20600:0:90:7:::\n"
)
GROUP = "root:x:0:\ndaemon:x:1:\nsudo:x:27:alice\nalice:x:1000:\nbob:x:1001:\n"
SUDOERS = "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n"
LOGIN_DEFS = "UID_MIN 1000\nUID_MAX 60000\nPASS_MAX_DAYS 90\nENCRYPT_METHOD SHA512\n"


def bash_available():
    return shutil.which("bash") is not None


@requires_linux
@unittest.skipUnless(bash_available(), "bash is required")
class AuditorTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def audit(self, *args, root=SAMPLE, path=None, permissions=False):
        extra = [] if permissions else ["--no-permission-checks"]
        env = {**os.environ, "USER_AUDITOR_NOW": NOW}

        if path:
            env["PATH"] = f"{path}{os.pathsep}{env['PATH']}"

        result = subprocess.run(
            ["bash", str(SCRIPT), "--root", str(root), "--no-color", *extra, *map(str, args)],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )

        return result.returncode, result.stdout + result.stderr

    def audit_json(self, *args, **kwargs):
        report = self.root / "report.json"
        code, output = self.audit("--json", report, *args, **kwargs)

        return code, output, json.loads(report.read_text())

    def tree(self, passwd=PASSWD, shadow=SHADOW, group=GROUP, sudoers=SUDOERS,
             login_defs=LOGIN_DEFS, sshd=None, name="tree"):
        root = self.root / name
        etc = root / "etc"
        (etc / "ssh").mkdir(parents=True)
        (etc / "sudoers.d").mkdir()

        for filename, content in (
            ("passwd", passwd), ("shadow", shadow), ("group", group),
            ("sudoers", sudoers), ("login.defs", login_defs),
        ):
            if content is not None:
                (etc / filename).write_text(content)

        if sshd is not None:
            (etc / "ssh" / "sshd_config").write_text(sshd)

        return root

    def ids(self, report):
        return sorted({finding["id"] for finding in report["findings"]})


class SampleTreeTests(AuditorTestCase):
    def test_the_sample_tree_produces_the_documented_findings(self):
        code, _, report = self.audit_json()

        self.assertEqual(code, 0)
        self.assertEqual(
            report["summary"],
            {"accounts": 19, "findings": 33, "critical": 2, "high": 8, "medium": 11, "low": 12},
        )

        counts = {}

        for finding in report["findings"]:
            counts[finding["id"]] = counts.get(finding["id"], 0) + 1

        self.assertEqual(counts, SAMPLE_FINDINGS)

    def test_critical_findings(self):
        _, _, report = self.audit_json()
        critical = {(f["id"], f["subject"]) for f in report["findings"] if f["severity"] == "CRITICAL"}

        self.assertEqual(critical, {("UA-001", "toor"), ("UA-002", "carol")})

    def test_sudo_privileges_are_resolved_through_groups_and_aliases(self):
        _, _, report = self.audit_json()
        sudo = {a["user"]: a["sudo"] for a in report["accounts"] if a["sudo"] != "-"}

        self.assertEqual(
            sudo,
            {"root": "full", "alice": "full", "carol": "full",
             "svc-deploy": "full", "bob": "limited", "dave": "limited"},
        )

    def test_console_report(self):
        code, output = self.audit()

        self.assertIn("Accounts: 19 total", output)
        self.assertIn("[CRITICAL] UA-001", output)
        self.assertIn("Summary: 2 CRITICAL | 8 HIGH | 11 MEDIUM | 12 LOW", output)
        self.assertIn("Fix:", output)

    def test_hashes_are_hidden_by_default(self):
        code, output, _ = self.audit_json()
        report_text = (self.root / "report.json").read_text()

        self.assertNotIn("FAKEHASH", output + report_text)
        self.assertNotIn("Password hashes", output)

    def test_hashes_can_be_shown_and_the_export_is_private(self):
        code, output, report = self.audit_json("--show-hashes")
        eve = [a for a in report["accounts"] if a["user"] == "eve"][0]

        self.assertIn("Password hashes (SENSITIVE", output)
        self.assertIn("$1$evesalt$", output)
        self.assertTrue(eve["hash"].startswith("$1$evesalt$"))
        self.assertEqual(eve["password_source"], "passwd")
        self.assertEqual(stat.S_IMODE((self.root / "report.json").stat().st_mode), 0o600)

    def test_severity_filter_and_exit_codes(self):
        _, output = self.audit("--min-severity", "critical")

        self.assertIn("UA-001", output)
        self.assertNotIn("UA-015", output)
        self.assertEqual(self.audit("--fail-on", "critical")[0], 1)
        self.assertEqual(self.audit("--fail-on", "low")[0], 1)

    def test_files_edited_on_windows_give_the_same_result(self):
        copy = self.root / "crlf"
        shutil.copytree(SAMPLE, copy)

        for path in copy.rglob("*"):
            if path.is_file():
                # Normalize first: the checkout may already use CRLF.
                data = path.read_bytes().replace(b"\r\n", b"\n")
                path.write_bytes(data.replace(b"\n", b"\r\n"))

        _, _, original = self.audit_json()
        _, _, windows = self.audit_json(root=copy)

        self.assertEqual(original["summary"], windows["summary"])


class RuleTests(AuditorTestCase):
    def test_a_healthy_system_has_no_findings(self):
        sshd = "PermitRootLogin prohibit-password\nPasswordAuthentication no\n"

        code, output, report = self.audit_json(root=self.tree(sshd=sshd))

        self.assertEqual(report["findings"], [], output)

    def test_unreadable_required_files_are_an_error(self):
        code, output = self.audit(root=self.tree(passwd=None))

        self.assertEqual(code, 2)
        self.assertIn("/etc/passwd", output)

    def test_sudoers_rules(self):
        sudoers = (
            "Defaults !authenticate\n"
            "Defaults env_keep += \"LD_PRELOAD\"\n"
            "User_Alias ADMINS = alice, #1001\n"
            "Cmnd_Alias SHELLS = /bin/bash, /usr/bin/python3\n"
            "ALL ALL=(ALL) ALL\n"
            "ADMINS ALL=(ALL) NOPASSWD: SHELLS, /usr/bin/id\n"
            "bob ALL=(postgres) NOPASSWD: ALL\n"
            "daemon ALL=(root) /usr/bin/systemctl restart *\n"
        )

        _, _, report = self.audit_json(root=self.tree(sudoers=sudoers))
        titles = " | ".join(f["title"] for f in report["findings"])

        self.assertEqual(
            self.ids(report),
            ["UA-020", "UA-021", "UA-022", "UA-023", "UA-024"],
        )
        self.assertIn("every user", titles)
        # bob only runs commands as the postgres user, which is not root.
        self.assertFalse([f for f in report["findings"] if "bob" in f["subject"]])

    def test_sudo_includes_and_line_continuations(self):
        root = self.tree(sudoers="@includedir /etc/sudoers.d\n")
        (root / "etc" / "sudoers.d" / "10-ops").write_text(
            "bob ALL=(ALL) \\\n    NOPASSWD: /usr/bin/vim\n"
        )
        (root / "etc" / "sudoers.d" / "skipped.bak").write_text("daemon ALL=(ALL) NOPASSWD: ALL\n")

        _, _, report = self.audit_json(root=root)
        subjects = [f["subject"] for f in report["findings"]]

        self.assertTrue(any("10-ops" in subject for subject in subjects))
        self.assertFalse(any("skipped" in subject for subject in subjects))

    def test_sshd_directives_use_the_first_value_and_ignore_match_blocks(self):
        root = self.tree(sshd="Include sshd_config.d/*.conf\nPermitRootLogin no\n"
                              "Match User x\n    PermitRootLogin yes\n")
        directory = root / "etc" / "ssh" / "sshd_config.d"
        directory.mkdir()
        (directory / "50.conf").write_text("PermitRootLogin yes\nPermitEmptyPasswords yes\n")

        _, _, report = self.audit_json(root=root)

        # The included file comes first, so its values win.
        self.assertIn("UA-040", self.ids(report))
        self.assertIn("UA-041", self.ids(report))

    def test_sensitive_data_is_not_printed_without_the_option(self):
        _, output = self.audit()

        self.assertNotIn("$6$", output)
        self.assertNotIn("$y$", output)

    def test_hostile_values_cannot_break_the_output(self):
        passwd = PASSWD + (
            "evil:x:2000:2000:\x1b[31mRED\x1b[0m:/home/evil\x1b[2J:/bin/bash\n"
            "*:x:2001:2001::/h:/bin/sh\n"
            "bad name:x:2003:2003::/h:/bin/sh\n"
            "num:x:abc:2004::/h:/bin/sh\n"
        )

        code, output, report = self.audit_json(root=self.tree(passwd=passwd))

        self.assertEqual(code, 0, output)
        self.assertNotIn("\x1b", output)
        self.assertEqual(len([f for f in report["findings"] if f["id"] == "UA-014"]), 3)

    def test_weak_hashes_and_hash_in_passwd(self):
        passwd = PASSWD + "eve:$1$salt$hash:1002:1002::/home/eve:/bin/bash\n"
        shadow = SHADOW + "carol::20600:0:90:7:::\n"
        passwd += "carol:x:1003:1003::/home/carol:/bin/bash\n"

        _, _, report = self.audit_json(root=self.tree(passwd=passwd, shadow=shadow))

        self.assertTrue({"UA-002", "UA-003", "UA-004"} <= set(self.ids(report)))

    def test_duplicate_ids_and_users(self):
        passwd = PASSWD + "twin:x:1000:1000::/home/twin:/bin/bash\nbob:x:1005:1005::/h:/bin/bash\n"

        _, _, report = self.audit_json(root=self.tree(passwd=passwd))

        self.assertTrue({"UA-008", "UA-009"} <= set(self.ids(report)))

    def test_root_equivalent_groups(self):
        group = GROUP + "docker:x:998:bob\n"

        _, _, report = self.audit_json(root=self.tree(group=group))

        self.assertIn("UA-025", self.ids(report))

    def test_permissions_of_critical_files(self):
        root = self.tree()
        (root / "etc" / "shadow").chmod(0o644)
        (root / "etc" / "group").chmod(0o666)

        _, _, report = self.audit_json(root=root, permissions=True)
        titles = [f["title"] for f in report["findings"] if f["id"] == "UA-030"]

        self.assertTrue(any("/etc/shadow is accessible by other users" in t for t in titles))
        self.assertTrue(any("/etc/group is writable by everyone" in t for t in titles))

    def test_home_directories_and_ssh_keys(self):
        root = self.tree(passwd=PASSWD + "eve:x:1002:1002::/home/eve:/bin/bash\n",
                         shadow=SHADOW + "eve:$y$j9T$s$h:20600:0:90:7:::\n",
                         group=GROUP + "eve:x:1002:\n")
        alice = root / "home" / "alice"
        (alice / ".ssh").mkdir(parents=True)
        alice.chmod(0o777)
        (alice / ".ssh").chmod(0o755)
        keys = alice / ".ssh" / "authorized_keys"
        keys.write_text("ssh-ed25519 AAAA one\n# comment\nssh-rsa BBBB two\n")
        keys.chmod(0o666)
        (root / "home" / "eve").mkdir()
        (root / "home" / "eve" / ".rhosts").write_text("+ +\n")

        _, _, report = self.audit_json("--check-homes", root=root)
        by_user = {a["user"]: a for a in report["accounts"]}
        ids = self.ids(report)

        for expected in ("UA-060", "UA-061", "UA-063", "UA-064"):
            self.assertIn(expected, ids)

        self.assertEqual(by_user["alice"]["authorized_keys"], 2)

    def test_login_activity_uses_lastlog(self):
        binary = self.root / "bin"
        binary.mkdir()
        fake = binary / "lastlog"
        fake.write_text(
            "#!/bin/bash\ncat <<'L'\n"
            "Username         Port     From             Latest\n"
            "root                                       **Never logged in**\n"
            "alice            pts/0    10.0.0.5         Tue Oct 20 09:00:00 +0000 2026\n"
            "bob              pts/1    10.0.0.6         Mon Jan  5 10:00:00 +0000 2026\n"
            "L\n"
        )
        fake.chmod(0o755)

        _, _, report = self.audit_json("--check-activity", "--inactive-days", "90",
                                       root=self.tree(), path=binary)

        found = {(f["id"], f["subject"]) for f in report["findings"]}

        self.assertEqual(found, {("UA-070", "bob")})


class UsageTests(AuditorTestCase):
    def test_invalid_usage_gives_exit_code_2(self):
        cases = (
            ["--bogus"],
            ["--min-severity", "extreme"],
            ["--fail-on", "x"],
            ["--max-password-age", "abc"],
            ["--json"],
        )

        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(self.audit(*args)[0], 2)

        self.assertEqual(self.audit(root=self.root / "missing")[0], 2)

    def test_help_and_version(self):
        for option in ("--help", "--version"):
            with self.subTest(option=option):
                result = subprocess.run(
                    ["bash", str(SCRIPT), option], capture_output=True, text=True,
                )

                self.assertEqual(result.returncode, 0)
                self.assertTrue(result.stdout.strip())

    @unittest.skipIf(os.geteuid() == 0 if hasattr(os, "geteuid") else True,
                     "root can read every file")
    def test_unreadable_shadow_is_reported_and_the_audit_continues(self):
        root = self.tree()
        (root / "etc" / "shadow").chmod(0)

        code, output = self.audit(root=root)

        self.assertEqual(code, 0)
        self.assertIn("Cannot read /etc/shadow", output)


if __name__ == "__main__":
    unittest.main()