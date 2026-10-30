import http.server
import json
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from src.ip import lookup
from src.ip.analyzer import analyze_address, analyze_addresses
from src.ip.classifier import canonical_address, classify, parse_address
from src.ip.lookup import RdapError, lookup_rdap, parse_rdap, reverse_dns
from src.ip.models import AddressEntry
from src.ip.sources import (
    build_entries,
    read_address_file,
    read_report_entries,
)
from src.ip.text import clean_text
from tests.helpers import run_cli


class ClassifierTests(unittest.TestCase):
    def test_categories(self):
        expected = {
            "8.8.8.8": ("global", True),
            "10.1.2.3": ("private", False),
            "172.16.0.1": ("private", False),
            "192.168.1.1": ("private", False),
            "127.0.0.1": ("loopback", False),
            "169.254.1.1": ("link_local", False),
            "100.64.0.5": ("carrier_grade_nat", False),
            "203.0.113.25": ("documentation", False),
            "198.18.0.1": ("benchmarking", False),
            "224.0.0.1": ("multicast", False),
            "0.0.0.0": ("unspecified", False),
            "255.255.255.255": ("broadcast", False),
            "240.0.0.1": ("reserved", False),
            "::1": ("loopback", False),
            "fe80::1": ("link_local", False),
            "fc00::1": ("private", False),
            "2001:db8::1": ("documentation", False),
            "ff02::1": ("multicast", False),
            "2606:4700:4700::1111": ("global", True),
        }

        for address, (category, is_global) in expected.items():
            with self.subTest(address=address):
                result = classify(address)

                self.assertEqual(result.category, category)
                self.assertEqual(result.is_global, is_global)

    def test_versions_and_reverse_pointer(self):
        self.assertEqual(classify("1.2.3.4").version, 4)
        self.assertEqual(classify("1.2.3.4").reverse_pointer, "4.3.2.1.in-addr.arpa")
        self.assertEqual(classify("2001:db8::1").version, 6)

    def test_ipv4_mapped_addresses_are_unwrapped(self):
        result = classify("::ffff:8.8.4.4")

        self.assertEqual(result.address, "8.8.4.4")
        self.assertEqual(result.version, 4)
        self.assertTrue(result.is_global)
        self.assertTrue(result.notes)

    def test_scope_identifier_is_ignored(self):
        self.assertEqual(classify("fe80::1%eth0").category, "link_local")

    def test_invalid_addresses(self):
        for value in ("999.1.1.1", "abc", "", "  ", "1.2.3", "1.2.3.4/24"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    classify(value)

    def test_canonical_form_is_used_to_find_duplicates(self):
        self.assertEqual(canonical_address("::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(canonical_address("2001:0db8:0:0:0:0:0:1"), "2001:db8::1")
        self.assertIsNone(canonical_address("nope"))
        self.assertEqual(str(parse_address(" 10.0.0.1 ")), "10.0.0.1")


class TextTests(unittest.TestCase):
    def test_control_characters_are_removed(self):
        self.assertEqual(clean_text("a\x1b[31mred\x00\n b"), "a [31mred b")

    def test_limits_and_types(self):
        self.assertEqual(len(clean_text("x" * 500)), 200)
        self.assertIsNone(clean_text(5))
        self.assertIsNone(clean_text("   \t"))


class SourceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_address_file_ignores_comments_and_blank_lines(self):
        path = self.root / "ips.txt"
        path.write_text("# header\n8.8.8.8   # google\n\n10.0.0.5\n")

        self.assertEqual(read_address_file(str(path)), ["8.8.8.8", "10.0.0.5"])

    def test_address_file_errors(self):
        with self.assertRaises(ValueError):
            read_address_file(str(self.root / "missing.txt"))

    def test_standard_input(self):
        with mock.patch("src.ip.sources.sys.stdin") as stdin:
            stdin.read.return_value = "1.1.1.1\n2.2.2.2\n"

            self.assertEqual(read_address_file("-"), ["1.1.1.1", "2.2.2.2"])

    def report(self, findings):
        path = self.root / "report.json"
        path.write_text(json.dumps({"findings": findings}))
        return path

    def test_report_entries_are_ordered_by_severity(self):
        entries = read_report_entries(self.report([
            {"rule_id": "brute_force", "severity": "MEDIUM", "source_ip": "198.51.100.7"},
            {"rule_id": "spraying", "severity": "MEDIUM", "source_ip": "198.51.100.7"},
            {"rule_id": "new_source_ip", "severity": "LOW", "source_ip": "10.0.0.5"},
            {
                "rule_id": "distributed_attack",
                "severity": "HIGH",
                "source_ip": None,
                "metadata": {"source_ips": ["192.0.2.1", "192.0.2.2"]},
            },
        ]))

        self.assertEqual(
            [entry.raw for entry in entries],
            ["192.0.2.1", "192.0.2.2", "198.51.100.7", "10.0.0.5"],
        )
        top = entries[2].context

        self.assertEqual((top.findings, top.max_severity), (2, "MEDIUM"))
        self.assertEqual(top.rules, ("brute_force", "spraying"))

    def test_invalid_reports(self):
        path = self.root / "bad.json"
        path.write_text(json.dumps({"events": []}))

        with self.assertRaises(ValueError):
            read_report_entries(path)

        with self.assertRaises(ValueError):
            read_report_entries(self.root / "missing.json")

    def test_entries_are_merged_and_limited(self):
        report = [AddressEntry("1.1.1.1", ["report"])]

        entries, warnings = build_entries(
            ["1.1.1.1", "::ffff:2.2.2.2"],
            ["2.2.2.2", "3.3.3.3"],
            report,
            limit=3,
        )

        self.assertEqual([entry.raw for entry in entries], ["1.1.1.1", "::ffff:2.2.2.2", "3.3.3.3"])
        self.assertEqual(entries[0].sources, ["argument", "report"])
        self.assertEqual(warnings, [])

        _, warnings = build_entries(["1.1.1.1", "2.2.2.2", "3.3.3.3"], [], [], limit=2)

        self.assertIn("1 additional", warnings[0])


ARIN_RESPONSE = {
    "name": "GOGL",
    "handle": "NET-8-8-8-0-2",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "entities": [{
        "roles": ["registrant"],
        "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
        "entities": [{
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["email", {}, "text", "network-abuse@google.com"]]],
        }],
    }],
}

RIPE_RESPONSE = {
    "name": "EXAMPLE\x1b[31m-NET",
    "startAddress": "193.0.0.0",
    "endAddress": "193.0.7.255",
    "country": "NL",
    "entities": [{
        "roles": ["abuse"],
        "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]],
    }],
}


class RdapParsingTests(unittest.TestCase):
    def test_nested_entities_and_cidr(self):
        info = parse_rdap(ARIN_RESPONSE)

        self.assertEqual(info.network_name, "GOGL")
        self.assertEqual(info.cidrs, ("8.8.8.0/24",))
        self.assertEqual(info.ip_range, "8.8.8.0 - 8.8.8.255")
        self.assertEqual(info.organization, "Google LLC")
        self.assertEqual(info.abuse_contact, "network-abuse@google.com")

    def test_cidr_is_computed_from_the_range_and_text_is_sanitized(self):
        info = parse_rdap(RIPE_RESPONSE)

        self.assertEqual(info.country, "NL")
        self.assertEqual(info.cidrs[0], "193.0.0.0/21")
        self.assertNotIn("\x1b", info.network_name)

    def test_unusable_or_hostile_data(self):
        for data in (
            {},
            {"name": 5},
            {"entities": "x", "cidr0_cidrs": [1, {"v4prefix": "x"}]},
        ):
            with self.subTest(data=data):
                with self.assertRaises(RdapError):
                    parse_rdap(data)

        info = parse_rdap({
            "name": "ok",
            "startAddress": "1.1.1.1",
            "endAddress": "garbage",
            "entities": [None, {"roles": None}, {"roles": ["abuse"], "vcardArray": "x"}],
        })

        self.assertEqual(info.network_name, "ok")
        self.assertIsNone(info.abuse_contact)

    def test_lookup_uses_the_expected_url(self):
        calls = []

        def fetch(url, timeout):
            calls.append((url, timeout))
            return ARIN_RESPONSE

        info = lookup_rdap("8.8.8.8", 4, fetch=fetch)

        self.assertEqual(calls, [("https://rdap.org/ip/8.8.8.8", 4)])
        self.assertEqual(info.handle, "NET-8-8-8-0-2")


class ReverseDnsTests(unittest.TestCase):
    def test_hostname_is_returned_and_sanitized(self):
        with mock.patch("socket.gethostbyaddr", return_value=("host\x1b[2J.example.com", [], [])):
            hostname, message = reverse_dns("1.2.3.4", 2)

        self.assertEqual(hostname, "host [2J.example.com")
        self.assertIsNone(message)

    def test_missing_record(self):
        import socket

        with mock.patch("socket.gethostbyaddr", side_effect=socket.herror(1, "x")):
            self.assertEqual(reverse_dns("1.2.3.4", 2), (None, "No PTR record found."))

    def test_other_errors_do_not_raise(self):
        with mock.patch("socket.gethostbyaddr", side_effect=OSError("network down")):
            hostname, message = reverse_dns("1.2.3.4", 2)

        self.assertIsNone(hostname)
        self.assertIn("network down", message)

    def test_slow_lookups_time_out(self):
        with mock.patch("socket.gethostbyaddr", side_effect=lambda a: (time.sleep(2), ("late", [], []))[1]):
            started = time.time()
            hostname, message = reverse_dns("1.2.3.4", 0.3)

        self.assertLess(time.time() - started, 2)
        self.assertIsNone(hostname)
        self.assertIn("timed out", message)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.com/x")
            self.end_headers()
            return

        body = {
            "/big": b"x" * (lookup.MAX_RESPONSE_BYTES + 10),
            "/text": b"not json",
            "/list": b"[1, 2]",
            "/ok": b'{"name": "fine"}',
        }.get(self.path, b"{}")

        self.send_response(404 if self.path == "/missing" else 200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def fetch(self, path):
        return lookup.fetch_json(self.base + path, 3)

    def test_valid_response(self):
        self.assertEqual(self.fetch("/ok"), {"name": "fine"})

    def test_rejected_responses(self):
        for path, text in (
            ("/big", "too large"),
            ("/text", "not valid JSON"),
            ("/list", "Unexpected"),
            ("/missing", "HTTP 404"),
            ("/redirect", "HTTP 302"),
        ):
            with self.subTest(path=path):
                with self.assertRaises(RdapError) as context:
                    self.fetch(path)

                self.assertIn(text, str(context.exception))

    def test_connection_failure(self):
        with self.assertRaises(RdapError):
            lookup.fetch_json("http://127.0.0.1:9/", 1)


class AnalyzerTests(unittest.TestCase):
    def analyze(self, address, **kwargs):
        options = {"known_ips": None, "resolve": False, "rdap": False, "timeout": 2}
        options.update(kwargs)

        return analyze_address(AddressEntry(address, ["argument"]), **options)

    def test_invalid_address(self):
        result = self.analyze("nope")

        self.assertIsNone(result.classification)
        self.assertIn("Invalid", result.error)

    def test_approval_status(self):
        self.assertIsNone(self.analyze("8.8.8.8").approved)
        self.assertTrue(self.analyze("8.8.8.8", known_ips={"8.8.8.8"}).approved)
        self.assertFalse(self.analyze("8.8.8.8", known_ips={"1.1.1.1"}).approved)

    def test_lookups_are_skipped_when_they_do_not_apply(self):
        private = self.analyze("10.0.0.1", rdap=True)
        multicast = self.analyze("224.0.0.1", resolve=True)

        self.assertIn("Skipped", private.lookup_messages["rdap"])
        self.assertIsNone(private.rdap)
        self.assertIn("Skipped", multicast.lookup_messages["dns"])

    def test_network_lookups_are_used_for_global_addresses(self):
        with mock.patch("src.ip.analyzer.reverse_dns", return_value=("dns.google", None)), \
                mock.patch("src.ip.analyzer.lookup_rdap", return_value="info"):
            result = self.analyze("8.8.8.8", resolve=True, rdap=True)

        self.assertEqual(result.hostname, "dns.google")
        self.assertEqual(result.rdap, "info")

    def test_lookup_failures_do_not_stop_the_analysis(self):
        with mock.patch("src.ip.analyzer.lookup_rdap", side_effect=RdapError("boom")):
            result = self.analyze("8.8.8.8", rdap=True)

        self.assertEqual(result.lookup_messages["rdap"], "boom")
        self.assertEqual(result.classification.category, "global")

    def test_order_is_preserved_with_concurrent_lookups(self):
        entries = [AddressEntry(f"8.8.8.{i}", ["argument"]) for i in range(1, 9)]

        with mock.patch("src.ip.analyzer.reverse_dns", return_value=(None, "none")):
            results = analyze_addresses(entries, None, True, False, 2)

        self.assertEqual([r.input for r in results], [e.raw for e in entries])


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_offline_analysis(self):
        code, output = run_cli("ip", "analyze", "8.8.8.8", "10.0.0.5", "::ffff:1.2.3.4")

        self.assertEqual(code, 0, output)
        self.assertIn("8.8.8.8 | IPv4 | global", output)
        self.assertIn("10.0.0.5 | IPv4 | private", output)
        self.assertIn("1.2.3.4 | IPv4 | global", output)

    def test_invalid_input_gives_exit_code_2(self):
        code, output = run_cli("ip", "analyze", "999.1.1.1")

        self.assertEqual(code, 2)
        self.assertIn("[INVALID]", output)

    def test_usage_errors(self):
        self.assertEqual(run_cli("ip", "analyze")[0], 2)
        self.assertEqual(run_cli("ip", "analyze", "1.1.1.1", "--timeout", "0")[0], 2)
        self.assertEqual(run_cli("ip", "analyze", "1.1.1.1", "--limit", "0")[0], 2)

    def test_standard_input_and_json_export(self):
        target = self.root / "out.json"

        code, _ = run_cli(
            "ip", "analyze", "--file", "-", "--json", target,
            input_text="1.1.1.1\n192.168.0.1\n",
        )
        data = json.loads(target.read_text())

        self.assertEqual(code, 0)
        self.assertEqual(data["summary"]["total"], 2)
        self.assertEqual(data["summary"]["global"], 1)

    def test_report_from_the_log_analyzer(self):
        report = self.root / "report.json"
        report.write_text(json.dumps({"findings": [
            {"rule_id": "brute_force", "severity": "HIGH", "source_ip": "198.51.100.7"},
        ]}))

        code, output = run_cli("ip", "analyze", "--from-report", report)

        self.assertEqual(code, 0, output)
        self.assertIn("max severity: HIGH", output)


if __name__ == "__main__":
    unittest.main()
