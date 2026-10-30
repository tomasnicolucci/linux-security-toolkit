import unittest
from types import SimpleNamespace
from unittest import mock

from src.url.analyzer import analyze_url
from src.url.domain import parse_url
from src.url.rules import analyze_rules
from tests.helpers import real_tldextract_available

TWO_LEVEL_SUFFIXES = {"co.uk"}


def fake_extractor(hostname):
    """Small stand-in for tldextract, so tests do not depend on it."""
    labels = hostname.split(".")

    if len(labels) < 2:
        return SimpleNamespace(subdomain="", domain=labels[0], suffix="")

    suffix_length = 2 if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES else 1

    if len(labels) <= suffix_length:
        return SimpleNamespace(subdomain="", domain="", suffix=hostname)

    return SimpleNamespace(
        subdomain=".".join(labels[: -suffix_length - 1]),
        domain=labels[-suffix_length - 1],
        suffix=".".join(labels[-suffix_length:]),
    )


class UrlTestCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("src.url.domain.EXTRACTOR", fake_extractor)
        patcher.start()
        self.addCleanup(patcher.stop)

    def codes(self, url):
        return {finding.code for finding in analyze_rules(parse_url(url))}


class ParseUrlTests(UrlTestCase):
    def test_parses_a_normal_url(self):
        info = parse_url("https://www.Example.com/path?q=1")

        self.assertEqual(info.hostname, "www.example.com")
        self.assertEqual(info.registered_domain, "example.com")
        self.assertEqual(info.subdomain, "www")
        self.assertFalse(info.is_ip)
        self.assertIsNone(info.port)

    def test_handles_trailing_dot_and_port(self):
        info = parse_url("http://example.com.:8080/")

        self.assertEqual(info.hostname, "example.com")
        self.assertEqual(info.port, 8080)

    def test_parses_ip_addresses(self):
        v4 = parse_url("http://192.168.0.1/")
        v6 = parse_url("http://[2001:db8::1]:8080/")

        self.assertTrue(v4.is_ip)
        self.assertEqual(v4.ip_version, 4)
        self.assertIsNone(v4.registered_domain)
        self.assertEqual(v6.ip_version, 6)
        self.assertEqual(v6.hostname, "2001:db8::1")

    def test_converts_internationalized_names(self):
        info = parse_url("https://bücher.example/")

        self.assertEqual(info.hostname, "xn--bcher-kva.example")
        self.assertEqual(info.unicode_hostname, "bücher.example")

    def test_rejects_invalid_urls(self):
        invalid = {
            "empty": "",
            "spaces": "   ",
            "scheme": "ftp://example.com/",
            "no scheme": "example.com",
            "no host": "http:///path",
            "control characters": "http://exa\x00mple.com/",
            "backslash": "http://example.com\\@evil.example/",
            "underscore": "http://under_score.example/",
            "no public suffix": "http://localhost/",
            "too long": "http://example.com/" + "a" * 9000,
            "bad ipv6": "http://[::zz]/",
        }

        for name, url in invalid.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    parse_url(url)

    def test_rejects_non_strings(self):
        with self.assertRaises(ValueError):
            parse_url(None)


class RuleTests(UrlTestCase):
    def test_clean_url_has_no_findings(self):
        self.assertEqual(self.codes("https://example.com/"), set())

    def test_insecure_scheme(self):
        self.assertIn("INSECURE_SCHEME", self.codes("http://example.com/"))

    def test_ip_host_and_private_address(self):
        codes = self.codes("https://192.168.1.10/")

        self.assertIn("IP_HOST", codes)
        self.assertIn("NON_PUBLIC_IP", codes)
        self.assertNotIn("NON_PUBLIC_IP", self.codes("https://8.8.8.8/"))

    def test_user_information(self):
        self.assertIn("USERINFO", self.codes("https://paypal.com@evil.example/"))

    def test_unusual_port(self):
        self.assertIn("UNUSUAL_PORT", self.codes("https://example.com:8443/"))
        self.assertNotIn("UNUSUAL_PORT", self.codes("https://example.com:443/"))

    def test_excessive_subdomains(self):
        self.assertIn(
            "EXCESSIVE_SUBDOMAINS",
            self.codes("https://a.b.c.d.example.com/"),
        )

    def test_long_url(self):
        self.assertIn(
            "LONG_URL",
            self.codes("https://example.com/" + "a" * 250),
        )

    def test_shortener(self):
        self.assertIn("URL_SHORTENER", self.codes("https://bit.ly/abc"))

    def test_punycode_and_mixed_scripts(self):
        codes = self.codes("https://pаypal.com/")  # Cyrillic "а"

        self.assertIn("PUNYCODE", codes)
        self.assertIn("MIXED_SCRIPT", codes)

    def test_single_script_internationalized_names_are_not_mixed(self):
        for url in (
            "https://пример.com/",      # Cyrillic label, Latin suffix
            "https://bücher.example/",  # Latin with accents
            "https://αβγ.example/",     # Greek label
        ):
            with self.subTest(url=url):
                self.assertNotIn("MIXED_SCRIPT", self.codes(url))

    def test_cyrillic_and_latin_in_one_label_are_mixed(self):
        self.assertIn("MIXED_SCRIPT", self.codes("https://paypаl.com/"))
        self.assertIn("MIXED_SCRIPT", self.codes("https://gοogle.com/"))  # Greek "ο"

    def test_brand_impersonation(self):
        self.assertIn(
            "BRAND_IMPERSONATION",
            self.codes("https://paypal-login.evil.example/"),
        )

    def test_official_brand_domain_is_not_flagged(self):
        self.assertNotIn(
            "BRAND_IMPERSONATION",
            self.codes("https://www.paypal.com/"),
        )

    def test_authentication_path(self):
        self.assertIn("AUTH_PATH", self.codes("https://example.com/user/login"))

    def test_encoded_characters(self):
        self.assertIn(
            "ENCODED_CHARACTERS",
            self.codes("https://example.com/a%2fb"),
        )

    def test_redirect_parameter(self):
        self.assertIn(
            "REDIRECT_PARAMETER",
            self.codes("https://example.com/?next=http://x.example"),
        )


class AnalyzerTests(UrlTestCase):
    def test_clean_url_is_low_risk(self):
        result = analyze_url("https://example.com/")

        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.risk_level, "LOW")
        self.assertEqual(result.registered_domain, "example.com")

    def test_score_adds_severity_weights(self):
        # IP host (15) + insecure scheme (5) + private IP (5)
        # + authentication path (5) + redirect parameter (15)
        result = analyze_url("http://192.168.1.1/login?next=x")

        self.assertEqual(result.risk_score, 45)
        self.assertEqual(result.risk_level, "HIGH")

    def test_risk_levels_by_score(self):
        cases = {
            "https://example.com/": "LOW",
            "https://example.com/?next=x": "MEDIUM",
            "https://paypal.com@evil.example/": "HIGH",
        }

        for url, level in cases.items():
            with self.subTest(url=url):
                self.assertEqual(analyze_url(url).risk_level, level)

    def test_score_is_capped_at_100(self):
        url = (
            "http://paypal-login.a.b.c.d.evil.example:81/login"
            "?next=x&url=y%2f"
        )

        result = analyze_url(url)

        self.assertLessEqual(result.risk_score, 100)
        self.assertIn(result.risk_level, ("HIGH", "CRITICAL"))


@unittest.skipUnless(
    real_tldextract_available(),
    "The tldextract library is not available.",
)
class RealLibraryTests(unittest.TestCase):
    def test_public_suffix_list_is_used(self):
        info = parse_url("https://www.example.co.uk/")

        self.assertEqual(info.registered_domain, "example.co.uk")
        self.assertEqual(info.subdomain, "www")

    def test_hostname_without_public_suffix_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_url("http://intranet/")


if __name__ == "__main__":
    unittest.main()
