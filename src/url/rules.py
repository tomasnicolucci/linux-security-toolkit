import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote

from src.url.domain import URLInfo


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    recommendation: str


BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
}

AUTH_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "authenticate",
}

REDIRECT_KEYS = {
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "returnurl",
    "return_url",
    "next",
    "url",
    "target",
    "destination",
    "continue",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
}


def analyze_rules(info: URLInfo) -> list[Finding]:
    findings = []

    def add(code, severity, message, recommendation):
        findings.append(
            Finding(code, severity, message, recommendation)
        )

    parsed = info.parsed
    hostname = info.hostname
    domain = info.registered_domain
    path = parsed.path.lower()
    query = parsed.query

    if parsed.scheme.lower() == "http":
        add(
            "INSECURE_SCHEME",
            "LOW",
            "URL uses HTTP instead of HTTPS.",
            "Avoid entering sensitive information over HTTP.",
        )

    if info.is_ip:
        add(
            "IP_HOST",
            "MEDIUM",
            f"URL uses an IPv{info.ip_version} address as hostname.",
            "Verify the destination before accessing it.",
        )

        ip = ipaddress.ip_address(hostname)

        if not ip.is_global:
            add(
                "NON_PUBLIC_IP",
                "LOW",
                "Destination IP is not globally reachable.",
                "Verify that this is an intended internal address.",
            )

    if parsed.username is not None or parsed.password is not None:
        add(
            "USERINFO",
            "HIGH",
            "URL contains user information before the @ symbol.",
            "Check the actual hostname after the @ symbol.",
        )

    if info.port is not None and info.port not in (80, 443):
        add(
            "UNUSUAL_PORT",
            "LOW",
            f"URL uses a nonstandard port: {info.port}.",
            "Confirm that the destination port is expected.",
        )

    if info.subdomain.count(".") >= 3:
        add(
            "EXCESSIVE_SUBDOMAINS",
            "MEDIUM",
            "URL contains an unusually deep subdomain structure.",
            "Verify the registered domain.",
        )

    if len(info.original) > 200:
        add(
            "LONG_URL",
            "LOW",
            "URL is unusually long.",
            "Inspect the destination and query parameters.",
        )

    if domain in SHORTENERS:
        add(
            "URL_SHORTENER",
            "MEDIUM",
            "URL uses a known shortening service.",
            "Verify the destination before following the link.",
        )

    if not info.is_ip and "xn--" in hostname:
        add(
            "PUNYCODE",
            "MEDIUM",
            "Hostname contains an internationalized domain label.",
            "Verify the displayed domain carefully.",
        )

    if not info.is_ip:
        scripts = set()

        for char in info.unicode_hostname:
            if not char.isalpha() or ord(char) < 128:
                continue

            name = unicodedata.name(char, "")

            for script in ("LATIN", "CYRILLIC", "GREEK"):
                if script in name:
                    scripts.add(script)

        if len(scripts) > 1:
            add(
                "MIXED_SCRIPT",
                "HIGH",
                "Hostname mixes characters from different scripts.",
                "Check for visually deceptive domain characters.",
            )

    if domain:
        for brand, official_domains in BRANDS.items():
            if domain in official_domains:
                continue

            labels = re.split(r"[.\-_]", hostname)

            if brand in labels:
                add(
                    "BRAND_IMPERSONATION",
                    "HIGH",
                    f"Hostname references {brand} outside its official domain.",
                    "Verify the actual registered domain.",
                )
                break

    decoded_path = unquote(path)

    path_words = set(
        re.split(r"[^a-z0-9]+", decoded_path)
    )

    if path_words.intersection(AUTH_WORDS):
        add(
            "AUTH_PATH",
            "LOW",
            "URL contains authentication-related path terms.",
            "Confirm that the login page belongs to the expected site.",
        )

    if re.search(r"%(?:25)?(?:2f|5c|40|00)", info.original, re.I):
        add(
            "ENCODED_CHARACTERS",
            "MEDIUM",
            "URL contains potentially deceptive encoded characters.",
            "Inspect the decoded URL carefully.",
        )

    for key, value in parse_qsl(query, keep_blank_values=True):
        if key.lower() in REDIRECT_KEYS:
            add(
                "REDIRECT_PARAMETER",
                "MEDIUM",
                f"URL contains a possible redirect parameter: {key}.",
                "Verify where the redirect may lead.",
            )
            break

    return findings
