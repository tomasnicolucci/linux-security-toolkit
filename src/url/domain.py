import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, SplitResult

import idna
import tldextract


EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(frozen=True)
class URLInfo:
    original: str
    parsed: SplitResult
    hostname: str
    unicode_hostname: str
    registered_domain: str | None
    subdomain: str
    is_ip: bool
    ip_version: int | None
    port: int | None


def parse_url(url: str) -> URLInfo:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    if len(url) > 8192:
        raise ValueError("URL exceeds the maximum supported length.")

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("URL contains control characters.")

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must contain a valid hostname.")

        hostname = parsed.hostname.rstrip(".")
        port = parsed.port

        if not hostname:
            raise ValueError("Hostname cannot be empty.")

        if any(char.isspace() for char in hostname):
            raise ValueError("Hostname contains whitespace.")

        if "\\" in url:
            raise ValueError("URL contains backslashes.")

        ip_version = None
        is_ip = False

        try:
            ip = ipaddress.ip_address(hostname)
            is_ip = True
            ip_version = ip.version
            normalized_hostname = ip.compressed
            unicode_hostname = normalized_hostname

        except ValueError:
            if ":" in hostname:
                raise ValueError("Invalid IP address.")

            normalized_hostname = idna.encode(
                hostname,
                uts46=True,
                std3_rules=True,
            ).decode("ascii").lower()

            unicode_hostname = idna.decode(normalized_hostname)

            if len(normalized_hostname) > 253:
                raise ValueError("Hostname is too long.")

        registered_domain = None
        subdomain = ""

        if not is_ip:
            extracted = EXTRACTOR(normalized_hostname)

            if not extracted.suffix or not extracted.domain:
                raise ValueError("Hostname has no recognized public suffix.")

            registered_domain = (
                f"{extracted.domain}.{extracted.suffix}"
            )

            subdomain = extracted.subdomain

        return URLInfo(
            original=url,
            parsed=parsed,
            hostname=normalized_hostname,
            unicode_hostname=unicode_hostname,
            registered_domain=registered_domain,
            subdomain=subdomain,
            is_ip=is_ip,
            ip_version=ip_version,
            port=port,
        )

    except (ValueError, UnicodeError, idna.IDNAError) as error:
        raise ValueError(f"Invalid URL: {error}") from error
