import ipaddress

from src.ip.models import IPClassification


# Ordered from the most specific range to the least specific one.
# Anything not listed here is classified through ipaddress.is_global.
SPECIAL_RANGES = tuple(
    (ipaddress.ip_network(network), category, description)
    for network, category, description in (
        ("0.0.0.0/32", "unspecified", "Unspecified address"),
        ("255.255.255.255/32", "broadcast", "Limited broadcast address"),
        ("0.0.0.0/8", "reserved", "'This network' (RFC 1122)"),
        ("10.0.0.0/8", "private", "Private network (RFC 1918)"),
        ("172.16.0.0/12", "private", "Private network (RFC 1918)"),
        ("192.168.0.0/16", "private", "Private network (RFC 1918)"),
        (
            "100.64.0.0/10",
            "carrier_grade_nat",
            "Shared address space for carrier-grade NAT (RFC 6598)",
        ),
        ("127.0.0.0/8", "loopback", "Loopback (RFC 1122)"),
        ("169.254.0.0/16", "link_local", "Link-local (RFC 3927)"),
        (
            "192.0.0.0/24",
            "reserved",
            "IETF protocol assignments (RFC 6890)",
        ),
        (
            "192.0.2.0/24",
            "documentation",
            "Documentation range TEST-NET-1 (RFC 5737)",
        ),
        (
            "198.51.100.0/24",
            "documentation",
            "Documentation range TEST-NET-2 (RFC 5737)",
        ),
        (
            "203.0.113.0/24",
            "documentation",
            "Documentation range TEST-NET-3 (RFC 5737)",
        ),
        (
            "198.18.0.0/15",
            "benchmarking",
            "Network benchmarking (RFC 2544)",
        ),
        ("224.0.0.0/4", "multicast", "Multicast (RFC 5771)"),
        (
            "240.0.0.0/4",
            "reserved",
            "Reserved for future use (RFC 1112)",
        ),
        ("::/128", "unspecified", "Unspecified address"),
        ("::1/128", "loopback", "Loopback (RFC 4291)"),
        ("fe80::/10", "link_local", "Link-local (RFC 4291)"),
        ("fc00::/7", "private", "Unique local address (RFC 4193)"),
        ("ff00::/8", "multicast", "Multicast (RFC 4291)"),
        (
            "2001:db8::/32",
            "documentation",
            "Documentation range (RFC 3849)",
        ),
        ("100::/64", "reserved", "Discard-only prefix (RFC 6666)"),
    )
)


def parse_address(
    text: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    value = text.strip()

    if not value:
        raise ValueError("Empty IP address.")

    # Scope identifiers (fe80::1%eth0) depend on the local interface
    # and are not part of the address itself.
    value = value.split("%", 1)[0]

    try:
        return ipaddress.ip_address(value)
    except ValueError as error:
        shown = repr(text.strip()[:60])

        raise ValueError(
            f"Invalid IP address: {shown}"
        ) from error


def unwrap_mapped(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[
    ipaddress.IPv4Address | ipaddress.IPv6Address,
    bool,
]:
    if (
        isinstance(address, ipaddress.IPv6Address)
        and address.ipv4_mapped is not None
    ):
        return address.ipv4_mapped, True

    return address, False


def canonical_address(text: str) -> str | None:
    """Normalized form used to detect duplicates; None if invalid."""
    try:
        address, _ = unwrap_mapped(parse_address(text))
    except ValueError:
        return None

    return str(address)


def classify(text: str) -> IPClassification:
    original = parse_address(text)
    address, was_mapped = unwrap_mapped(original)

    notes = []

    if was_mapped:
        shown = text.strip().split("%", 1)[0]

        notes.append(
            f"IPv4-mapped IPv6 address ({shown}); "
            f"analyzed as {address}."
        )

    category = None
    description = None

    for network, special_category, special_description in (
        SPECIAL_RANGES
    ):
        if address in network:
            category = special_category
            description = special_description
            break

    if category is None:
        if address.is_global:
            category = "global"
            description = "Publicly routable address"
        else:
            category = "reserved"
            description = (
                "Not globally routable (special-purpose range)"
            )

    return IPClassification(
        address=str(address),
        version=address.version,
        category=category,
        description=description,
        is_global=category == "global",
        reverse_pointer=address.reverse_pointer,
        notes=tuple(notes),
    )