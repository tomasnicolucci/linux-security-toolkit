import http.client
import ipaddress
import json
import socket
import threading
import urllib.error
import urllib.request
from typing import Callable, Iterator

from src.ip.models import RdapInfo
from src.ip.text import clean_text


# Public RDAP bootstrap service. It redirects each query to the
# Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
# responsible for the address.
RDAP_BASE_URL = "https://rdap.org/ip/"

MAX_RESPONSE_BYTES = 1_000_000
MAX_ENTITY_DEPTH = 5
MAX_CIDRS = 8


class RdapError(Exception):
    pass


def reverse_dns(
    address: str,
    timeout: float,
) -> tuple[str | None, str | None]:
    """
    Resolve the PTR record of an address.

    Returns (hostname, message). socket.gethostbyaddr has no timeout
    parameter, so the lookup runs in a daemon thread that is abandoned
    if it takes too long.
    """
    outcome: dict[str, object] = {}

    def worker() -> None:
        try:
            outcome["hostname"] = socket.gethostbyaddr(address)[0]
        except socket.herror:
            outcome["message"] = "No PTR record found."
        except OSError as error:
            outcome["message"] = f"DNS lookup failed: {error}"

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        return None, f"DNS lookup timed out after {timeout:g}s."

    hostname = clean_text(outcome.get("hostname"))

    if hostname is None and "message" not in outcome:
        return None, "No PTR record found."

    return hostname, outcome.get("message")


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(
                newurl,
                code,
                "Redirect to a non-HTTPS URL was blocked",
                headers,
                fp,
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


def fetch_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "linux-security-toolkit",
        },
    )

    opener = urllib.request.build_opener(HttpsOnlyRedirectHandler)

    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise RdapError(
            f"RDAP server returned HTTP {error.code}."
        ) from error
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        OSError,
    ) as error:
        reason = getattr(error, "reason", error)

        raise RdapError(f"RDAP request failed: {reason}") from error

    if len(body) > MAX_RESPONSE_BYTES:
        raise RdapError("RDAP response is too large.")

    try:
        data = json.loads(body)
    except ValueError as error:
        raise RdapError("RDAP response is not valid JSON.") from error

    if not isinstance(data, dict):
        raise RdapError("Unexpected RDAP response format.")

    return data


def iter_entities(
    entities: object,
    depth: int = 0,
) -> Iterator[dict]:
    if depth > MAX_ENTITY_DEPTH or not isinstance(entities, list):
        return

    for entity in entities:
        if isinstance(entity, dict):
            yield entity
            yield from iter_entities(
                entity.get("entities"),
                depth + 1,
            )


def vcard_value(entity: dict, field_name: str) -> str | None:
    vcard = entity.get("vcardArray")

    if not (
        isinstance(vcard, list)
        and len(vcard) == 2
        and isinstance(vcard[1], list)
    ):
        return None

    for item in vcard[1]:
        if (
            isinstance(item, list)
            and len(item) >= 4
            and item[0] == field_name
        ):
            value = clean_text(item[3])

            if value:
                return value

    return None


def find_contact(
    data: dict,
    role: str,
    fields: tuple[str, ...],
) -> str | None:
    for entity in iter_entities(data.get("entities")):
        roles = entity.get("roles")

        if not isinstance(roles, list) or role not in roles:
            continue

        for field_name in fields:
            value = vcard_value(entity, field_name)

            if value:
                return value

    return None


def parse_ip(value: object):
    if not isinstance(value, str):
        return None

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def extract_cidrs(data: dict) -> tuple[str, ...]:
    cidrs = []

    declared = data.get("cidr0_cidrs")

    if isinstance(declared, list):
        for item in declared:
            if not isinstance(item, dict):
                continue

            prefix = item.get("v4prefix") or item.get("v6prefix")
            length = item.get("length")

            try:
                network = ipaddress.ip_network(
                    f"{prefix}/{length}",
                    strict=False,
                )
            except ValueError:
                continue

            cidrs.append(str(network))

    if cidrs:
        return tuple(cidrs[:MAX_CIDRS])

    start = parse_ip(data.get("startAddress"))
    end = parse_ip(data.get("endAddress"))

    if start is None or end is None or start.version != end.version:
        return ()

    try:
        networks = ipaddress.summarize_address_range(start, end)

        return tuple(str(network) for network in networks)[:MAX_CIDRS]
    except ValueError:
        return ()


def parse_rdap(data: dict) -> RdapInfo:
    start = parse_ip(data.get("startAddress"))
    end = parse_ip(data.get("endAddress"))

    ip_range = f"{start} - {end}" if start and end else None

    info = RdapInfo(
        network_name=clean_text(data.get("name")),
        handle=clean_text(data.get("handle")),
        ip_range=ip_range,
        cidrs=extract_cidrs(data),
        country=clean_text(data.get("country"), 10),
        organization=find_contact(
            data,
            "registrant",
            ("fn", "org"),
        ),
        abuse_contact=find_contact(
            data,
            "abuse",
            ("email",),
        ),
    )

    if info == RdapInfo():
        raise RdapError("RDAP response contained no usable data.")

    return info


def lookup_rdap(
    address: str,
    timeout: float,
    fetch: Callable[[str, float], dict] = fetch_json,
) -> RdapInfo:
    # The address was validated by ipaddress, so it is safe to place
    # it in the URL path.
    return parse_rdap(fetch(f"{RDAP_BASE_URL}{address}", timeout))