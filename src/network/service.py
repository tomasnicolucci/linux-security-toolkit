import ipaddress
from collections import Counter
from dataclasses import dataclass

from src.network.models import Snapshot, SocketInfo


@dataclass
class Selection:
    listeners: list[SocketInfo]
    connections: list[SocketInfo]


def is_connection(item: SocketInfo) -> bool:
    """Sockets that represent traffic with another host."""
    if item.listening or item.state == "TIME_WAIT":
        return False

    # Unconnected UDP sockets are not connections.
    return not (item.proto == "udp" and item.state == "UNCONN")


def matches(
    item: SocketInfo,
    proto: str | None,
    port: int | None,
    pid: int | None,
) -> bool:
    if proto and item.proto != proto:
        return False

    if port is not None and port not in (item.local_port, item.remote_port):
        return False

    if pid is not None and pid not in item.pids:
        return False

    return True


def select_sockets(
    snapshot: Snapshot,
    listening_only: bool,
    established_only: bool,
    proto: str | None,
    port: int | None,
    pid: int | None,
) -> Selection:
    listeners = []
    connections = []

    if not established_only:
        listeners = [
            item for item in snapshot.listeners
            if matches(item, proto, port, pid)
        ]

    if not listening_only:
        connections = [
            item for item in snapshot.sockets
            if is_connection(item)
            and matches(item, proto, port, pid)
            and (not established_only or item.state == "ESTABLISHED")
        ]

    listeners.sort(key=lambda item: (item.local_port, item.proto, item.local_ip))
    connections.sort(
        key=lambda item: (item.state, item.local_port, item.remote_ip)
    )

    return Selection(listeners, connections)


def public_remote_ips(sockets: list[SocketInfo]) -> list[str]:
    """Unique public remote addresses, ready for the IP analyzer."""
    found = set()

    for item in sockets:
        if not is_connection(item):
            continue

        try:
            address = ipaddress.ip_address(item.remote_ip)
        except ValueError:
            continue

        if address.is_global:
            found.add(address)

    ordered = sorted(found, key=lambda address: (address.version, address))

    return [str(address) for address in ordered]


def state_counts(snapshot: Snapshot) -> dict[str, int]:
    counts = Counter(
        item.state
        for item in snapshot.sockets
        if item.proto == "tcp"
    )

    return dict(sorted(counts.items(), key=lambda pair: (-pair[1], pair[0])))