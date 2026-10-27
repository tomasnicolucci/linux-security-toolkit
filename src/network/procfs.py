import ipaddress
import os
import pwd
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.network.models import (
    NetworkError,
    ProcessInfo,
    Snapshot,
    SocketInfo,
)

DEFAULT_PROC_ROOT = Path("/proc")

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

UDP_STATES = {
    "01": "ESTABLISHED",
    "07": "UNCONN",
}

TABLES = (
    ("net/tcp", "tcp", 4),
    ("net/tcp6", "tcp", 6),
    ("net/udp", "udp", 4),
    ("net/udp6", "udp", 6),
)

DEFAULT_EPHEMERAL_LOW = 32768
MAX_CMDLINE_BYTES = 4096
MAX_TEXT = 120


def printable(value: str, limit: int = MAX_TEXT) -> str:
    """Make text from other processes safe to print in a terminal."""
    text = "".join(
        character if character.isprintable() else "?"
        for character in value
    )

    return text[:limit]


def decode_address(value: str, family: int) -> tuple[str, int]:
    """
    Decode "HEXADDR:HEXPORT" as printed by the kernel. Addresses are
    printed as 32-bit words in the byte order of the machine.
    """
    host_hex, port_hex = value.split(":")

    if family == 4:
        address = ipaddress.IPv4Address(
            struct.pack("=I", int(host_hex, 16))
        )
    else:
        words = [int(host_hex[i:i + 8], 16) for i in range(0, 32, 8)]
        address = ipaddress.IPv6Address(struct.pack("=4I", *words))

        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped

    return str(address), int(port_hex, 16)


def bind_scope(ip: str) -> str:
    address = ipaddress.ip_address(ip)

    if address.is_unspecified:
        return "all"

    if address.is_loopback:
        return "loopback"

    return "specific"


def read_table(
    path: Path,
    proto: str,
    family: int,
) -> list[SocketInfo]:
    states = TCP_STATES if proto == "tcp" else UDP_STATES
    sockets = []

    with path.open("r", encoding="ascii", errors="replace") as stream:
        next(stream, None)

        for line in stream:
            fields = line.split()

            if len(fields) < 10:
                continue

            try:
                local_ip, local_port = decode_address(fields[1], family)
                remote_ip, remote_port = decode_address(fields[2], family)

                sockets.append(
                    SocketInfo(
                        proto=proto,
                        family=family,
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        state=states.get(fields[3].upper(), "OTHER"),
                        uid=int(fields[7]),
                        inode=int(fields[9]),
                    )
                )
            except (ValueError, struct.error):
                continue

    return sockets


def read_ephemeral_low(proc_root: Path) -> int:
    try:
        text = (proc_root / "sys/net/ipv4/ip_local_port_range").read_text()
        return int(text.split()[0])
    except (OSError, ValueError, IndexError):
        return DEFAULT_EPHEMERAL_LOW


def map_socket_owners(
    proc_root: Path,
    wanted: set[int],
) -> tuple[dict[int, list[int]], int]:
    """
    Find which processes hold each socket inode by reading
    /proc/<pid>/fd. Returns (owners, number of unreadable processes).
    """
    owners: dict[int, list[int]] = {}
    unreadable = 0

    try:
        entries = os.listdir(proc_root)
    except OSError:
        return owners, 0

    for name in sorted(entries, key=lambda value: (len(value), value)):
        if not name.isdigit():
            continue

        fd_dir = proc_root / name / "fd"

        try:
            descriptors = os.listdir(fd_dir)
        except PermissionError:
            unreadable += 1
            continue
        except OSError:
            continue

        for descriptor in descriptors:
            try:
                target = os.readlink(fd_dir / descriptor)
            except OSError:
                continue

            if not target.startswith("socket:["):
                continue

            try:
                inode = int(target[8:-1])
            except ValueError:
                continue

            if inode in wanted:
                holders = owners.setdefault(inode, [])

                if int(name) not in holders:
                    holders.append(int(name))

    return owners, unreadable


def read_text(path: Path, limit: int) -> str | None:
    try:
        with path.open("rb") as stream:
            return stream.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return None


def user_name(uid: int | None) -> str:
    if uid is None:
        return "?"

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def read_process(proc_root: Path, pid: int) -> ProcessInfo:
    base = proc_root / str(pid)

    name = (read_text(base / "comm", 64) or "?").strip()
    raw = read_text(base / "cmdline", MAX_CMDLINE_BYTES) or ""
    cmdline = " ".join(part for part in raw.split("\0") if part)

    try:
        exe = os.readlink(base / "exe")
    except OSError:
        exe = ""

    uid = None
    status = read_text(base / "status", 8192) or ""

    for line in status.splitlines():
        if line.startswith("Uid:"):
            try:
                uid = int(line.split()[1])
            except (ValueError, IndexError):
                pass
            break

    return ProcessInfo(
        pid=pid,
        name=printable(name, 32),
        uid=uid,
        user=printable(user_name(uid), 32),
        exe=printable(exe, 200),
        cmdline=printable(cmdline),
        deleted=exe.endswith(" (deleted)"),
    )


def is_privileged(proc_root: Path) -> bool:
    if proc_root != DEFAULT_PROC_ROOT:
        return True

    return getattr(os, "geteuid", lambda: 1)() == 0


def collect_snapshot(
    proc_root: Path = DEFAULT_PROC_ROOT,
) -> Snapshot:
    if proc_root == DEFAULT_PROC_ROOT and not sys.platform.startswith(
        "linux"
    ):
        raise NetworkError("This module only works on Linux.")

    warnings: list[str] = []
    sockets: list[SocketInfo] = []
    found = False

    for relative, proto, family in TABLES:
        try:
            sockets.extend(read_table(proc_root / relative, proto, family))
            found = True
        except FileNotFoundError:
            continue
        except OSError as error:
            warnings.append(
                f"Cannot read {relative}: {error.strerror or error}"
            )

    if not found:
        raise NetworkError(
            f"Cannot read the network tables under {proc_root}/net."
        )

    ephemeral_low = read_ephemeral_low(proc_root)

    owners, unreadable = map_socket_owners(
        proc_root,
        {item.inode for item in sockets if item.inode},
    )

    cache: dict[int, ProcessInfo] = {}

    for item in sockets:
        if item.proto == "tcp":
            item.listening = item.state == "LISTEN"
        else:
            item.listening = (
                item.state == "UNCONN"
                and 0 < item.local_port < ephemeral_low
            )

        if item.listening:
            item.scope = bind_scope(item.local_ip)

        holders = owners.get(item.inode)

        if holders:
            item.pids = tuple(holders)

            if holders[0] not in cache:
                cache[holders[0]] = read_process(proc_root, holders[0])

            item.process = cache[holders[0]]

    privileged = is_privileged(proc_root)

    if unreadable:
        warnings.append(
            f"{unreadable} process(es) could not be inspected, so some "
            "sockets may show no process. Run as root (in Docker, add "
            "the SYS_PTRACE capability)."
        )
    elif not privileged:
        warnings.append(
            "Not running as root: only your own processes can be "
            "identified."
        )

    try:
        host = socket.gethostname()
    except OSError:
        host = "unknown"

    return Snapshot(
        host=printable(host, 64),
        taken_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        privileged=privileged,
        unreadable_processes=unreadable,
        ephemeral_low=ephemeral_low,
        sockets=sockets,
        warnings=warnings,
    )