import ipaddress
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from src.network.models import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    SEVERITY_ORDER,
    Finding,
    ProcessInfo,
    Snapshot,
    SocketInfo,
)

DEFAULT_MAX_PER_IP = 100
DEFAULT_SYN_THRESHOLD = 50

# (protocol, port): (service, severity, reason)
RISKY_PORTS = {
    ("tcp", 21): ("FTP", HIGH, "sends credentials in clear text"),
    ("tcp", 23): ("Telnet", HIGH, "sends credentials in clear text"),
    ("udp", 69): ("TFTP", HIGH, "has no authentication"),
    ("tcp", 512): ("rexec", HIGH, "is a legacy remote execution service"),
    ("tcp", 513): ("rlogin", HIGH, "is a legacy remote login service"),
    ("tcp", 514): ("rsh", HIGH, "is a legacy remote shell service"),
    ("tcp", 111): ("rpcbind", MEDIUM, "exposes RPC services"),
    ("udp", 111): ("rpcbind", MEDIUM, "exposes RPC services"),
    ("tcp", 139): ("SMB/NetBIOS", MEDIUM, "exposes file sharing"),
    ("tcp", 445): ("SMB", MEDIUM, "exposes file sharing"),
    ("tcp", 2049): ("NFS", MEDIUM, "exposes file sharing"),
    ("udp", 2049): ("NFS", MEDIUM, "exposes file sharing"),
    ("tcp", 3389): ("RDP", MEDIUM, "exposes remote desktop access"),
    ("udp", 161): ("SNMP", MEDIUM, "exposes device information"),
    ("udp", 1900): ("UPnP", MEDIUM, "exposes device discovery"),
    ("tcp", 1433): ("Microsoft SQL Server", MEDIUM, "is a database"),
    ("tcp", 1521): ("Oracle Database", MEDIUM, "is a database"),
    ("tcp", 3306): ("MySQL/MariaDB", MEDIUM, "is a database"),
    ("tcp", 5432): ("PostgreSQL", MEDIUM, "is a database"),
    ("tcp", 5984): ("CouchDB", HIGH, "often runs without authentication"),
    ("tcp", 6379): ("Redis", HIGH, "often runs without authentication"),
    ("tcp", 9200): ("Elasticsearch", HIGH, "often runs without authentication"),
    ("tcp", 9300): ("Elasticsearch", HIGH, "often runs without authentication"),
    ("tcp", 11211): ("Memcached", HIGH, "often runs without authentication"),
    ("udp", 11211): ("Memcached", HIGH, "can be abused for amplification attacks"),
    ("tcp", 27017): ("MongoDB", HIGH, "often runs without authentication"),
    ("tcp", 2375): ("Docker API", CRITICAL, "gives root control of the host without TLS"),
}

for _port in range(5900, 5910):
    RISKY_PORTS[("tcp", _port)] = (
        "VNC",
        MEDIUM,
        "exposes remote desktop access",
    )

SHELL_NAMES = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
})

NETWORK_TOOLS = frozenset({"nc", "ncat", "netcat", "socat"})

TEMP_DIRECTORIES = ("/tmp/", "/var/tmp/", "/dev/shm/")
SYSTEM_DIRECTORIES = (
    "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/",
)

# States that represent an active or half-open connection.
ACTIVE_STATES = frozenset({
    "ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT",
    "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING",
})


@dataclass(frozen=True)
class RuleOptions:
    max_per_ip: int = DEFAULT_MAX_PER_IP
    syn_threshold: int = DEFAULT_SYN_THRESHOLD


def describe(item: SocketInfo) -> str:
    owner = ""

    if item.process is not None:
        owner = f" ({item.process.name}, pid {item.process.pid})"

    if item.listening:
        return f"{item.proto} {item.local}{owner}"

    return f"{item.proto} {item.local} -> {item.remote}{owner}"


def exposure_finding(item: SocketInfo) -> Finding | None:
    """A risky service reachable beyond the local machine (NC-001)."""
    if not item.listening or item.scope == "loopback":
        return None

    known = RISKY_PORTS.get((item.proto, item.local_port))

    if known is None:
        return None

    service, severity, reason = known

    where = (
        "on all network interfaces"
        if item.scope == "all"
        else f"on {item.local_ip}"
    )

    return Finding(
        "NC-001",
        severity,
        describe(item),
        f"{service} is listening {where} (port {item.local_port})",
        f"{service} {reason}, and it accepts connections from the network.",
        "Bind it to 127.0.0.1 or a private interface, restrict it with "
        "a firewall, and use an SSH tunnel or VPN for remote access.",
    )


def base_name(process: ProcessInfo) -> str:
    path = process.exe.removesuffix(" (deleted)")
    name = PurePosixPath(path).name if path else process.name
    return name.lower()


def process_findings(
    process: ProcessInfo,
    sockets: list[SocketInfo],
) -> list[Finding]:
    """Findings about the program behind network sockets."""
    findings = []
    exe_path = process.exe.removesuffix(" (deleted)")
    listening = any(item.listening for item in sockets)
    subject = f"{process.name} (pid {process.pid})"
    example = describe(sockets[0])

    if process.deleted:
        if exe_path.startswith("/memfd:"):
            findings.append(Finding(
                "NC-002", CRITICAL, subject,
                f"Process '{process.name}' runs from memory only (memfd)",
                f"The program of pid {process.pid} has no file on disk "
                f"and owns network sockets, such as {example}. This is "
                "typical of fileless malware.",
                "Investigate the process immediately and isolate the host "
                "if it is not expected.",
            ))
        elif exe_path.startswith(SYSTEM_DIRECTORIES):
            findings.append(Finding(
                "NC-002", LOW, subject,
                f"Process '{process.name}' runs a replaced program file",
                f"The file {exe_path} was replaced or removed after "
                f"pid {process.pid} started; it owns sockets such as "
                f"{example}. This usually happens after a package update.",
                "Restart the service to run the updated program.",
            ))
        else:
            findings.append(Finding(
                "NC-002", CRITICAL if listening else HIGH, subject,
                f"Process '{process.name}' runs a deleted program",
                f"The program file {exe_path} no longer exists, but "
                f"pid {process.pid} is running and owns sockets such as "
                f"{example}. Malware often deletes itself after starting.",
                "Inspect /proc/<pid> and the process, and stop it if it "
                "is not expected.",
            ))

    if exe_path.startswith(TEMP_DIRECTORIES):
        findings.append(Finding(
            "NC-003", HIGH, subject,
            f"Process '{process.name}' runs from a temporary directory",
            f"The program {exe_path} (pid {process.pid}) runs from a "
            f"world-writable directory and owns sockets such as {example}.",
            "Verify where the program came from; legitimate services "
            "do not run from temporary directories.",
        ))

    name = base_name(process)
    tool = name.split(".")[0]

    established = [item for item in sockets if item.state == "ESTABLISHED"]

    if name in SHELL_NAMES and established:
        findings.append(Finding(
            "NC-009", HIGH, subject,
            f"Shell '{process.name}' has a network connection",
            f"The shell of pid {process.pid} owns {describe(established[0])}. "
            "Interactive shells normally use a terminal, not a socket; "
            "this is the pattern of a reverse shell.",
            "Inspect the process and its parent, and terminate it if it "
            "is not expected.",
        ))
    elif tool in NETWORK_TOOLS and (established or listening):
        findings.append(Finding(
            "NC-009", HIGH, subject,
            f"Network tool '{process.name}' is using the network",
            f"The tool of pid {process.pid} owns {example}. Tools such as "
            "netcat and socat are used to open bind or reverse shells.",
            "Confirm that this use is expected; otherwise terminate the "
            "process and investigate how it started.",
        ))

    return findings


def aggregate_findings(
    snapshot: Snapshot,
    options: RuleOptions,
) -> list[Finding]:
    findings = []
    sockets = snapshot.sockets

    per_remote: Counter = Counter()

    for item in sockets:
        if item.state not in ACTIVE_STATES:
            continue

        address = ipaddress.ip_address(item.remote_ip)

        if address.is_loopback or address.is_unspecified:
            continue

        per_remote[item.remote_ip] += 1

    for remote, count in per_remote.most_common():
        if count < options.max_per_ip:
            break

        findings.append(Finding(
            "NC-006", MEDIUM, remote,
            f"{count} simultaneous connections with {remote}",
            f"The host {remote} has {count} active connections "
            f"(threshold: {options.max_per_ip}). This can indicate a "
            "scan, a flood or an abusive client.",
            "Check the traffic, and block or rate limit the address if "
            "it is not expected.",
        ))

    half_open: Counter = Counter()

    for item in sockets:
        if item.state == "SYN_RECV":
            half_open[(item.proto, item.local_port)] += 1

    for (proto, port), count in half_open.most_common():
        if count < options.syn_threshold:
            break

        findings.append(Finding(
            "NC-007", MEDIUM, f"{proto} {port}",
            f"{count} half-open connections on port {port}",
            f"Port {port} has {count} connections in SYN_RECV state "
            f"(threshold: {options.syn_threshold}), a sign of a SYN "
            "flood or a scan.",
            "Enable SYN cookies (net.ipv4.tcp_syncookies=1) and review "
            "the firewall and rate limits.",
        ))

    if snapshot.privileged and snapshot.unreadable_processes == 0:
        for item in snapshot.listeners:
            if item.process is None:
                findings.append(Finding(
                    "NC-008", LOW, describe(item),
                    f"Listening socket on port {item.local_port} has no "
                    "visible process",
                    f"{describe(item)} is listening, but no process holds "
                    "it. It may belong to the kernel (for example NFS) or "
                    "to another namespace, but it can also be hidden.",
                    "Check with 'ss -tulpn' and the owner of the service.",
                ))

    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER[item.severity],
            item.rule_id,
            item.subject,
        ),
    )


def analyze(
    snapshot: Snapshot,
    options: RuleOptions,
) -> list[Finding]:
    findings = []

    for item in snapshot.listeners:
        finding = exposure_finding(item)

        if finding:
            findings.append(finding)

    by_process: dict[int, list[SocketInfo]] = {}
    processes: dict[int, ProcessInfo] = {}

    for item in snapshot.sockets:
        if item.process is None:
            continue

        pid = item.process.pid
        processes[pid] = item.process
        by_process.setdefault(pid, []).append(item)

    for pid, process in processes.items():
        findings.extend(process_findings(process, by_process[pid]))

    findings.extend(aggregate_findings(snapshot, options))

    return findings