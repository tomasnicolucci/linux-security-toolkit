from dataclasses import dataclass, field

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

SEVERITY_ORDER = {LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}


class NetworkError(ValueError):
    """An expected failure that can be reported to the user."""


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    uid: int | None
    user: str
    exe: str
    cmdline: str
    deleted: bool


@dataclass
class SocketInfo:
    proto: str
    family: int
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    uid: int
    inode: int
    listening: bool = False
    scope: str = ""
    pids: tuple[int, ...] = ()
    process: ProcessInfo | None = None

    @staticmethod
    def _format(ip: str, port: int) -> str:
        return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

    @property
    def local(self) -> str:
        return self._format(self.local_ip, self.local_port)

    @property
    def remote(self) -> str:
        return self._format(self.remote_ip, self.remote_port)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    subject: str
    title: str
    detail: str
    recommendation: str


@dataclass
class Snapshot:
    host: str
    taken_at: str
    privileged: bool
    unreadable_processes: int
    ephemeral_low: int
    sockets: list[SocketInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def listeners(self) -> list[SocketInfo]:
        return [item for item in self.sockets if item.listening]