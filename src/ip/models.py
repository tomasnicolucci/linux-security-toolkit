from dataclasses import dataclass, field


@dataclass(frozen=True)
class IPClassification:
    address: str
    version: int
    category: str
    description: str
    is_global: bool
    reverse_pointer: str
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RdapInfo:
    network_name: str | None = None
    handle: str | None = None
    ip_range: str | None = None
    cidrs: tuple[str, ...] = ()
    country: str | None = None
    organization: str | None = None
    abuse_contact: str | None = None


@dataclass(frozen=True)
class ReportContext:
    rules: tuple[str, ...]
    max_severity: str
    findings: int


@dataclass
class AddressEntry:
    raw: str
    sources: list[str] = field(default_factory=list)
    context: ReportContext | None = None


@dataclass
class IPAnalysis:
    input: str
    error: str | None = None
    classification: IPClassification | None = None
    approved: bool | None = None
    hostname: str | None = None
    rdap: RdapInfo | None = None
    context: ReportContext | None = None
    sources: list[str] = field(default_factory=list)
    lookup_messages: dict[str, str] = field(default_factory=dict)