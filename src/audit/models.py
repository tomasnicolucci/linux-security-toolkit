import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime

MODULES = ("users", "network", "integrity", "logs")

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

STATUS_OK = "ok"
STATUS_LIMITED = "limited"
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"

# A module that produced results, even if it could not check everything.
RAN = (STATUS_OK, STATUS_LIMITED)

OVERALL_CRITICAL = "critical"
OVERALL_ATTENTION = "attention"
OVERALL_OK = "no_serious_problems"
OVERALL_INCONCLUSIVE = "inconclusive"

OVERALL_TEXT = {
    OVERALL_CRITICAL: "CRITICAL - there are critical findings",
    OVERALL_ATTENTION: "NEEDS ATTENTION - there are high severity findings",
    OVERALL_OK: "NO SERIOUS PROBLEMS - no critical or high severity findings",
    OVERALL_INCONCLUSIVE: "INCONCLUSIVE - no module could be audited",
}

PID_PATTERN = re.compile(r"pid \d+")
NUMBER_PATTERN = re.compile(r"\d+")


class AuditError(ValueError):
    """An expected failure that can be reported to the user."""


@dataclass(frozen=True)
class AuditFinding:
    module: str
    rule_id: str
    severity: str
    subject: str
    title: str
    detail: str
    recommendation: str

    @property
    def fingerprint(self) -> str:
        """
        Identity of a finding across runs. Process ids and counters that
        change between runs (a pid, "for 120 days") are left out so that
        the same problem keeps the same identity.
        """
        key = "\x1f".join((
            self.module,
            self.rule_id,
            PID_PATTERN.sub("pid", self.subject),
            NUMBER_PATTERN.sub("#", self.title),
        ))

        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


@dataclass
class AdapterResult:
    findings: list[AuditFinding] = field(default_factory=list)
    status: str = STATUS_OK
    message: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class ModuleRun:
    name: str
    status: str
    message: str = ""
    findings: int = 0
    seconds: float = 0.0
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResolvedFinding:
    fingerprint: str
    module: str
    rule_id: str
    severity: str
    subject: str
    title: str


@dataclass
class Comparison:
    previous_file: str
    previous_started_at: str
    previous_host: str
    new: int = 0
    unchanged: int = 0
    resolved: list[ResolvedFinding] = field(default_factory=list)
    not_comparable: list[str] = field(default_factory=list)
    states: dict[str, str] = field(default_factory=dict)


@dataclass
class AuditReport:
    host: str
    started_at: datetime
    finished_at: datetime
    modules: list[ModuleRun]
    findings: list[AuditFinding]
    comparison: Comparison | None = None

    @property
    def summary(self) -> dict[str, int]:
        counts = {level: 0 for level in SEVERITIES}

        for finding in self.findings:
            counts[finding.severity] += 1

        counts["total"] = len(self.findings)

        return counts

    @property
    def status(self) -> str:
        if not any(run.status in RAN for run in self.modules):
            return OVERALL_INCONCLUSIVE

        summary = self.summary

        if summary["CRITICAL"]:
            return OVERALL_CRITICAL

        if summary["HIGH"]:
            return OVERALL_ATTENTION

        return OVERALL_OK

    @property
    def complete(self) -> bool:
        return all(run.status == STATUS_OK for run in self.modules)