import socket
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from src.audit import adapters
from src.audit.adapters import AuditOptions
from src.audit.models import (
    MODULES,
    SEVERITY_RANK,
    STATUS_ERROR,
    AdapterResult,
    AuditError,
    AuditReport,
    ModuleRun,
)

DEFAULT_MODULES = ("users", "network", "integrity")

ADAPTERS = {
    "users": adapters.run_users,
    "network": adapters.run_network,
    "integrity": adapters.run_integrity,
    "logs": adapters.run_logs,
}


def parse_module_list(text: str | None, option: str) -> tuple[str, ...]:
    if not text:
        return ()

    names = tuple(item.strip() for item in text.split(",") if item.strip())

    for name in names:
        if name not in MODULES:
            raise AuditError(
                f"Unknown module '{name}' in {option} "
                f"(available: {', '.join(MODULES)})."
            )

    return names


def select_modules(
    only: tuple[str, ...],
    skip: tuple[str, ...],
    logs_given: bool,
) -> tuple[str, ...]:
    if only:
        selected = set(only)
    else:
        selected = set(DEFAULT_MODULES)

        if logs_given:
            selected.add("logs")

    selected -= set(skip)

    if "logs" in selected and not logs_given:
        raise AuditError("The logs module needs the --logs option.")

    if not selected:
        raise AuditError("There are no modules to run.")

    return tuple(name for name in MODULES if name in selected)


def detect_host(root: Path) -> str:
    """Host name of the audited system (the mounted one, if any)."""
    try:
        text = (root / "etc" / "hostname").read_text(encoding="utf-8")
        name = text.strip()
    except OSError:
        name = ""

    if not name:
        try:
            name = socket.gethostname()
        except OSError:
            name = "unknown"

    return "".join(c if c.isprintable() else "?" for c in name)[:64]


def normalize(finding):
    if finding.severity not in SEVERITY_RANK:
        return replace(finding, severity="LOW")

    return finding


def run_audit(
    modules: tuple[str, ...],
    options: AuditOptions,
) -> AuditReport:
    started = datetime.now(timezone.utc)
    runs = []
    findings = []

    for name in modules:
        begin = time.monotonic()

        try:
            result = ADAPTERS[name](options)
        except Exception as exc:  # a failing module must not hide the rest
            result = AdapterResult(
                status=STATUS_ERROR,
                message=f"{type(exc).__name__}: {exc}",
            )

        runs.append(ModuleRun(
            name=name,
            status=result.status,
            message=result.message,
            findings=len(result.findings),
            seconds=round(time.monotonic() - begin, 2),
            notes=list(result.notes),
        ))

        findings.extend(normalize(item) for item in result.findings)

    findings.sort(key=lambda item: (
        -SEVERITY_RANK[item.severity],
        MODULES.index(item.module),
        item.rule_id,
        item.subject,
    ))

    return AuditReport(
        host=detect_host(options.root),
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        modules=runs,
        findings=findings,
    )