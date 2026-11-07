import json
import re
from pathlib import Path

from src.audit.models import (
    RAN,
    AuditError,
    AuditFinding,
    Comparison,
    ModuleRun,
    ResolvedFinding,
)

REPORT_TOOL = "linux-security-toolkit-audit"
REPORT_VERSION = 1
MAX_REPORT_BYTES = 50_000_000

REPORT_NAME = re.compile(r"audit-(\d{8}-\d{6})(?:-(\d+))?\.json")


def find_latest(directory: Path) -> Path | None:
    """The newest saved audit report (names contain the date)."""
    if not directory.is_dir():
        return None

    candidates = []

    for path in directory.glob("audit-*.json"):
        match = REPORT_NAME.fullmatch(path.name)

        if match:
            # Reports saved in the same second get a "-2", "-3" suffix.
            candidates.append(
                ((match.group(1), int(match.group(2) or 1)), path)
            )

    return max(candidates)[1] if candidates else None


def load_previous(path: Path) -> dict:
    if not path.is_file():
        raise AuditError(f"Previous report not found: {path}")

    if path.stat().st_size > MAX_REPORT_BYTES:
        raise AuditError(f"Previous report is too large: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as error:
        raise AuditError(f"Previous report cannot be read: {path}") from error

    valid = (
        isinstance(data, dict)
        and data.get("tool") == REPORT_TOOL
        and data.get("version") == REPORT_VERSION
        and isinstance(data.get("findings"), list)
        and isinstance(data.get("modules"), list)
        and all(
            isinstance(item, dict) and "fingerprint" in item and "module" in item
            for item in data["findings"]
        )
    )

    if not valid:
        raise AuditError(f"Not a valid audit report: {path}")

    return data


def compare(
    findings: list[AuditFinding],
    runs: list[ModuleRun],
    previous: dict,
    previous_file: str,
) -> Comparison:
    """
    Classify findings as new or unchanged and list the resolved ones.
    Only modules that ran in both audits are compared: a module that was
    skipped must not make its old findings look resolved.
    """
    ran_now = {run.name for run in runs if run.status in RAN}
    ran_before = {
        item.get("name")
        for item in previous["modules"]
        if isinstance(item, dict) and item.get("status") in RAN
    }

    comparable = ran_now & ran_before

    comparison = Comparison(
        previous_file=previous_file,
        previous_started_at=str(previous.get("started_at", "")),
        previous_host=str(previous.get("host", "")),
        not_comparable=sorted(
            {run.name for run in runs} - comparable
        ),
    )

    before = {
        item["fingerprint"]: item
        for item in previous["findings"]
        if item["module"] in comparable
    }

    current = set()

    for finding in findings:
        if finding.module not in comparable:
            continue

        current.add(finding.fingerprint)

        if finding.fingerprint in before:
            comparison.states[finding.fingerprint] = "unchanged"
            comparison.unchanged += 1
        else:
            comparison.states[finding.fingerprint] = "new"
            comparison.new += 1

    for fingerprint, item in before.items():
        if fingerprint not in current:
            comparison.resolved.append(ResolvedFinding(
                fingerprint=fingerprint,
                module=str(item.get("module", "")),
                rule_id=str(item.get("rule_id", "")),
                severity=str(item.get("severity", "LOW")),
                subject=str(item.get("subject", "")),
                title=str(item.get("title", "")),
            ))

    return comparison