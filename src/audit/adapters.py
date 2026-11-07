import argparse
import shutil
import subprocess
import tempfile
import json
from dataclasses import dataclass
from pathlib import Path

from src.audit.models import (
    STATUS_ERROR,
    STATUS_LIMITED,
    STATUS_OK,
    STATUS_SKIPPED,
    AdapterResult,
    AuditFinding,
)
from src.integrity.baseline import load_baseline as load_integrity_baseline
from src.integrity.checker import compare_integrity
from src.integrity.scanner import scan_target
from src.logs.cli import analyze_logs
from src.logs.config import load_config
from src.network import baseline as network_baseline
from src.network.models import NetworkError
from src.network.procfs import DEFAULT_PROC_ROOT, collect_snapshot
from src.network.rules import RuleOptions, analyze as analyze_network

USERS_SCRIPT = Path(__file__).resolve().parents[1] / "users" / "user_auditor.sh"
USERS_TIMEOUT_SECONDS = 600

MAX_FILES_PER_KIND = 25


@dataclass
class AuditOptions:
    root: Path = Path("/")
    logs: Path | None = None
    recursive: bool = False
    year: int | None = None
    config: Path | None = None
    integrity_dir: Path | None = None
    network_baseline: Path | None = None
    proc_root: Path = DEFAULT_PROC_ROOT
    no_permission_checks: bool = False


def error(message: str) -> AdapterResult:
    return AdapterResult(status=STATUS_ERROR, message=message)


def first_line(text: str, default: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()

    return default


def run_users(options: AuditOptions) -> AdapterResult:
    """Run the Bash user auditor and read its JSON report."""
    bash = shutil.which("bash")

    if bash is None:
        return error("bash is not available on this system.")

    if not USERS_SCRIPT.is_file():
        return error(f"User auditor script not found: {USERS_SCRIPT}")

    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "users.json"

        command = [
            bash,
            str(USERS_SCRIPT),
            "--root",
            str(options.root),
            "--no-color",
            "--json",
            str(report),
        ]

        if options.no_permission_checks:
            command.append("--no-permission-checks")

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=USERS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return error("The user auditor took too long and was stopped.")

        if completed.returncode != 0 or not report.is_file():
            return error(
                first_line(
                    completed.stderr,
                    "The user auditor failed.",
                )
            )

        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except ValueError:
            return error("The user auditor produced an invalid report.")

    findings = []

    for item in data.get("findings", []):
        if not isinstance(item, dict):
            continue

        findings.append(AuditFinding(
            module="users",
            rule_id=str(item.get("id", "")),
            severity=str(item.get("severity", "LOW")),
            subject=str(item.get("subject", "")),
            title=str(item.get("title", "")),
            detail=str(item.get("detail", "")),
            recommendation=str(item.get("recommendation", "")),
        ))

    notes = [str(item) for item in data.get("warnings", [])]

    return AdapterResult(
        findings=findings,
        status=STATUS_LIMITED if notes else STATUS_OK,
        notes=notes,
    )


def run_network(options: AuditOptions) -> AdapterResult:
    """Look at listening ports and connections, and compare with the baseline."""
    try:
        snapshot = collect_snapshot(options.proc_root)
    except NetworkError as exc:
        return error(str(exc))

    found = analyze_network(snapshot, RuleOptions())
    notes = list(snapshot.warnings)

    baseline_path = options.network_baseline or network_baseline.DEFAULT_BASELINE

    if baseline_path.is_file():
        try:
            baseline = network_baseline.load_baseline(baseline_path)
            found.extend(network_baseline.compare_baseline(snapshot, baseline))
        except NetworkError as exc:
            notes.append(f"Baseline ignored: {exc}")
    else:
        notes.append(
            f"No network baseline found at {baseline_path}; change "
            "detection was skipped (create one with 'network baseline create')."
        )

    findings = [
        AuditFinding(
            module="network",
            rule_id=item.rule_id,
            severity=item.severity,
            subject=item.subject,
            title=item.title,
            detail=item.detail,
            recommendation=item.recommendation,
        )
        for item in found
    ]

    return AdapterResult(
        findings=findings,
        status=STATUS_LIMITED if notes else STATUS_OK,
        notes=notes,
    )


def run_logs(options: AuditOptions) -> AdapterResult:
    """Analyze the authentication logs with the log analyzer."""
    if options.logs is None:
        return error("No log path was given (use --logs).")

    try:
        config = load_config(options.config)

        result = analyze_logs(
            argparse.Namespace(
                target=options.logs,
                recursive=options.recursive,
                year=options.year,
                source_ip=None,
                username=None,
                event_types=None,
                start_date=None,
                end_date=None,
            ),
            config,
        )
    except (ValueError, OSError) as exc:
        return error(str(exc))

    if not result.files_processed:
        message = next(iter(result.errors.values()), "No log files were found.")
        return error(message)

    findings = []

    for item in result.findings:
        first = item.first_seen.strftime("%Y-%m-%d %H:%M")
        last = item.last_seen.strftime("%Y-%m-%d %H:%M")

        findings.append(AuditFinding(
            module="logs",
            rule_id=item.rule_id,
            severity=item.severity.value,
            subject=f"{item.source_ip or '-'}/{item.username or '-'}",
            title=item.title,
            detail=(
                f"{item.description} Events: {item.event_count}; "
                f"first seen {first} UTC, last seen {last} UTC."
            ),
            recommendation=item.recommendation,
        ))

    notes = list(result.warnings)

    if result.errors:
        notes.append(
            f"{len(result.errors)} log file(s) or line(s) could not be read."
        )

    return AdapterResult(
        findings=findings,
        status=STATUS_LIMITED if notes else STATUS_OK,
        notes=notes,
    )


INTEGRITY_KINDS = (
    ("modified", "INT-001", "HIGH", "modified"),
    ("added", "INT-002", "MEDIUM", "added"),
    ("deleted", "INT-003", "MEDIUM", "deleted"),
)


def integrity_findings(name: str, target: Path, report) -> list[AuditFinding]:
    findings = []

    for attribute, rule_id, severity, verb in INTEGRITY_KINDS:
        paths = getattr(report, attribute)

        for path in paths[:MAX_FILES_PER_KIND]:
            findings.append(AuditFinding(
                module="integrity",
                rule_id=rule_id,
                severity=severity,
                subject=f"{name}: {path}",
                title=f"File {verb}: {path}",
                detail=(
                    f"{path} was {verb} compared with baseline '{name}' "
                    f"of {target} (content or permissions)."
                    if attribute == "modified"
                    else f"{path} was {verb} compared with baseline "
                    f"'{name}' of {target}."
                ),
                recommendation=(
                    "Check that the change is expected. If it is, accept it "
                    f"with 'integrity update --name {name}'; otherwise "
                    "investigate how it happened."
                ),
            ))

        extra = len(paths) - MAX_FILES_PER_KIND

        if extra > 0:
            findings.append(AuditFinding(
                module="integrity",
                rule_id=rule_id,
                severity=severity,
                subject=f"{name}: more {attribute} files",
                title=f"{extra} more files {verb} in baseline '{name}'",
                detail=(
                    f"Only the first {MAX_FILES_PER_KIND} files are listed. "
                    f"Run 'integrity check --name {name}' for the full list."
                ),
                recommendation=(
                    "Review the full list and update the baseline if the "
                    "changes are expected."
                ),
            ))

    return findings


def run_integrity(options: AuditOptions) -> AdapterResult:
    """Check every saved integrity baseline."""
    directory = options.integrity_dir

    if directory is None:
        from src.integrity.cli import DATA_DIR

        directory = DATA_DIR

    baselines = sorted(directory.glob("*.json")) if directory.is_dir() else []

    if not baselines:
        return AdapterResult(
            status=STATUS_SKIPPED,
            message=f"No integrity baselines found in {directory}.",
        )

    findings = []
    notes = []

    for path in baselines:
        name = path.stem

        try:
            baseline = load_integrity_baseline(path)
        except (ValueError, OSError) as exc:
            notes.append(f"Baseline '{name}' was skipped: {exc}")
            continue

        target = Path(baseline["target"])

        if not target.exists():
            notes.append(
                f"Baseline '{name}' was skipped: its target is not "
                f"available here ({target})."
            )
            continue

        try:
            scan = scan_target(
                target,
                recursive=baseline["recursive"],
                exclusions=baseline["exclusions"],
            )
        except (ValueError, OSError) as exc:
            notes.append(f"Baseline '{name}' could not be checked: {exc}")
            continue

        report = compare_integrity(baseline["files"], scan)
        findings.extend(integrity_findings(name, target, report))

        if report.errors:
            notes.append(
                f"Baseline '{name}': {len(report.errors)} file(s) could not "
                "be read."
            )

    if not findings and notes and len(notes) >= len(baselines):
        return AdapterResult(
            status=STATUS_ERROR,
            message="No baseline could be checked.",
            notes=notes,
        )

    return AdapterResult(
        findings=findings,
        status=STATUS_LIMITED if notes else STATUS_OK,
        notes=notes,
    )