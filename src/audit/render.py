import json
import os
from datetime import timezone
from pathlib import Path
from typing import Any

from src.audit.comparison import REPORT_TOOL, REPORT_VERSION
from src.audit.models import (
    OVERALL_TEXT,
    SEVERITIES,
    AuditFinding,
    AuditReport,
)

MAX_LISTED_CHANGES = 20
MAX_CELL = 300

SEVERITY_TITLES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


def iso(moment) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(text: object) -> str:
    """Replace control characters in text that comes from the system."""
    return "".join(
        character if character.isprintable() else " "
        for character in str(text)
    )


def md(text: object) -> str:
    """Escape text so that it cannot become Markdown or HTML."""
    value = clean(text)

    for character in ("\\", "`", "*", "_", "[", "]", "<", ">", "|"):
        value = value.replace(character, "\\" + character)

    return value


def duration(report: AuditReport) -> float:
    return (report.finished_at - report.started_at).total_seconds()


def report_to_dict(report: AuditReport) -> dict[str, Any]:
    states = report.comparison.states if report.comparison else {}

    comparison = None

    if report.comparison:
        item = report.comparison

        comparison = {
            "previous_file": item.previous_file,
            "previous_started_at": item.previous_started_at,
            "previous_host": item.previous_host,
            "new": item.new,
            "unchanged": item.unchanged,
            "resolved": [
                {
                    "fingerprint": resolved.fingerprint,
                    "module": resolved.module,
                    "rule_id": resolved.rule_id,
                    "severity": resolved.severity,
                    "subject": resolved.subject,
                    "title": resolved.title,
                }
                for resolved in item.resolved
            ],
            "not_comparable": item.not_comparable,
        }

    return {
        "tool": REPORT_TOOL,
        "version": REPORT_VERSION,
        "host": report.host,
        "started_at": iso(report.started_at),
        "finished_at": iso(report.finished_at),
        "status": report.status,
        "complete": report.complete,
        "modules": [
            {
                "name": run.name,
                "status": run.status,
                "message": run.message,
                "findings": run.findings,
                "seconds": run.seconds,
                "notes": run.notes,
            }
            for run in report.modules
        ],
        "summary": report.summary,
        "comparison": comparison,
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "module": finding.module,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "subject": finding.subject,
                "title": finding.title,
                "detail": finding.detail,
                "recommendation": finding.recommendation,
                "state": states.get(finding.fingerprint),
            }
            for finding in report.findings
        ],
    }


def module_notes(run) -> str:
    parts = ([run.message] if run.message else []) + list(run.notes)
    text = "; ".join(parts)

    return text[:MAX_CELL] + ("..." if len(text) > MAX_CELL else "")


def render_markdown(report: AuditReport) -> str:
    states = report.comparison.states if report.comparison else {}
    summary = report.summary
    lines = [
        "# Security Audit Report",
        "",
        f"- **Host:** {md(report.host)}",
        f"- **Started:** {iso(report.started_at)}",
        f"- **Duration:** {duration(report):.0f} s",
        f"- **Status:** {md(OVERALL_TEXT[report.status])}",
    ]

    if not report.complete:
        lines.append(
            "- **Coverage:** incomplete. Some modules were skipped, "
            "limited or failed (see the table below)."
        )

    lines += [
        "",
        "## Modules",
        "",
        "| Module | Status | Findings | Notes |",
        "|---|---|---|---|",
    ]

    for run in report.modules:
        lines.append(
            f"| {md(run.name)} | {md(run.status)} | {run.findings} "
            f"| {md(module_notes(run))} |"
        )

    lines += [
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]

    for level in SEVERITIES:
        lines.append(f"| {SEVERITY_TITLES[level]} | {summary[level]} |")

    lines.append(f"| **Total** | **{summary['total']}** |")

    if report.comparison:
        item = report.comparison

        lines += [
            "",
            "## Changes since the previous report",
            "",
            f"- **Previous report:** {md(item.previous_file)} "
            f"({md(item.previous_started_at)})",
            f"- **New findings:** {item.new}",
            f"- **Unchanged findings:** {item.unchanged}",
            f"- **Resolved findings:** {len(item.resolved)}",
        ]

        if item.previous_host and item.previous_host != report.host:
            lines.append(
                f"- **Note:** the previous report belongs to host "
                f"{md(item.previous_host)}."
            )

        if item.not_comparable:
            lines.append(
                "- **Not compared** (the module did not run in both "
                f"audits): {md(', '.join(item.not_comparable))}."
            )

        if item.resolved:
            lines += ["", "### Resolved", ""]

            for resolved in item.resolved[:MAX_LISTED_CHANGES]:
                lines.append(
                    f"- {md(resolved.severity)} {md(resolved.rule_id)}: "
                    f"{md(resolved.title)}"
                )

            hidden = len(item.resolved) - MAX_LISTED_CHANGES

            if hidden > 0:
                lines.append(f"- ... and {hidden} more (see the JSON report).")

    for level in SEVERITIES:
        group = [item for item in report.findings if item.severity == level]

        if not group:
            continue

        lines += ["", f"## {SEVERITY_TITLES[level]} findings ({len(group)})"]

        for finding in group:
            state = states.get(finding.fingerprint)

            lines += [
                "",
                f"### {md(finding.rule_id)}: {md(finding.title)}",
                "",
                f"- **Module:** {md(finding.module)}",
                f"- **Subject:** {md(finding.subject)}",
            ]

            if state == "new":
                lines.append("- **Since the previous report:** new")

            lines += [
                f"- **Detail:** {md(finding.detail)}",
                f"- **Fix:** {md(finding.recommendation)}",
            ]

    if not report.findings:
        lines += ["", "No findings."]

    return "\n".join(lines) + "\n"


def console_finding(finding: AuditFinding, state: str | None) -> list[str]:
    marker = " (new)" if state == "new" else ""

    return [
        f"[{finding.severity}] {finding.module} {clean(finding.rule_id)} "
        f"{clean(finding.title)}{marker}",
        f"    {clean(finding.detail)}",
        f"    Fix: {clean(finding.recommendation)}",
    ]


def render_console(report: AuditReport) -> str:
    states = report.comparison.states if report.comparison else {}
    summary = report.summary

    lines = [
        f"Security Audit | Host: {clean(report.host)} | "
        f"{iso(report.started_at)}",
        f"Status: {OVERALL_TEXT[report.status]}",
    ]

    if not report.complete:
        lines.append(
            "Coverage: incomplete (some modules were skipped, limited or "
            "failed)."
        )

    lines += ["", "Modules"]

    for run in report.modules:
        notes = module_notes(run)

        lines.append(
            f"  {run.name:<10} {run.status:<8} {run.findings:>4} findings"
            + (f"  - {clean(notes)}" if notes else "")
        )

    lines.append("")
    lines.append(
        "Findings: "
        + " | ".join(f"{summary[level]} {level}" for level in SEVERITIES)
        + f" ({summary['total']} in total)"
    )

    if report.comparison:
        item = report.comparison

        lines += [
            "",
            f"Changes since the previous report ({clean(item.previous_file)}): "
            f"{item.new} new, {item.unchanged} unchanged, "
            f"{len(item.resolved)} resolved.",
        ]

        if item.not_comparable:
            lines.append(
                "  Not compared: " + ", ".join(item.not_comparable)
            )

        for resolved in item.resolved[:MAX_LISTED_CHANGES]:
            lines.append(
                f"  [resolved] {resolved.severity} {clean(resolved.rule_id)} "
                f"{clean(resolved.title)}"
            )

    serious = [
        finding for finding in report.findings
        if finding.severity in ("CRITICAL", "HIGH")
    ]

    if serious:
        lines += ["", "Critical and high severity findings"]

        for finding in serious:
            lines += console_finding(
                finding,
                states.get(finding.fingerprint),
            )

    return "\n".join(lines)


def write_reports(
    report: AuditReport,
    directory: Path,
    formats: tuple[str, ...],
) -> list[Path]:
    """
    Save the report. Files are private (mode 600) and never replace an
    existing report.
    """
    if not formats:
        return []

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    base = f"audit-{report.started_at.astimezone(timezone.utc):%Y%m%d-%H%M%S}"
    suffix = ""
    attempt = 1

    while any(
        (directory / f"{base}{suffix}.{extension}").exists()
        for extension in ("md", "json")
    ):
        attempt += 1
        suffix = f"-{attempt}"

    contents = {
        "md": lambda: render_markdown(report),
        "json": lambda: json.dumps(
            report_to_dict(report),
            indent=2,
            ensure_ascii=False,
        ) + "\n",
    }

    paths = []

    for extension in formats:
        path = directory / f"{base}{suffix}.{extension}"

        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(contents[extension]())

        paths.append(path)

    return paths