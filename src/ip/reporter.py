import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.ip.models import IPAnalysis
from src.ip.text import clean_text


def summarize(analyses: list[IPAnalysis]) -> dict[str, int]:
    valid = [a for a in analyses if a.classification is not None]

    return {
        "total": len(analyses),
        "invalid": len(analyses) - len(valid),
        "global": sum(a.classification.is_global for a in valid),
        "non_global": sum(
            not a.classification.is_global for a in valid
        ),
    }


def approval_label(approved: bool | None) -> str:
    if approved is None:
        return "unknown (no baseline)"

    return "approved" if approved else "NOT approved"


def print_analysis(analysis: IPAnalysis) -> None:
    classification = analysis.classification

    if classification is None:
        shown = clean_text(analysis.input, 60) or "(empty)"

        print(f"[INVALID] {shown}")
        print(f"  {analysis.error}")
        return

    print(
        f"{classification.address} | IPv{classification.version} | "
        f"{classification.category}"
    )
    print(f"  Description: {classification.description}")

    for note in classification.notes:
        print(f"  Note: {note}")

    print(f"  Reverse pointer: {classification.reverse_pointer}")
    print(f"  Baseline: {approval_label(analysis.approved)}")
    print(f"  Source: {', '.join(analysis.sources)}")

    if analysis.context is not None:
        context = analysis.context

        print(
            f"  Log findings: {context.findings} | "
            f"max severity: {context.max_severity} | "
            f"rules: {', '.join(context.rules) or '-'}"
        )

    if analysis.hostname:
        print(f"  Reverse DNS: {analysis.hostname}")
    elif "dns" in analysis.lookup_messages:
        print(f"  Reverse DNS: {analysis.lookup_messages['dns']}")

    rdap = analysis.rdap

    if rdap is not None:
        print("  RDAP:")

        rows = (
            ("Network", rdap.network_name),
            ("Handle", rdap.handle),
            ("Range", rdap.ip_range),
            ("CIDR", ", ".join(rdap.cidrs) or None),
            ("Country", rdap.country),
            ("Organization", rdap.organization),
            ("Abuse contact", rdap.abuse_contact),
        )

        for label, value in rows:
            if value:
                print(f"    {label}: {value}")
    elif "rdap" in analysis.lookup_messages:
        print(f"  RDAP: {analysis.lookup_messages['rdap']}")


def print_report(
    analyses: list[IPAnalysis],
    warnings: list[str],
) -> None:
    stats = summarize(analyses)

    print(
        f"Addresses: {stats['total']} | Global: {stats['global']} | "
        f"Non-global: {stats['non_global']} | "
        f"Invalid: {stats['invalid']}"
    )

    for warning in warnings:
        print(f"[WARNING] {warning}")

    for analysis in analyses:
        print()
        print_analysis(analysis)


def result_to_dict(
    analyses: list[IPAnalysis],
    warnings: list[str],
) -> dict[str, Any]:
    return {
        "summary": summarize(analyses),
        "warnings": warnings,
        "results": [asdict(analysis) for analysis in analyses],
    }


def export_json(
    analyses: list[IPAnalysis],
    warnings: list[str],
    path: Path,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            result_to_dict(analyses, warnings),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )