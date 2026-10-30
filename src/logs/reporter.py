import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from src.logs.models import AnalysisResult, SecurityEvent, SecurityFinding


def summarize(events: list[SecurityEvent], findings: list[SecurityFinding]) -> dict[str, Any]:
    ordered = sorted(events, key=lambda e: e.timestamp)
    midpoint = None
    if len(ordered) >= 2:
        midpoint = ordered[0].timestamp + (ordered[-1].timestamp - ordered[0].timestamp) / 2
    previous = sum(e.timestamp < midpoint for e in events) if midpoint else 0
    current = len(events) - previous
    return {
        "total_events": len(events),
        "total_findings": len(findings),
        "by_event_type": dict(Counter(e.event_type.value for e in events)),
        "by_severity": dict(Counter(f.severity.value for f in findings)),
        "top_source_ips": Counter(e.source_ip for e in events if e.source_ip).most_common(10),
        "top_users": Counter(e.username for e in events if e.username).most_common(10),
        "period_comparison": {
            "method": "equal-duration halves of observed time range",
            "first_half_events": previous,
            "second_half_events": current,
            "difference": current - previous,
        } if midpoint else None,
    }


def result_to_dict(result: AnalysisResult) -> dict[str, Any]:
    def serialize(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.isoformat()
        if hasattr(value, "value"):
            return value.value
        if isinstance(value, dict):
            return {str(k): serialize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [serialize(item) for item in value]
        return value
    return serialize(asdict(result))


def export_json(result: AnalysisResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result_to_dict(result), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def print_report(result: AnalysisResult) -> None:
    print(f"Files: {len(result.files_processed)} | Lines: {result.lines_processed} | Events: {len(result.events)} | Findings: {len(result.findings)}")
    if result.lines_unparsed:
        print(f"Unparsed lines: {result.lines_unparsed}")
    for source, error in result.errors.items():
        print(f"[ERROR] {source}: {error}")
    for warning in result.warnings:
        print(f"[WARNING] {warning}")
    for finding in sorted(result.findings, key=lambda f: (f.first_seen, f.rule_id)):
        print(f"[{finding.severity.value}] {finding.title} | {finding.first_seen.isoformat()} | IP={finding.source_ip or '-'} | user={finding.username or '-'} | events={finding.event_count}")
        print(f"  {finding.description}")
        print(f"  Recommendation: {finding.recommendation}")
    stats = result.statistics
    print("Top IPs:", stats.get("top_source_ips", []))
    print("Top users:", stats.get("top_users", []))
    print("Period comparison:", stats.get("period_comparison"))
