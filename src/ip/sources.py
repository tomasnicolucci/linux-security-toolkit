import json
import sys
from pathlib import Path

from src.ip.classifier import canonical_address
from src.ip.models import AddressEntry, ReportContext


MAX_FILE_BYTES = 1_000_000
MAX_REPORT_BYTES = 100_000_000

SEVERITY_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def read_address_file(path: str) -> list[str]:
    """
    Read one address per line. Blank lines and '#' comments are
    ignored. Use '-' to read from standard input.
    """
    if path == "-":
        content = sys.stdin.read(MAX_FILE_BYTES + 1)
    else:
        file_path = Path(path)

        if not file_path.is_file():
            raise ValueError(f"Address file not found: {path}")

        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(
                f"Address file is too large (limit "
                f"{MAX_FILE_BYTES} bytes): {path}"
            )

        content = file_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

    if len(content) > MAX_FILE_BYTES:
        raise ValueError(
            f"Input is too large (limit {MAX_FILE_BYTES} bytes)."
        )

    addresses = []

    for line in content.splitlines():
        value = line.split("#", 1)[0].strip()

        if value:
            addresses.append(value)

    return addresses


def read_report_entries(path: Path) -> list[AddressEntry]:
    """
    Extract the IP addresses mentioned in the findings of a JSON
    report exported by `logs analyze --json`, ordered by severity.
    """
    if not path.is_file():
        raise ValueError(f"Report not found: {path}")

    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"Report is too large: {path}")

    with path.open("r", encoding="utf-8") as stream:
        data = json.load(stream)

    findings = (
        data.get("findings") if isinstance(data, dict) else None
    )

    if not isinstance(findings, list):
        raise ValueError(
            "Not a valid log analyzer report: "
            "missing 'findings' list."
        )

    collected: dict[str, dict] = {}

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        candidates = [finding.get("source_ip")]

        metadata = finding.get("metadata")

        if isinstance(metadata, dict):
            extra = metadata.get("source_ips")

            if isinstance(extra, list):
                candidates.extend(extra)

        rule = finding.get("rule_id")
        severity = finding.get("severity")

        for candidate in candidates:
            if not isinstance(candidate, str):
                continue

            key = canonical_address(candidate)

            if key is None:
                continue

            item = collected.setdefault(
                key,
                {"rules": set(), "severity": -1, "count": 0},
            )

            if isinstance(rule, str):
                item["rules"].add(rule)

            item["severity"] = max(
                item["severity"],
                SEVERITY_ORDER.get(severity, -1),
            )

            item["count"] += 1

    names = {value: name for name, value in SEVERITY_ORDER.items()}

    ordered = sorted(
        collected.items(),
        key=lambda pair: (
            -pair[1]["severity"],
            -pair[1]["count"],
            pair[0],
        ),
    )

    return [
        AddressEntry(
            raw=address,
            sources=["report"],
            context=ReportContext(
                rules=tuple(sorted(item["rules"])),
                max_severity=names.get(item["severity"], "UNKNOWN"),
                findings=item["count"],
            ),
        )
        for address, item in ordered
    ]


def build_entries(
    addresses: list[str],
    file_addresses: list[str],
    report_entries: list[AddressEntry],
    limit: int,
) -> tuple[list[AddressEntry], list[str]]:
    """Merge all sources, removing duplicates and applying a limit."""
    pending = [
        *(AddressEntry(raw, ["argument"]) for raw in addresses),
        *(AddressEntry(raw, ["file"]) for raw in file_addresses),
        *report_entries,
    ]

    merged: dict[str, AddressEntry] = {}

    for entry in pending:
        key = canonical_address(entry.raw) or entry.raw.strip()

        existing = merged.get(key)

        if existing is None:
            merged[key] = entry
            continue

        for source in entry.sources:
            if source not in existing.sources:
                existing.sources.append(source)

        if existing.context is None:
            existing.context = entry.context

    entries = list(merged.values())
    warnings = []

    if len(entries) > limit:
        skipped = len(entries) - limit
        entries = entries[:limit]

        warnings.append(
            f"{skipped} additional address(es) skipped "
            f"(limit is {limit}; use --limit to change it)."
        )

    return entries, warnings