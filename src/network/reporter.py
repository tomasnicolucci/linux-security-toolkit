import json
from dataclasses import asdict
from pathlib import Path

from src.network.baseline import Baseline
from src.network.models import Finding, Snapshot, SocketInfo
from src.network.procfs import printable


def render_table(
    headers: list[str],
    rows: list[list[str]],
    limit: int,
) -> list[str]:
    if not rows:
        return ["  (none)"]

    shown = rows[:limit]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in shown))
        for i in range(len(headers))
    ]

    lines = [
        "  " + "  ".join(
            headers[i].ljust(widths[i]) for i in range(len(headers))
        ).rstrip()
    ]

    for row in shown:
        lines.append(
            "  " + "  ".join(
                row[i].ljust(widths[i]) for i in range(len(row))
            ).rstrip()
        )

    if len(rows) > limit:
        lines.append(f"  ... {len(rows) - limit} more (use --limit)")

    return lines


def owner_columns(item: SocketInfo) -> list[str]:
    process = item.process

    if process is None:
        return ["-", "-", "-"]

    return [str(process.pid), process.name, process.user]


def print_scan(
    snapshot: Snapshot,
    listeners: list[SocketInfo],
    connections: list[SocketInfo],
    findings: list[Finding],
    states: dict[str, int],
    limit: int,
    min_severity_value: int,
    show_listeners: bool,
    show_connections: bool,
) -> None:
    print(
        f"Network Connections Monitor | Host: {snapshot.host} | "
        f"{snapshot.taken_at}"
    )

    for warning in snapshot.warnings:
        print(f"[WARNING] {warning}")

    if show_listeners:
        print(f"\nListening sockets ({len(listeners)})")

        rows = [
            [
                item.proto,
                item.local,
                item.scope,
                *owner_columns(item),
                printable(item.process.cmdline, 50) if item.process else "-",
            ]
            for item in listeners
        ]

        for line in render_table(
            ["PROTO", "LOCAL", "SCOPE", "PID", "PROCESS", "USER", "COMMAND"],
            rows,
            limit,
        ):
            print(line)

    if show_connections:
        print(f"\nConnections ({len(connections)})")

        rows = [
            [
                item.proto,
                item.local,
                item.remote,
                item.state,
                *owner_columns(item),
            ]
            for item in connections
        ]

        for line in render_table(
            ["PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS", "USER"],
            rows,
            limit,
        ):
            print(line)

    print("\nTCP states: " + (
        ", ".join(f"{name} {count}" for name, count in states.items())
        or "none"
    ))

    print("\nFindings")

    if not findings:
        print("  No findings.")

    for finding in findings:
        print(
            f"[{finding.severity}] {finding.rule_id} {finding.title}"
        )
        print(f"    {finding.detail}")
        print(f"    Fix: {finding.recommendation}")

    print()
    print("Summary: " + " | ".join(
        f"{sum(f.severity == level for f in findings)} {level}"
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ) + f" ({len(findings)} findings)")


def print_baseline(baseline: Baseline) -> None:
    print(f"Baseline of host {baseline.host or '?'} created {baseline.created_at}")
    print(f"Expected listeners: {len(baseline.entries)}")

    rows = [
        [entry.proto, str(entry.port), entry.scope, entry.process or "-"]
        for entry in baseline.entries
    ]

    for line in render_table(
        ["PROTO", "PORT", "SCOPE", "PROCESS"],
        rows,
        len(rows) or 1,
    ):
        print(line)


def export_json(
    path: Path,
    snapshot: Snapshot,
    listeners: list[SocketInfo],
    connections: list[SocketInfo],
    findings: list[Finding],
    states: dict[str, int],
) -> None:
    document = {
        "host": snapshot.host,
        "taken_at": snapshot.taken_at,
        "privileged": snapshot.privileged,
        "summary": {
            "listeners": len(listeners),
            "connections": len(connections),
            "findings": len(findings),
            "tcp_states": states,
        },
        "listeners": [asdict(item) for item in listeners],
        "connections": [asdict(item) for item in connections],
        "findings": [asdict(item) for item in findings],
        "warnings": snapshot.warnings,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )