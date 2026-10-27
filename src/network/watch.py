import ipaddress
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from src.network.baseline import Baseline, listener_finding
from src.network.models import Finding, SocketInfo
from src.network.procfs import collect_snapshot
from src.network.rules import exposure_finding, process_findings

MIN_INTERVAL = 1.0


def tracked(
    sockets: list[SocketInfo],
    include_loopback: bool,
) -> dict[tuple, SocketInfo]:
    """Listening sockets and established connections, by identity."""
    found = {}

    for item in sockets:
        if item.listening:
            found[("listener", item.proto, item.local)] = item
        elif item.state == "ESTABLISHED":
            if not include_loopback:
                if ipaddress.ip_address(item.remote_ip).is_loopback:
                    continue

            found[("connection", item.proto, item.local, item.remote)] = item

    return found


def alerts_for(
    item: SocketInfo,
    baseline: Baseline | None,
) -> list[Finding]:
    findings = []

    if item.listening:
        finding = exposure_finding(item)

        if finding:
            findings.append(finding)

        if baseline is not None:
            finding = listener_finding(item, baseline)

            if finding:
                findings.append(finding)

    if item.process is not None:
        findings.extend(process_findings(item.process, [item]))

    return findings


def event_record(
    kind: str,
    item: SocketInfo,
    alerts: list[Finding],
) -> dict:
    process = item.process

    return {
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": kind,
        "proto": item.proto,
        "local": item.local,
        "remote": None if item.listening else item.remote,
        "state": item.state,
        "pid": process.pid if process else None,
        "process": process.name if process else None,
        "user": process.user if process else None,
        "alerts": [
            {"id": a.rule_id, "severity": a.severity, "title": a.title}
            for a in alerts
        ],
    }


def format_event(record: dict, item: SocketInfo) -> list[str]:
    label = record["event"].replace("_", " ").upper()

    owner = ""

    if record["process"]:
        owner = (
            f" ({record['process']}, pid {record['pid']}, "
            f"user {record['user']})"
        )

    if item.listening:
        what = f"{record['proto']} {record['local']}"
    else:
        what = f"{record['proto']} {record['local']} -> {record['remote']}"

    lines = [f"[{record['time']}] {label} {what}{owner}"]

    for alert in record["alerts"]:
        lines.append(
            f"    [{alert['severity']}] {alert['id']} {alert['title']}"
        )

    return lines


def open_log(path: Path | None):
    if path is None:
        return None

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600,
    )

    return os.fdopen(descriptor, "a", encoding="utf-8")


def watch(
    proc_root: Path,
    interval: float,
    count: int,
    log_path: Path | None,
    include_loopback: bool,
    baseline: Baseline | None,
    emit: Callable[[str], None],
) -> dict[str, int]:
    """
    Poll the sockets and report what appears or disappears. Returns
    the number of events by kind. Connections that start and end
    between two polls are not seen.
    """
    totals = {
        "listener_new": 0,
        "listener_closed": 0,
        "connection_new": 0,
        "connection_closed": 0,
    }

    log = open_log(log_path)
    previous: dict[tuple, SocketInfo] | None = None
    iterations = 0

    try:
        while True:
            snapshot = collect_snapshot(proc_root)
            current = tracked(snapshot.sockets, include_loopback)

            if previous is None:
                listeners = sum(key[0] == "listener" for key in current)

                emit(
                    f"Watching: {listeners} listener(s) and "
                    f"{len(current) - listeners} connection(s) at start. "
                    f"Polling every {interval:g}s; press Ctrl+C to stop."
                )

                for warning in snapshot.warnings:
                    emit(f"[WARNING] {warning}")
            else:
                changes = []

                for key, item in current.items():
                    if key not in previous:
                        changes.append((f"{key[0]}_new", item, True))

                for key, item in previous.items():
                    if key not in current:
                        changes.append((f"{key[0]}_closed", item, False))

                for kind, item, is_new in changes:
                    alerts = alerts_for(item, baseline) if is_new else []
                    record = event_record(kind, item, alerts)
                    totals[kind] += 1

                    for line in format_event(record, item):
                        emit(line)

                    if log is not None:
                        log.write(json.dumps(record) + "\n")
                        log.flush()

            previous = current
            iterations += 1

            if count and iterations >= count:
                break

            time.sleep(interval)
    except KeyboardInterrupt:
        emit("\nStopped.")
    finally:
        if log is not None:
            log.close()

    return totals