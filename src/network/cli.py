import argparse
import os
import sys
from pathlib import Path

from src.network.baseline import (
    DEFAULT_BASELINE,
    compare_baseline,
    create_baseline,
    load_baseline,
)
from src.network.models import SEVERITY_ORDER
from src.network.procfs import DEFAULT_PROC_ROOT, collect_snapshot
from src.network.reporter import (
    export_json,
    print_baseline,
    print_scan,
)
from src.network.rules import (
    DEFAULT_MAX_PER_IP,
    DEFAULT_SYN_THRESHOLD,
    RuleOptions,
    analyze,
    sort_findings,
)
from src.network.service import (
    public_remote_ips,
    select_sockets,
    state_counts,
)
from src.network.watch import MIN_INTERVAL, watch


def add_proc_root(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--proc-root",
        type=Path,
        default=DEFAULT_PROC_ROOT,
        help="Alternative /proc directory (for tests)",
    )


def add_baseline_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--baseline",
        nargs="?",
        const=DEFAULT_BASELINE,
        type=Path,
        help=f"Compare listeners with a baseline (default: {DEFAULT_BASELINE})",
    )


def severity_type(value: str) -> str:
    level = value.upper()

    if level not in SEVERITY_ORDER:
        raise argparse.ArgumentTypeError(
            "must be LOW, MEDIUM, HIGH or CRITICAL"
        )

    return level


def add_network_subcommands(subcommands) -> None:
    scan = subcommands.add_parser(
        "scan",
        help="Show listening ports and connections, and find problems",
    )

    scan.add_argument("--listening", action="store_true", help="Only listening sockets")
    scan.add_argument("--established", action="store_true", help="Only established connections")
    scan.add_argument("--proto", choices=("tcp", "udp"), help="Only one protocol")
    scan.add_argument("--port", type=int, help="Only sockets using this port")
    scan.add_argument("--pid", type=int, help="Only sockets of this process")
    scan.add_argument("--limit", type=int, default=100, help="Rows per table (default: 100)")
    scan.add_argument("--min-severity", type=severity_type, default="LOW", help="Show findings at or above this level")
    scan.add_argument("--fail-on", type=severity_type, help="Exit with status 1 when a finding reaches this level")
    scan.add_argument("--max-per-ip", type=int, default=DEFAULT_MAX_PER_IP, help="Connections per remote IP that raise a finding (default: 100)")
    scan.add_argument("--syn-threshold", type=int, default=DEFAULT_SYN_THRESHOLD, help="Half-open connections that raise a finding (default: 50)")
    scan.add_argument("--remote-ips", action="store_true", help="Print only the public remote IPs, one per line")
    scan.add_argument("--json", type=Path, dest="json_output", help="Save the result as JSON")
    add_baseline_option(scan)
    add_proc_root(scan)
    scan.set_defaults(func=run_scan)

    baseline = subcommands.add_parser(
        "baseline",
        help="Record the expected listening ports",
    )

    baseline_commands = baseline.add_subparsers(
        dest="baseline_command",
        required=True,
    )

    create = baseline_commands.add_parser(
        "create",
        help="Save the current listening ports as the baseline",
    )
    create.add_argument("--path", type=Path, default=DEFAULT_BASELINE)
    create.add_argument("--force", action="store_true", help="Replace an existing baseline")
    add_proc_root(create)
    create.set_defaults(func=run_baseline_create)

    show = baseline_commands.add_parser("show", help="Show the baseline")
    show.add_argument("--path", type=Path, default=DEFAULT_BASELINE)
    show.set_defaults(func=run_baseline_show)

    watcher = subcommands.add_parser(
        "watch",
        help="Report new and closed listeners and connections",
    )
    watcher.add_argument("--interval", type=float, default=5.0, help="Seconds between checks (default: 5)")
    watcher.add_argument("--count", type=int, default=0, help="Stop after this many checks (default: until Ctrl+C)")
    watcher.add_argument("--log", type=Path, help="Append events as JSON lines to this file")
    watcher.add_argument("--include-loopback", action="store_true", help="Also report local connections")
    add_baseline_option(watcher)
    add_proc_root(watcher)
    watcher.set_defaults(func=run_watch)


def register_network_commands(commands) -> None:
    parser = commands.add_parser(
        "network",
        help="Monitor network connections and open ports",
        description="Network Connections Monitor",
    )

    subcommands = parser.add_subparsers(
        dest="network_command",
        required=True,
    )

    add_network_subcommands(subcommands)


def run_scan(args: argparse.Namespace) -> None:
    if args.limit <= 0:
        raise ValueError("--limit must be greater than zero.")

    if args.max_per_ip <= 0 or args.syn_threshold <= 0:
        raise ValueError("Thresholds must be greater than zero.")

    if args.listening and args.established:
        raise ValueError("--listening and --established cannot be combined.")

    snapshot = collect_snapshot(args.proc_root)

    findings = analyze(
        snapshot,
        RuleOptions(args.max_per_ip, args.syn_threshold),
    )

    if args.baseline:
        findings.extend(
            compare_baseline(snapshot, load_baseline(args.baseline))
        )

    findings = sort_findings(findings)

    selection = select_sockets(
        snapshot,
        args.listening,
        args.established,
        args.proto,
        args.port,
        args.pid,
    )

    if args.remote_ips:
        for warning in snapshot.warnings:
            print(f"[WARNING] {warning}", file=sys.stderr)

        for address in public_remote_ips(selection.connections):
            print(address)

        return

    minimum = SEVERITY_ORDER[args.min_severity]

    shown = [
        item for item in findings
        if SEVERITY_ORDER[item.severity] >= minimum
    ]

    states = state_counts(snapshot)

    print_scan(
        snapshot,
        selection.listeners,
        selection.connections,
        shown,
        states,
        args.limit,
        minimum,
        show_listeners=not args.established,
        show_connections=not args.listening,
    )

    if args.json_output:
        export_json(
            args.json_output,
            snapshot,
            selection.listeners,
            selection.connections,
            shown,
            states,
        )

        print(f"JSON report saved: {args.json_output}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]

        if any(SEVERITY_ORDER[item.severity] >= threshold for item in findings):
            raise SystemExit(1)


def run_baseline_create(args: argparse.Namespace) -> None:
    snapshot = collect_snapshot(args.proc_root)

    for warning in snapshot.warnings:
        print(f"[WARNING] {warning}")

    total = create_baseline(snapshot, args.path, args.force)

    print(f"Baseline saved: {args.path} ({total} listening ports)")


def run_baseline_show(args: argparse.Namespace) -> None:
    print_baseline(load_baseline(args.path))


def run_watch(args: argparse.Namespace) -> None:
    if args.interval < MIN_INTERVAL:
        raise ValueError(f"--interval must be at least {MIN_INTERVAL:g} second.")

    if args.count < 0:
        raise ValueError("--count cannot be negative.")

    baseline = load_baseline(args.baseline) if args.baseline else None

    totals = watch(
        args.proc_root,
        args.interval,
        args.count,
        args.log,
        args.include_loopback,
        baseline,
        lambda line: print(line, flush=True),
    )

    print(
        "Events: "
        + ", ".join(f"{name.replace('_', ' ')} {value}" for name, value in totals.items())
    )


def main(argv: list[str] | None = None) -> None:
    """Standalone entry point: python3 -m src.network"""
    parser = argparse.ArgumentParser(
        prog="python3 -m src.network",
        description="Network Connections Monitor",
    )

    subcommands = parser.add_subparsers(
        dest="network_command",
        required=True,
    )

    add_network_subcommands(subcommands)

    args = parser.parse_args(argv)

    try:
        args.func(args)
        # Output is buffered; flushing here makes a closed pipe show up
        # inside this block instead of while the interpreter exits.
        sys.stdout.flush()
    except BrokenPipeError:
        # The reader of a pipe (for example "head") closed early.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0)
    except (ValueError, OSError) as error:
        parser.exit(2, f"Error: {error}\n")