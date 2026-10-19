
import argparse
from dataclasses import replace
from datetime import timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from src.logs.config import load_config
from src.logs.detectors.account_changes import detect_account_changes
from src.logs.detectors.brute_force import detect_brute_force
from src.logs.detectors.distributed_attack import detect_distributed_attack
from src.logs.detectors.password_spraying import detect_password_spraying
from src.logs.detectors.privileged_activity import detect_privileged_activity
from src.logs.detectors.service_errors import detect_service_errors
from src.logs.detectors.suspicious_login import detect_suspicious_logins
from src.logs.filters import create_filters, filter_events
from src.logs.ip_history import (
    approve_ips,
    load_known_ips,
    revoke_ips,
    save_known_ips,
)
from src.logs.models import AnalysisResult
from src.logs.parser import SYSLOG_PATTERN, parse_log_line
from src.logs.reader import discover_log_files, read_log_lines
from src.logs.reporter import export_json, print_report, summarize


def register_logs_commands(commands) -> None:
    parser = commands.add_parser(
        "logs",
        help="Analyze Linux security logs",
        description="Linux Security Log Analyzer",
    )

    parser.add_argument(
        "--config",
        type=Path,
        help="YAML configuration file",
    )

    subcommands = parser.add_subparsers(
        dest="logs_command",
        required=True,
    )

    analyze = subcommands.add_parser(
        "analyze",
        help="Analyze Linux log files",
    )

    analyze.add_argument(
        "target",
        type=Path,
        help="Log file or directory to analyze",
    )

    analyze.add_argument(
        "--recursive",
        action="store_true",
        help="Search directories recursively",
    )

    analyze.add_argument(
        "--year",
        type=int,
        help="Year for traditional syslog entries",
    )

    analyze.add_argument(
        "--ip",
        dest="source_ip",
        help="Filter by source IP address",
    )

    analyze.add_argument(
        "--user",
        dest="username",
        help="Filter by username",
    )

    analyze.add_argument(
        "--event-type",
        action="append",
        dest="event_types",
        help="Filter by event type (repeatable)",
    )

    analyze.add_argument(
        "--from",
        dest="start_date",
        help="Start date in ISO 8601 format",
    )

    analyze.add_argument(
        "--to",
        dest="end_date",
        help="End date in ISO 8601 format",
    )

    analyze.add_argument(
        "--json",
        type=Path,
        dest="json_output",
        help="Save analysis report as JSON",
    )

    analyze.set_defaults(func=run_analysis)

    ips = subcommands.add_parser(
        "ips",
        help="Manage approved SSH source IPs",
    )

    ip_commands = ips.add_subparsers(
        dest="ip_command",
        required=True,
    )

    list_parser = ip_commands.add_parser(
        "list",
        help="List approved IP addresses",
    )
    list_parser.set_defaults(func=list_ips)

    init_parser = ip_commands.add_parser(
        "init",
        help="Create an empty approved IP baseline",
    )
    init_parser.set_defaults(func=initialize_ip_history)

    approve_parser = ip_commands.add_parser(
        "approve",
        help="Approve IP addresses",
    )
    approve_parser.add_argument(
        "addresses",
        nargs="+",
    )
    approve_parser.set_defaults(func=approve_ip_addresses)

    revoke_parser = ip_commands.add_parser(
        "revoke",
        help="Revoke approved IP addresses",
    )
    revoke_parser.add_argument(
        "addresses",
        nargs="+",
    )
    revoke_parser.set_defaults(func=revoke_ip_addresses)


def analyze_logs(
    args: argparse.Namespace,
    config,
) -> AnalysisResult:
    discovered = discover_log_files(
        args.target,
        recursive=args.recursive,
    )

    result = AnalysisResult(
        errors=dict(discovered.errors),
    )

    parsed_events = []

    for path in discovered.files:
        try:
            for line in read_log_lines(path):
                result.lines_processed += 1

                try:
                    event = parse_log_line(
                        line,
                        year=args.year,
                    )

                    if event is None:
                        result.lines_unparsed += 1
                        continue

                    if SYSLOG_PATTERN.match(line.content):
                        local_time = (
                            event.timestamp
                            .replace(tzinfo=None)
                            .replace(
                                tzinfo=ZoneInfo(config.timezone)
                            )
                        )

                        event = replace(
                            event,
                            timestamp=local_time.astimezone(
                                timezone.utc
                            ),
                        )

                    parsed_events.append(event)

                except (ValueError, OverflowError) as error:
                    result.lines_unparsed += 1
                    result.errors[
                        f"{path}:{line.line_number}"
                    ] = str(error)

            result.files_processed.append(str(path))

        except (OSError, ValueError, EOFError) as error:
            result.errors[str(path)] = str(error)

    filters = create_filters(
        source_ip=args.source_ip,
        username=args.username,
        event_types=args.event_types,
        start_date=args.start_date,
        end_date=args.end_date,
        timezone_name=config.timezone,
    )

    result.events = filter_events(
        parsed_events,
        filters,
    )

    known_ips = load_known_ips(
        Path(config.ip_history_path)
    )

    detectors = (
        detect_brute_force,
        detect_password_spraying,
        detect_distributed_attack,
        detect_suspicious_logins,
        detect_privileged_activity,
        detect_account_changes,
        detect_service_errors,
    )

    for detector in detectors:
        if detector is detect_suspicious_logins:
            findings = detector(
                result.events,
                config,
                known_ips=known_ips,
            )
        else:
            findings = detector(
                result.events,
                config,
            )

        result.findings.extend(findings)

    result.findings.sort(
        key=lambda finding: (
            finding.first_seen,
            finding.rule_id,
        )
    )

    result.statistics = summarize(
        result.events,
        result.findings,
    )

    return result


def run_analysis(args: argparse.Namespace) -> None:
    config = load_config(args.config)

    result = analyze_logs(
        args,
        config,
    )

    print_report(result)

    if args.json_output:
        export_json(
            result,
            args.json_output,
        )

        print(
            f"JSON report saved: {args.json_output}"
        )

    if result.errors:
        raise ValueError(
            f"Analysis completed with "
            f"{len(result.errors)} error(s)."
        )


def list_ips(args: argparse.Namespace) -> None:
    config = load_config(args.config)

    approved = load_known_ips(
        Path(config.ip_history_path)
    )

    if approved is None:
        print("No approved baseline exists.")
        return

    if not approved:
        print("Approved baseline is empty.")
        return

    for address in sorted(approved):
        print(address)


def initialize_ip_history(
    args: argparse.Namespace,
) -> None:
    config = load_config(args.config)
    path = Path(config.ip_history_path)

    if load_known_ips(path) is not None:
        raise ValueError(
            "Baseline already exists; refusing to overwrite."
        )

    save_known_ips(path, set())

    print(
        f"Empty approved baseline created: {path}"
    )


def approve_ip_addresses(
    args: argparse.Namespace,
) -> None:
    config = load_config(args.config)

    approved = approve_ips(
        Path(config.ip_history_path),
        args.addresses,
    )

    print(f"Approved IPs: {len(approved)}")


def revoke_ip_addresses(
    args: argparse.Namespace,
) -> None:
    config = load_config(args.config)

    approved = revoke_ips(
        Path(config.ip_history_path),
        args.addresses,
    )

    print(f"Approved IPs: {len(approved)}")
