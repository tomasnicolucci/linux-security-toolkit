import argparse
from pathlib import Path

from src.ip.analyzer import analyze_addresses
from src.ip.reporter import export_json, print_report, summarize
from src.ip.sources import (
    build_entries,
    read_address_file,
    read_report_entries,
)
from src.logs.config import load_config
from src.logs.ip_history import load_known_ips

MAX_TIMEOUT = 60.0


def register_ip_commands(commands) -> None:
    parser = commands.add_parser(
        "ip",
        help="Analyze IP addresses",
        description="IP Address Analyzer",
    )

    parser.add_argument(
        "--config",
        type=Path,
        help=(
            "YAML configuration file (provides the path of the "
            "approved IP baseline shared with the log analyzer)"
        ),
    )

    subcommands = parser.add_subparsers(
        dest="ip_command",
        required=True,
    )

    analyze = subcommands.add_parser(
        "analyze",
        help="Analyze one or more IP addresses",
    )

    analyze.add_argument(
        "addresses",
        nargs="*",
        help="IPv4 or IPv6 addresses to analyze",
    )

    analyze.add_argument(
        "--file",
        help=(
            "File with one address per line "
            "(use '-' to read from standard input)"
        ),
    )

    analyze.add_argument(
        "--from-report",
        type=Path,
        dest="report",
        help=(
            "JSON report exported by 'logs analyze --json'; "
            "analyzes the IPs mentioned in its findings"
        ),
    )

    analyze.add_argument(
        "--resolve",
        action="store_true",
        help="Look up the reverse DNS (PTR) record",
    )

    analyze.add_argument(
        "--rdap",
        action="store_true",
        help="Query RDAP for network ownership information",
    )

    analyze.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for each network lookup (default: 5)",
    )

    analyze.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of addresses to analyze (default: 50)",
    )

    analyze.add_argument(
        "--json",
        type=Path,
        dest="json_output",
        help="Save the analysis as JSON",
    )

    analyze.set_defaults(func=run_analysis)


def run_analysis(args: argparse.Namespace) -> None:
    if not (args.addresses or args.file or args.report):
        raise ValueError(
            "Provide at least one address, --file or --from-report."
        )

    if not 0 < args.timeout <= MAX_TIMEOUT:
        raise ValueError(
            f"--timeout must be between 0 and {MAX_TIMEOUT:g} seconds."
        )

    if args.limit <= 0:
        raise ValueError("--limit must be greater than zero.")

    config = load_config(args.config)

    file_addresses = (
        read_address_file(args.file) if args.file else []
    )

    report_entries = (
        read_report_entries(args.report) if args.report else []
    )

    entries, warnings = build_entries(
        args.addresses,
        file_addresses,
        report_entries,
        args.limit,
    )

    baseline_path = Path(config.ip_history_path)
    known_ips = load_known_ips(baseline_path)

    analyses = analyze_addresses(
        entries,
        known_ips,
        resolve=args.resolve,
        rdap=args.rdap,
        timeout=args.timeout,
    )

    if known_ips is None and any(
        analysis.classification is not None
        and analysis.classification.is_global
        for analysis in analyses
    ):
        warnings.append(
            f"No approved IP baseline found at {baseline_path}; "
            "approval status is unavailable."
        )

    print_report(analyses, warnings)

    if args.json_output:
        export_json(analyses, warnings, args.json_output)

        print()
        print(f"JSON report saved: {args.json_output}")

    invalid = summarize(analyses)["invalid"]

    if invalid:
        raise ValueError(
            f"{invalid} invalid address(es) found."
        )