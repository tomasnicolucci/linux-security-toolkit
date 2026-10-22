import argparse
from pathlib import Path

from src.logs.config import load_config
from src.statistics.analyzer import analyze_statistics
from src.statistics.reporter import export_json, print_report

MAX_TOP = 100


def register_stats_commands(commands) -> None:
    parser = commands.add_parser(
        "stats",
        help="Statistics from Linux security logs",
        description="Security Events Statistics",
    )

    parser.add_argument(
        "--config",
        type=Path,
        help="YAML configuration file (timezone)",
    )

    subcommands = parser.add_subparsers(
        dest="stats_command",
        required=True,
    )

    analyze = subcommands.add_parser(
        "analyze",
        help="Generate statistics from Linux log files",
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
        "--from",
        dest="start_date",
        help="Start of the period (ISO 8601; default: first event)",
    )

    analyze.add_argument(
        "--to",
        dest="end_date",
        help="End of the period (ISO 8601; default: last event)",
    )

    analyze.add_argument(
        "--by",
        choices=("hour", "day"),
        help="Trend granularity (default: hour up to 3 days, else day)",
    )

    analyze.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of IPs and users to list (default: 10)",
    )

    comparison = analyze.add_mutually_exclusive_group()

    comparison.add_argument(
        "--compare-previous",
        action="store_true",
        help="Compare with the previous period of equal duration",
    )

    comparison.add_argument(
        "--compare-with",
        nargs=2,
        metavar=("FROM", "TO"),
        help="Compare with an explicit period (ISO 8601)",
    )

    analyze.add_argument(
        "--json",
        type=Path,
        dest="json_output",
        help="Save the statistics as JSON",
    )

    analyze.set_defaults(func=run_analysis)


def run_analysis(args: argparse.Namespace) -> None:
    if not 1 <= args.top <= MAX_TOP:
        raise ValueError(f"--top must be between 1 and {MAX_TOP}.")

    config = load_config(args.config)

    result = analyze_statistics(
        args.target,
        config,
        recursive=args.recursive,
        year=args.year,
        start_text=args.start_date,
        end_text=args.end_date,
        granularity=args.by,
        top=args.top,
        compare_previous=args.compare_previous,
        compare_with=(
            tuple(args.compare_with) if args.compare_with else None
        ),
    )

    print_report(result)

    if args.json_output:
        export_json(result, args.json_output)

        print()
        print(f"JSON report saved: {args.json_output}")

    if result.errors:
        raise ValueError(
            f"Analysis completed with {len(result.errors)} error(s)."
        )