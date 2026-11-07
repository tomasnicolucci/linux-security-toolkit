import argparse
from pathlib import Path

from src.audit import comparison as comparison_module
from src.audit.adapters import AuditOptions
from src.audit.models import (
    OVERALL_INCONCLUSIVE,
    SEVERITY_RANK,
    AuditError,
)
from src.audit.render import render_console, write_reports
from src.audit.runner import (
    parse_module_list,
    run_audit,
    select_modules,
)

DEFAULT_OUTPUT_DIR = Path("data/audit")
FORMATS = {
    "md": ("md",),
    "json": ("json",),
    "both": ("md", "json"),
    "none": (),
}


def severity_type(value: str) -> str:
    level = value.upper()

    if level not in SEVERITY_RANK:
        raise argparse.ArgumentTypeError(
            "must be LOW, MEDIUM, HIGH or CRITICAL"
        )

    return level


def register_audit_commands(commands) -> None:
    parser = commands.add_parser(
        "audit",
        help="Run several modules and produce one consolidated report",
        description="Consolidated security audit",
    )

    subcommands = parser.add_subparsers(
        dest="audit_command",
        required=True,
    )

    run = subcommands.add_parser(
        "run",
        help="Audit users, network, file integrity and logs",
    )

    run.add_argument(
        "--only",
        help="Comma-separated modules to run: users, network, integrity, logs",
    )
    run.add_argument(
        "--skip",
        help="Comma-separated modules to leave out",
    )
    run.add_argument(
        "--root",
        type=Path,
        default=Path("/"),
        help="Root of the audited system for the users module "
        "(for example /host in Docker; default: /)",
    )
    run.add_argument(
        "--logs",
        type=Path,
        help="Authentication log file or directory (enables the logs module)",
    )
    run.add_argument(
        "--recursive",
        action="store_true",
        help="Search the logs directory recursively",
    )
    run.add_argument(
        "--year",
        type=int,
        help="Year of traditional syslog entries",
    )
    run.add_argument(
        "--config",
        type=Path,
        help="YAML configuration file of the log analyzer",
    )
    run.add_argument(
        "--integrity-dir",
        type=Path,
        help="Folder with the integrity baselines",
    )
    run.add_argument(
        "--network-baseline",
        type=Path,
        help="Network baseline file (default: data/network/baseline.json)",
    )
    run.add_argument(
        "--proc-root",
        type=Path,
        default=Path("/proc"),
        help="Alternative /proc directory (for tests)",
    )
    run.add_argument(
        "--no-permission-checks",
        action="store_true",
        help="Skip the file permission checks of the users module",
    )
    run.add_argument(
        "--previous",
        help="Previous JSON report to compare with, or 'latest'",
    )
    run.add_argument(
        "--format",
        choices=tuple(FORMATS),
        default="both",
        help="Report files to save (default: both)",
    )
    run.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Where to save the reports (default: {DEFAULT_OUTPUT_DIR})",
    )
    run.add_argument(
        "--fail-on",
        type=severity_type,
        help="Exit with status 1 when a finding reaches this level",
    )

    run.set_defaults(func=run_command)


def run_command(args: argparse.Namespace) -> None:
    modules = select_modules(
        parse_module_list(args.only, "--only"),
        parse_module_list(args.skip, "--skip"),
        args.logs is not None,
    )

    previous_path = None

    if args.previous == "latest":
        previous_path = comparison_module.find_latest(args.output_dir)
    elif args.previous:
        previous_path = Path(args.previous)

    previous = (
        comparison_module.load_previous(previous_path)
        if previous_path
        else None
    )

    options = AuditOptions(
        root=args.root,
        logs=args.logs,
        recursive=args.recursive,
        year=args.year,
        config=args.config,
        integrity_dir=args.integrity_dir,
        network_baseline=args.network_baseline,
        proc_root=args.proc_root,
        no_permission_checks=args.no_permission_checks,
    )

    report = run_audit(modules, options)

    if previous is not None:
        report.comparison = comparison_module.compare(
            report.findings,
            report.modules,
            previous,
            previous_path.name,
        )

    # The files are saved first, so closing the console (for example a
    # pipe to "head") never loses the report.
    saved = write_reports(report, args.output_dir, FORMATS[args.format])

    print(render_console(report))

    if args.previous == "latest" and previous_path is None:
        print("\nNo previous report was found to compare with.")

    if saved:
        print("\nReports saved:")

        for path in saved:
            print(f"  {path}")

    if report.status == OVERALL_INCONCLUSIVE:
        raise AuditError("No module could be audited.")

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]

        if any(SEVERITY_RANK[item.severity] >= threshold for item in report.findings):
            raise SystemExit(1)