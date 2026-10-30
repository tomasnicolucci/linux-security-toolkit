import argparse
import re
from pathlib import Path

from src.integrity.baseline import (
    create_baseline_data,
    load_baseline,
    save_json,
)
from src.integrity.checker import compare_integrity
from src.integrity.hasher import calculate_sha256
from src.integrity.scanner import scan_target


DATA_DIR = Path("/app/data/integrity")


def baseline_path(name: str) -> Path:
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name):
        raise ValueError("Invalid baseline name.")

    return DATA_DIR / f"{name}.json"


def handle_hash(args: argparse.Namespace) -> None:
    path = Path(args.target)

    if path.is_symlink() or not path.is_file():
        raise ValueError("Target must be a regular file, not a symlink.")

    print(f"SHA-256: {calculate_sha256(path)}")
    print(f"File: {path}")


def handle_create(args: argparse.Namespace) -> None:
    target = Path(args.target).absolute()
    destination = baseline_path(args.name)

    if destination.exists():
        raise ValueError(
            "Baseline already exists. Use update to replace it."
        )

    result = scan_target(
        target,
        recursive=args.recursive,
        exclusions=args.exclude,
    )

    if result.errors:
        raise ValueError(
            f"Scan failed with {len(result.errors)} errors: "
            + "; ".join(
                f"{path}: {error}"
                for path, error in result.errors.items()
            )
        )

    data = create_baseline_data(
        target=target,
        recursive=args.recursive,
        exclusions=args.exclude,
        files=result.files,
    )

    save_json(destination, data)

    print(f"Baseline created: {args.name}")
    print(f"Files recorded: {len(result.files)}")


def handle_check(args: argparse.Namespace) -> None:
    baseline = load_baseline(baseline_path(args.name))

    target = Path(baseline["target"])

    if not target.exists():
        raise ValueError(f"Target is unavailable: {target}")

    result = scan_target(
        target,
        recursive=baseline["recursive"],
        exclusions=baseline["exclusions"],
    )

    report = compare_integrity(baseline["files"], result)
    summary = report.to_dict()["summary"]

    print("\nFile Integrity Check")
    print("--------------------")
    print(f"Baseline: {args.name}")
    print(f"Target: {target}")
    print(f"Unchanged: {summary['unchanged']}")
    print(f"Modified:  {summary['modified']}")
    print(f"Added:     {summary['added']}")
    print(f"Deleted:   {summary['deleted']}")
    print(f"Errors:    {summary['errors']}")

    for label, paths in (
        ("MODIFIED", report.modified),
        ("ADDED", report.added),
        ("DELETED", report.deleted),
    ):
        for path in paths:
            print(f"[{label}] {path}")

    for path, error in report.errors.items():
        print(f"[ERROR] {path}: {error}")

    if args.output:
        save_json(Path(args.output), report.to_dict())
        print(f"Report saved: {args.output}")

    if report.errors:
        raise SystemExit(2)

    if report.modified or report.added or report.deleted:
        raise SystemExit(1)


def handle_update(args: argparse.Namespace) -> None:
    destination = baseline_path(args.name)
    baseline = load_baseline(destination)
    target = Path(baseline["target"])

    result = scan_target(
        target,
        recursive=baseline["recursive"],
        exclusions=baseline["exclusions"],
    )

    if result.errors:
        raise ValueError("Cannot update baseline: scan contains errors.")

    data = create_baseline_data(
        target=target,
        recursive=baseline["recursive"],
        exclusions=baseline["exclusions"],
        files=result.files,
    )

    save_json(destination, data)

    print(f"Baseline updated: {args.name}")
    print(f"Files recorded: {len(result.files)}")


def register_integrity_commands(commands) -> None:
    parser = commands.add_parser(
        "integrity",
        help="File integrity tools",
    )

    subcommands = parser.add_subparsers(
        dest="integrity_command",
        required=True,
    )

    hash_parser = subcommands.add_parser("hash")
    hash_parser.add_argument("target")
    hash_parser.set_defaults(func=handle_hash)

    create_parser = subcommands.add_parser("create")
    create_parser.add_argument("target")
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument(
        "--recursive",
        action="store_true",
    )
    create_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
    )
    create_parser.set_defaults(func=handle_create)

    check_parser = subcommands.add_parser("check")
    check_parser.add_argument("--name", required=True)
    check_parser.add_argument("--output")
    check_parser.set_defaults(func=handle_check)

    update_parser = subcommands.add_parser("update")
    update_parser.add_argument("--name", required=True)
    update_parser.set_defaults(func=handle_update)
