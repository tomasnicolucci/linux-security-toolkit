import argparse
from pathlib import Path

from src.encryption.format import EncryptionError
from src.encryption.keys import (
    KeySource,
    generate_key_file,
    load_key_file,
    load_password_file,
    prompt_password,
)
from src.encryption.reporter import (
    print_info,
    print_result,
    print_summary,
)
from src.encryption.service import (
    collect_jobs,
    inspect_file,
    run_job,
)


def add_key_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--key-file",
        type=Path,
        help="Use a key file created with 'encryption keygen'",
    )

    group.add_argument(
        "--password-file",
        type=Path,
        help="Read the password from a file (default: ask for it)",
    )


def register_encryption_commands(commands) -> None:
    parser = commands.add_parser(
        "encryption",
        help="Encrypt and decrypt files",
        description="File Encryption",
    )

    subcommands = parser.add_subparsers(
        dest="encryption_command",
        required=True,
    )

    keygen = subcommands.add_parser(
        "keygen",
        help="Create a random key file",
    )

    keygen.add_argument("path", type=Path, help="Key file to create")

    keygen.add_argument(
        "--force",
        action="store_true",
        help="Replace the key file if it exists",
    )

    keygen.set_defaults(func=run_keygen)

    for name, helptext in (
        ("encrypt", "Encrypt files"),
        ("decrypt", "Decrypt files"),
    ):
        command = subcommands.add_parser(name, help=helptext)

        command.add_argument(
            "files",
            nargs="+",
            type=Path,
            help="Files or directories",
        )

        command.add_argument(
            "--recursive",
            action="store_true",
            help="Process the files inside directories",
        )

        command.add_argument(
            "-o",
            "--output",
            type=Path,
            help="Output file (single input file only)",
        )

        command.add_argument(
            "--force",
            action="store_true",
            help="Replace existing output files",
        )

        add_key_options(command)

        command.set_defaults(func=run_process, action=name)

    info = subcommands.add_parser(
        "info",
        help="Show the header of an encrypted file (no key needed)",
    )

    info.add_argument("file", type=Path)
    info.set_defaults(func=run_info)


def run_keygen(args: argparse.Namespace) -> None:
    generate_key_file(args.path, args.force)

    print(f"Key file created: {args.path} (32 random bytes, mode 600)")
    print(
        "Keep a secure backup: files encrypted with it cannot be "
        "recovered without it."
    )


def resolve_key_source(
    args: argparse.Namespace,
    confirm: bool,
) -> KeySource:
    if args.key_file:
        return load_key_file(args.key_file)

    if args.password_file:
        return load_password_file(args.password_file, confirm)

    return prompt_password(confirm)


def run_process(args: argparse.Namespace) -> None:
    in_use = frozenset(
        path.resolve()
        for path in (args.key_file, args.password_file)
        if path is not None
    )

    jobs = collect_jobs(
        args.files,
        args.action,
        args.recursive,
        args.output,
        in_use,
    )

    if not jobs:
        raise EncryptionError("No files to process.")

    key = None

    if any(not job.error for job in jobs):
        key = resolve_key_source(args, args.action == "encrypt")

        for warning in key.warnings:
            print(f"[WARNING] {warning}")

    results = []

    for job in jobs:
        result = run_job(args.action, job, key, args.force)
        print_result(result)
        results.append(result)

    print_summary(results)

    failed = sum(not result.success for result in results)

    if failed:
        raise ValueError(f"{failed} file(s) could not be processed.")


def run_info(args: argparse.Namespace) -> None:
    print_info(inspect_file(args.file))