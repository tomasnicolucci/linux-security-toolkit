import argparse
import shutil
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("user_auditor.sh")

VALUE_OPTIONS = (
    ("root", "--root"),
    ("min_severity", "--min-severity"),
    ("fail_on", "--fail-on"),
    ("max_password_age", "--max-password-age"),
    ("inactive_days", "--inactive-days"),
    ("json", "--json"),
)

FLAG_OPTIONS = (
    ("show_hashes", "--show-hashes"),
    ("all_accounts", "--all-accounts"),
    ("no_permission_checks", "--no-permission-checks"),
    ("check_homes", "--check-homes"),
    ("check_activity", "--check-activity"),
    ("no_color", "--no-color"),
)


def register_users_commands(commands) -> None:
    parser = commands.add_parser(
        "users",
        help="Audit user accounts and privileges",
        description="Linux User Auditor",
    )

    subcommands = parser.add_subparsers(
        dest="users_command",
        required=True,
    )

    audit = subcommands.add_parser(
        "audit",
        help="Run the user auditor (see docs/linux-user-auditor.md)",
    )

    audit.add_argument("--root", help="Audit the file tree under this path")
    audit.add_argument("--min-severity", help="LOW, MEDIUM, HIGH or CRITICAL")
    audit.add_argument("--fail-on", help="Exit with status 1 at this level")
    audit.add_argument("--max-password-age", help="Days")
    audit.add_argument("--inactive-days", help="Days")
    audit.add_argument("--json", help="Save the audit as JSON")
    audit.add_argument("--show-hashes", action="store_true", help="Show password hashes (sensitive)")
    audit.add_argument("--all-accounts", action="store_true", help="List every account")
    audit.add_argument("--no-permission-checks", action="store_true", help="Skip file permission checks")
    audit.add_argument("--check-homes", action="store_true", help="Check home directories")
    audit.add_argument("--check-activity", action="store_true", help="Check login activity")
    audit.add_argument("--no-color", action="store_true", help="Disable colors")

    audit.set_defaults(func=run_users_audit)


def build_command(bash: str, args: argparse.Namespace) -> list[str]:
    command = [bash, str(SCRIPT)]

    for name, option in VALUE_OPTIONS:
        value = getattr(args, name)

        if value is not None:
            command += [option, str(value)]

    for name, option in FLAG_OPTIONS:
        if getattr(args, name):
            command.append(option)

    return command


def run_users_audit(args: argparse.Namespace) -> None:
    bash = shutil.which("bash")

    if bash is None:
        raise ValueError("bash is not available on this system.")

    if not SCRIPT.is_file():
        raise ValueError(f"User auditor script not found: {SCRIPT}")

    # The script prints its own report and validates its own options.
    completed = subprocess.run(build_command(bash, args))

    if completed.returncode:
        raise SystemExit(completed.returncode)