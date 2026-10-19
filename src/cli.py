import argparse

from src.password.cli import register_password_commands
from src.url.cli import register_url_commands
from src.integrity.cli import register_integrity_commands
from src.logs.cli import register_logs_commands


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="security-toolkit",
        description="Linux Security Toolkit",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    register_password_commands(commands)
    register_url_commands(commands)
    register_integrity_commands(commands)
    register_logs_commands(commands)

    args = parser.parse_args()

    try:
        args.func(args)
    except (ValueError, OSError) as error:
        parser.exit(2, f"Error: {error}\n")


if __name__ == "__main__":
    main()
