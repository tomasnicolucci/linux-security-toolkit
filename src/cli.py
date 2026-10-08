import argparse

from src.password.cli import register_password_commands


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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()