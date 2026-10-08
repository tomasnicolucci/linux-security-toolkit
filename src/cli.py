import argparse

from src.password.generator import generate_password


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="security-toolkit",
        description="Linux Security Toolkit",
    )

    commands = parser.add_subparsers(dest="command", required=True)

    password_parser = commands.add_parser("password")
    password_commands = password_parser.add_subparsers(
        dest="password_command",
        required=True,
    )

    generate_parser = password_commands.add_parser("generate")

    generate_parser.add_argument(
        "--length",
        type=int,
        default=16,
    )

    args = parser.parse_args()

    if args.command == "password" and args.password_command == "generate":
        password = generate_password(length=args.length)
        print(password)


if __name__ == "__main__":
    main()