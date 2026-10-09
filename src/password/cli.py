
import argparse
import getpass
import sys

from src.password.generator import generate_password
from src.password.analyzer import analyze_password


def ask_length(default: int = 16) -> int:
    while True:
        value = input(f"Password length [{default}]: ").strip()

        if not value:
            return default

        try:
            length = int(value)

            if length >= 8:
                return length

            print("Password length must be at least 8 characters.")
        except ValueError:
            print("Please enter a valid number.")


def ask_boolean(question: str, default: bool = True) -> bool:
    options = "Y/n" if default else "y/N"

    while True:
        value = input(f"{question} [{options}]: ").strip().lower()

        if not value:
            return default

        if value in ("y", "yes"):
            return True

        if value in ("n", "no"):
            return False

        print("Please enter y or n.")


def handle_generate(args: argparse.Namespace) -> None:
    has_options = any(
        value is not None
        for value in (
            args.length,
            args.uppercase,
            args.lowercase,
            args.digits,
            args.symbols,
        )
    )

    if has_options:
        length = args.length if args.length is not None else 16
        uppercase = args.uppercase if args.uppercase is not None else True
        lowercase = args.lowercase if args.lowercase is not None else True
        digits = args.digits if args.digits is not None else True
        symbols = args.symbols if args.symbols is not None else True
    else:
        length = ask_length()
        uppercase = ask_boolean("Include uppercase letters?")
        lowercase = ask_boolean("Include lowercase letters?")
        digits = ask_boolean("Include numbers?")
        symbols = ask_boolean("Include symbols?")

    try:
        password = generate_password(
            length=length,
            use_uppercase=uppercase,
            use_lowercase=lowercase,
            use_digits=digits,
            use_symbols=symbols,
        )
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error

    print(f"\nGenerated password:\n{password}")


def handle_analyze(args: argparse.Namespace) -> None:
    if not sys.stdin.isatty():
        raise SystemExit(
            "Error: Interactive terminal required for password analysis."
        )

    try:
        password = getpass.getpass("Enter password to analyze: ")
    except (EOFError, KeyboardInterrupt):
        raise SystemExit("\nPassword analysis cancelled.")

    try:
        result = analyze_password(password)
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error

    print("\nPassword Analysis")
    print("-----------------")
    print(f"Length: {result.length}")
    print(f"Score: {result.score}/4")
    print(f"Strength: {result.strength}")
    print(f"Estimated guesses: {result.guesses:,}")
    print(f"Estimated crack time: {result.crack_time}")

    if result.warnings:
        print("\nWarnings:")
        for warning in result.warnings:
            print(f"- {warning}")

    if result.recommendations:
        print("\nRecommendations:")
        for recommendation in result.recommendations:
            print(f"- {recommendation}")
    else:
        print("\nNo obvious weaknesses detected.")


def register_password_commands(commands) -> None:
    password_parser = commands.add_parser(
        "password",
        help="Password security tools",
    )

    password_commands = password_parser.add_subparsers(
        dest="password_command",
        required=True,
    )

    generate_parser = password_commands.add_parser(
        "generate",
        help="Generate a secure password",
    )

    generate_parser.add_argument("--length", type=int)

    generate_parser.add_argument(
        "--uppercase",
        action=argparse.BooleanOptionalAction,
        default=None,
    )

    generate_parser.add_argument(
        "--lowercase",
        action=argparse.BooleanOptionalAction,
        default=None,
    )

    generate_parser.add_argument(
        "--digits",
        action=argparse.BooleanOptionalAction,
        default=None,
    )

    generate_parser.add_argument(
        "--symbols",
        action=argparse.BooleanOptionalAction,
        default=None,
    )

    generate_parser.set_defaults(func=handle_generate)

    analyze_parser = password_commands.add_parser(
        "analyze",
        help="Analyze password strength",
    )

    analyze_parser.set_defaults(func=handle_analyze)
