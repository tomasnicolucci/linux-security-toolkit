import argparse

from src.url.analyzer import analyze_url


def handle_analyze(args: argparse.Namespace) -> None:
    try:
        url = args.url

        if url is None:
            url = input("Enter URL: ").strip()

        result = analyze_url(url)

    except (ValueError, EOFError) as error:
        raise SystemExit(f"Error: {error}") from error

    except KeyboardInterrupt:
        raise SystemExit("\nAnalysis cancelled.")

    print("\nURL Security Analysis")
    print("---------------------")
    print(f"URL: {result.url}")
    print(f"Hostname: {result.hostname}")
    print(f"Registered domain: {result.registered_domain or 'N/A'}")
    print(f"Risk score: {result.risk_score}/100")
    print(f"Risk level: {result.risk_level}")

    if not result.findings:
        print("\nNo suspicious indicators detected.")
        print("This does not guarantee that the URL is safe.")
        return

    print("\nIndicators:")

    for finding in result.findings:
        print(f"\n[{finding.severity}] {finding.code}")
        print(f"  {finding.message}")
        print(f"  Recommendation: {finding.recommendation}")


def register_url_commands(commands) -> None:
    url_parser = commands.add_parser(
        "url",
        help="URL security analysis tools",
    )

    url_commands = url_parser.add_subparsers(
        dest="url_command",
        required=True,
    )

    analyze_parser = url_commands.add_parser(
        "analyze",
        help="Analyze a URL for suspicious indicators",
    )

    analyze_parser.add_argument(
        "url",
        nargs="?",
        help="URL to analyze (interactive if omitted)",
    )

    analyze_parser.set_defaults(func=handle_analyze)
