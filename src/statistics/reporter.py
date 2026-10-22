import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from src.statistics.metrics import METRIC_LABELS
from src.statistics.models import (
    Comparison,
    PeriodStats,
    RankedItem,
    StatsResult,
    Trend,
)

BAR_WIDTH = 30
MAX_ERRORS_SHOWN = 10


def printable(value: object) -> str:
    """Replace control characters in text that comes from logs."""
    return "".join(
        character if character.isprintable() else "?"
        for character in str(value)
    )


def format_range(stats: PeriodStats) -> str:
    return f"{stats.start.isoformat()} -> {stats.end.isoformat()}"


def format_change(
    difference: int,
    percent: float | None,
    current: int,
) -> str:
    if difference == 0:
        return "no change"

    if percent is None and current > 0:
        return f"{difference:+d} (new)"

    return f"{difference:+d} ({percent:+.1f}%)"


def print_ranking(
    title: str,
    label: str,
    items: list[RankedItem],
) -> None:
    print()
    print(title)

    if not items:
        print("  (none)")
        return

    width = max(len(printable(item.name)) for item in items)
    width = max(width, len(label))

    print(
        f"  {label.ljust(width)}  {'Events':>7}  "
        f"{'Failed':>7}  {'Success':>7}"
    )

    for item in items:
        print(
            f"  {printable(item.name).ljust(width)}  "
            f"{item.events:>7}  {item.failed:>7}  {item.success:>7}"
        )


def print_summary(stats: PeriodStats) -> None:
    print()
    print("Summary")

    for name, label in METRIC_LABELS.items():
        print(f"  {label.ljust(32)} {stats.metrics[name]:>8}")

    rate = (
        f"{stats.ssh_success_rate:.1f}%"
        if stats.ssh_success_rate is not None
        else "n/a"
    )

    print(f"  {'SSH login success rate'.ljust(32)} {rate:>8}")

    print()
    print("Events by type")

    if not stats.by_event_type:
        print("  (none)")

    for name, count in stats.by_event_type.items():
        print(f"  {name.ljust(32)} {count:>8}")


def print_trend(trend: Trend) -> None:
    print()

    peak = (
        f"{trend.peak_label} ({trend.peak_events} events)"
        if trend.peak_label
        else "none"
    )

    print(f"Trend by {trend.granularity} | peak: {peak}")

    for bucket in trend.buckets:
        length = (
            max(1, round(bucket.events / trend.peak_events * BAR_WIDTH))
            if bucket.events
            else 0
        )

        print(
            f"  {bucket.label} | {('#' * length).ljust(BAR_WIDTH)} "
            f"{bucket.events} (failed {bucket.failed})"
        )


def print_appeared(
    title: str,
    items: list[RankedItem],
    total: int,
) -> None:
    print(f"  {title}: {total}")

    for item in items:
        plural = "event" if item.events == 1 else "events"

        print(
            f"    {printable(item.name)} "
            f"({item.events} {plural}, {item.failed} failed)"
        )


def print_comparison(comparison: Comparison) -> None:
    print()
    print(
        "Comparison with period "
        f"{format_range(comparison.previous)}"
    )

    print(
        f"  {'Metric'.ljust(32)} {'Current':>8} {'Previous':>9}  Change"
    )

    for change in comparison.changes:
        print(
            f"  {METRIC_LABELS[change.name].ljust(32)} "
            f"{change.current:>8} {change.previous:>9}  "
            + format_change(
                change.difference,
                change.change_percent,
                change.current,
            )
        )

    print()
    print_appeared(
        "New source IPs",
        comparison.new_ips,
        comparison.new_ips_total,
    )
    print_appeared(
        "Source IPs no longer seen",
        comparison.gone_ips,
        comparison.gone_ips_total,
    )
    print_appeared(
        "New users",
        comparison.new_users,
        comparison.new_users_total,
    )
    print_appeared(
        "Users no longer seen",
        comparison.gone_users,
        comparison.gone_users_total,
    )


def print_report(result: StatsResult) -> None:
    print(
        f"Period: {format_range(result.period)} "
        f"({result.timezone})"
    )

    print(
        f"Files: {len(result.files_processed)} | "
        f"Lines: {result.lines_processed} | "
        f"Events loaded: {result.events_loaded} | "
        f"Events in period: {result.period.metrics['total_events']}"
    )

    if result.lines_unparsed:
        print(f"Unparsed lines: {result.lines_unparsed}")

    errors = list(result.errors.items())

    for source, error in errors[:MAX_ERRORS_SHOWN]:
        print(f"[ERROR] {printable(source)}: {printable(error)}")

    if len(errors) > MAX_ERRORS_SHOWN:
        print(
            f"[ERROR] ... and {len(errors) - MAX_ERRORS_SHOWN} "
            "more error(s)"
        )

    for warning in result.warnings:
        print(f"[WARNING] {warning}")

    print_summary(result.period)

    print_ranking("Top source IPs", "IP", result.period.top_ips)
    print_ranking("Top users", "User", result.period.top_users)

    print_trend(result.trend)

    if result.comparison is not None:
        print_comparison(result.comparison)


def serialize(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()

    raise TypeError(f"Cannot serialize {type(value).__name__}")


def result_to_dict(result: StatsResult) -> dict[str, Any]:
    return asdict(result)


def export_json(result: StatsResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            result_to_dict(result),
            indent=2,
            ensure_ascii=False,
            default=serialize,
        )
        + "\n",
        encoding="utf-8",
    )