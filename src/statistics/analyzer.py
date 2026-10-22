from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from src.logs.config import LogAnalyzerConfig
from src.statistics.comparison import compare
from src.statistics.loader import load_events
from src.statistics.metrics import (
    build_stats,
    build_trend,
    choose_granularity,
    collect,
)
from src.statistics.models import StatsResult
from src.statistics.periods import (
    Period,
    events_in,
    explicit_period,
    previous_period,
    resolve_period,
)


def coverage_warnings(
    label: str,
    period: Period,
    earliest: datetime,
    event_count: int,
    tz: ZoneInfo,
) -> list[str]:
    warnings = []

    if event_count == 0:
        warnings.append(f"No events found in the {label} period.")

    if earliest > period.start:
        warnings.append(
            f"The provided logs start at "
            f"{earliest.astimezone(tz).isoformat()}, after the start "
            f"of the {label} period "
            f"({period.start.astimezone(tz).isoformat()}); "
            "its data may be incomplete if older logs were not "
            "provided."
        )

    return warnings


def analyze_statistics(
    target: Path,
    config: LogAnalyzerConfig,
    recursive: bool = False,
    year: int | None = None,
    start_text: str | None = None,
    end_text: str | None = None,
    granularity: str | None = None,
    top: int = 10,
    compare_previous: bool = False,
    compare_with: tuple[str, str] | None = None,
) -> StatsResult:
    tz = ZoneInfo(config.timezone)

    loaded = load_events(target, recursive, year, tz)

    if not loaded.events:
        raise ValueError(
            "No events could be parsed from the provided logs"
            + (
                f" ({len(loaded.errors)} read error(s))."
                if loaded.errors
                else "."
            )
        )

    earliest = min(event.timestamp for event in loaded.events)

    period = resolve_period(
        loaded.events,
        start_text,
        end_text,
        config.timezone,
    )

    current = collect(period, events_in(loaded.events, period))

    warnings = coverage_warnings(
        "analyzed",
        period,
        earliest,
        len(current.events),
        tz,
    )

    trend = build_trend(
        current,
        choose_granularity(period, granularity),
        tz,
    )

    comparison = None

    if compare_previous or compare_with:
        if compare_with:
            other = explicit_period(
                compare_with[0],
                compare_with[1],
                config.timezone,
            )

            if (
                other.start < period.end_exclusive
                and period.start < other.end_exclusive
            ):
                warnings.append(
                    "The comparison period overlaps the analyzed "
                    "period; events in the overlap are counted in "
                    "both."
                )
        else:
            other = previous_period(period)

        previous = collect(other, events_in(loaded.events, other))

        warnings.extend(
            coverage_warnings(
                "comparison",
                other,
                earliest,
                len(previous.events),
                tz,
            )
        )

        comparison = compare(
            current,
            previous,
            build_stats(previous, top, tz),
            top,
        )

    return StatsResult(
        timezone=config.timezone,
        period=build_stats(current, top, tz),
        trend=trend,
        comparison=comparison,
        files_processed=loaded.files_processed,
        lines_processed=loaded.lines_processed,
        lines_unparsed=loaded.lines_unparsed,
        events_loaded=len(loaded.events),
        errors=loaded.errors,
        warnings=warnings,
    )