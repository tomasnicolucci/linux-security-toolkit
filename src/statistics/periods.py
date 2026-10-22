from dataclasses import dataclass
from datetime import datetime, timedelta

from src.logs.filters import parse_filter_date
from src.logs.models import SecurityEvent

SECOND = timedelta(seconds=1)


@dataclass(frozen=True)
class Period:
    """
    Half-open time range [start, end_exclusive).

    The end shown to users is inclusive, like the --to filter of the
    log analyzer, so it is end_exclusive minus one second.
    """

    start: datetime
    end_exclusive: datetime

    @property
    def duration(self) -> timedelta:
        return self.end_exclusive - self.start

    @property
    def end(self) -> datetime:
        return self.end_exclusive - SECOND

    def contains(self, timestamp: datetime) -> bool:
        return self.start <= timestamp < self.end_exclusive


def build_period(start: datetime, end: datetime) -> Period:
    """Create a period from an inclusive start and end."""
    period = Period(start, end + SECOND)

    if period.start >= period.end_exclusive:
        raise ValueError("Start date cannot be later than end date.")

    return period


def resolve_period(
    events: list[SecurityEvent],
    start_text: str | None,
    end_text: str | None,
    timezone_name: str,
) -> Period:
    """
    Use the requested range, completing missing limits with the
    first and last event found in the logs.
    """
    timestamps = [event.timestamp for event in events]

    start = parse_filter_date(start_text, timezone_name)
    end = parse_filter_date(end_text, timezone_name)

    return build_period(
        start if start is not None else min(timestamps),
        end if end is not None else max(timestamps),
    )


def explicit_period(
    start_text: str,
    end_text: str,
    timezone_name: str,
) -> Period:
    return build_period(
        parse_filter_date(start_text, timezone_name),
        parse_filter_date(end_text, timezone_name),
    )


def previous_period(period: Period) -> Period:
    """The period of equal duration that ends where this one starts."""
    return Period(
        period.start - period.duration,
        period.start,
    )


def events_in(
    events: list[SecurityEvent],
    period: Period,
) -> list[SecurityEvent]:
    return [
        event
        for event in events
        if period.contains(event.timestamp)
    ]