
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from src.logs.models import EventType, SecurityEvent


@dataclass(frozen=True)
class EventFilters:
    source_ip: str | None = None
    username: str | None = None
    event_types: frozenset[EventType] | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None


def normalize_filter_ip(value: str | None) -> str | None:
    if value is None:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError(
            f"Invalid IP address: {value}"
        ) from error


def parse_event_types(
    values: list[str] | None,
) -> frozenset[EventType] | None:
    if not values:
        return None

    parsed = set()

    for value in values:
        try:
            parsed.add(EventType(value.lower()))
        except ValueError as error:
            available = ", ".join(
                event.value for event in EventType
            )

            raise ValueError(
                f"Unknown event type: {value}. "
                f"Available types: {available}"
            ) from error

    return frozenset(parsed)


def parse_filter_date(
    value: str | None,
    timezone_name: str,
) -> datetime | None:
    if value is None:
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            f"Invalid date: {value}. "
            "Use ISO 8601 format."
        ) from error

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=ZoneInfo(timezone_name)
        )

    return parsed.astimezone(timezone.utc)


def create_filters(
    source_ip: str | None = None,
    username: str | None = None,
    event_types: list[str] | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    timezone_name: str = "UTC",
) -> EventFilters:
    parsed_start = parse_filter_date(
        start_date,
        timezone_name,
    )

    parsed_end = parse_filter_date(
        end_date,
        timezone_name,
    )

    if (
        parsed_start is not None
        and parsed_end is not None
        and parsed_start > parsed_end
    ):
        raise ValueError(
            "Start date cannot be later than end date."
        )

    if username is not None and not username.strip():
        raise ValueError("Username cannot be empty.")

    return EventFilters(
        source_ip=normalize_filter_ip(source_ip),
        username=username,
        event_types=parse_event_types(event_types),
        start_date=parsed_start,
        end_date=parsed_end,
    )


def filter_events(
    events: list[SecurityEvent],
    filters: EventFilters,
) -> list[SecurityEvent]:
    filtered = []

    for event in events:
        if (
            filters.source_ip is not None
            and event.source_ip != filters.source_ip
        ):
            continue

        if (
            filters.username is not None
            and event.username != filters.username
        ):
            continue

        if (
            filters.event_types is not None
            and event.event_type not in filters.event_types
        ):
            continue

        if (
            filters.start_date is not None
            and event.timestamp < filters.start_date
        ):
            continue

        if (
            filters.end_date is not None
            and event.timestamp > filters.end_date
        ):
            continue

        filtered.append(event)

    return filtered
