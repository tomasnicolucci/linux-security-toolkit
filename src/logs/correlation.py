
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Hashable, TypeVar

from src.logs.models import EventType, SecurityEvent


GroupKey = TypeVar("GroupKey", bound=Hashable)

SSH_FAILURE_TYPES = frozenset({
    EventType.SSH_LOGIN_FAILED,
    EventType.SSH_INVALID_USER,
})


def sort_events(
    events: list[SecurityEvent],
) -> list[SecurityEvent]:
    return sorted(
        events,
        key=lambda event: (
            event.timestamp,
            event.source,
            event.line_number,
        ),
    )


def group_events(
    events: list[SecurityEvent],
    key_function: Callable[[SecurityEvent], GroupKey | None],
) -> dict[GroupKey, list[SecurityEvent]]:
    groups = defaultdict(list)

    for event in events:
        key = key_function(event)

        if key is not None:
            groups[key].append(event)

    return {
        key: sort_events(group)
        for key, group in groups.items()
    }


def group_by_ip(
    events: list[SecurityEvent],
) -> dict[str, list[SecurityEvent]]:
    return group_events(
        events,
        lambda event: event.source_ip,
    )


def group_by_user(
    events: list[SecurityEvent],
) -> dict[str, list[SecurityEvent]]:
    return group_events(
        events,
        lambda event: event.username,
    )


def group_by_ip_and_user(
    events: list[SecurityEvent],
) -> dict[tuple[str, str], list[SecurityEvent]]:
    return group_events(
        events,
        lambda event: (
            (event.source_ip, event.username)
            if event.source_ip and event.username
            else None
        ),
    )


def deduplicate_ssh_failures(
    events: list[SecurityEvent],
) -> list[SecurityEvent]:
    """
    Remove likely duplicate SSH failure records.

    SSH_INVALID_USER and SSH_LOGIN_FAILED can describe
    the same authentication activity.

    Only events with matching source IP, username and
    process ID, but different event types, are considered
    duplicates within a two-second interval.

    Repeated failures of the same type are preserved.
    """
    ordered = sort_events([
        event
        for event in events
        if event.event_type in SSH_FAILURE_TYPES
    ])

    unique = []

    for event in ordered:
        duplicate = False

        for previous in reversed(unique):
            difference = (
                event.timestamp - previous.timestamp
            ).total_seconds()

            if difference > 2:
                break

            if (
                event.source_ip is not None
                and event.username is not None
                and event.process_id is not None
                and event.source_ip == previous.source_ip
                and event.username == previous.username
                and event.process_id == previous.process_id
                and event.event_type != previous.event_type
                and 0 <= difference <= 2
            ):
                duplicate = True
                break

        if not duplicate:
            unique.append(event)

    return unique


def find_event_windows(
    events: list[SecurityEvent],
    window_minutes: int,
    threshold: int,
    distinct_key: Callable[
        [SecurityEvent], Hashable
    ] | None = None,
) -> list[list[SecurityEvent]]:
    """
    Find sequences that meet a threshold within a
    sliding time window.

    If distinct_key is provided, count distinct values
    instead of total events.

    Consecutive qualifying windows are consolidated
    into one finding sequence.
    """
    if window_minutes <= 0:
        raise ValueError(
            "Window must be greater than zero."
        )

    if threshold <= 0:
        raise ValueError(
            "Threshold must be greater than zero."
        )

    ordered = sort_events(events)

    if not ordered:
        return []

    duration = timedelta(minutes=window_minutes)
    matches = []

    left = 0
    active_start = None
    active_end = None

    for right, event in enumerate(ordered):
        while (
            left <= right
            and event.timestamp - ordered[left].timestamp
            > duration
        ):
            left += 1

        current_window = ordered[left:right + 1]

        if distinct_key is None:
            count = len(current_window)
        else:
            count = len({
                distinct_key(item)
                for item in current_window
            })

        if count >= threshold:
            if active_start is None:
                active_start = left

            active_end = right

        elif active_start is not None:
            # A qualifying sequence has ended.
            # Retain the complete consolidated interval.
            matches.append(
                ordered[active_start:active_end + 1]
            )

            active_start = None
            active_end = None

    if active_start is not None:
        matches.append(
            ordered[active_start:active_end + 1]
        )

    return matches


def get_ssh_failures(
    events: list[SecurityEvent],
) -> list[SecurityEvent]:
    return deduplicate_ssh_failures(events)


def get_ssh_successes(
    events: list[SecurityEvent],
) -> list[SecurityEvent]:
    return [
        event
        for event in events
        if event.event_type == EventType.SSH_LOGIN_SUCCESS
    ]


def find_success_after_failures(
    events: list[SecurityEvent],
    threshold: int,
    window_minutes: int,
) -> list[
    tuple[SecurityEvent, list[SecurityEvent]]
]:
    """
    Detect successful SSH logins preceded by failed
    attempts from the same IP against the same user.

    Duplicate SSH failure records are removed before
    counting attempts.

    Only failures occurring before the successful login
    and within the configured time window are counted.
    """
    if threshold <= 0:
        raise ValueError(
            "Threshold must be greater than zero."
        )

    if window_minutes <= 0:
        raise ValueError(
            "Window must be greater than zero."
        )

    failures = deduplicate_ssh_failures(events)
    successes = get_ssh_successes(events)

    relevant_events = sort_events([
        *failures,
        *successes,
    ])

    groups = group_by_ip_and_user(relevant_events)

    duration = timedelta(minutes=window_minutes)
    results = []

    for group in groups.values():
        recent_failures = []

        for event in group:
            recent_failures = [
                failure
                for failure in recent_failures
                if (
                    timedelta(0)
                    <= event.timestamp - failure.timestamp
                    <= duration
                )
            ]

            if event.event_type in SSH_FAILURE_TYPES:
                recent_failures.append(event)
                continue

            if event.event_type != EventType.SSH_LOGIN_SUCCESS:
                continue

            if len(recent_failures) >= threshold:
                results.append((
                    event,
                    recent_failures.copy(),
                ))

            # A successful authentication closes the
            # current sequence of failed attempts.
            recent_failures.clear()

    return sorted(
        results,
        key=lambda result: (
            result[0].timestamp,
            result[0].source,
            result[0].line_number,
        ),
    )
