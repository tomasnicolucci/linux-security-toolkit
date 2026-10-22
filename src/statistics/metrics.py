from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo

from src.logs.correlation import deduplicate_ssh_failures
from src.logs.models import EventType, SecurityEvent
from src.statistics.models import (
    PeriodStats,
    RankedItem,
    Trend,
    TrendBucket,
)
from src.statistics.periods import Period

MAX_BUCKETS = 400
AUTO_HOURLY_LIMIT = timedelta(days=3)

# Event types counted by each derived metric. SSH failures are
# counted separately because duplicate records are removed first.
METRIC_GROUPS = {
    "ssh_success": (EventType.SSH_LOGIN_SUCCESS,),
    "privilege_use": (
        EventType.SUDO_COMMAND,
        EventType.SU_SUCCESS,
    ),
    "privilege_failures": (
        EventType.SUDO_AUTH_FAILED,
        EventType.SU_FAILED,
    ),
    "account_changes": (
        EventType.USER_CREATED,
        EventType.USER_DELETED,
        EventType.PASSWORD_CHANGED,
        EventType.GROUP_CREATED,
        EventType.GROUP_DELETED,
        EventType.GROUP_MEMBERSHIP_CHANGED,
    ),
    "service_errors": (EventType.SERVICE_ERROR,),
}

METRIC_LABELS = {
    "total_events": "Total events",
    "ssh_failed": "SSH failed logins",
    "ssh_success": "SSH successful logins",
    "privilege_use": "Privileged activity (sudo/su)",
    "privilege_failures": "Privileged auth failures",
    "account_changes": "Account and group changes",
    "service_errors": "Service errors",
    "unique_source_ips": "Unique source IPs",
    "unique_users": "Unique users",
}


@dataclass
class PeriodData:
    """Events of a period together with values derived from them."""

    period: Period
    events: list[SecurityEvent]
    failures: list[SecurityEvent]
    ips: list[RankedItem]
    users: list[RankedItem]


def rank_by(
    events: list[SecurityEvent],
    failures: list[SecurityEvent],
    attribute: str,
) -> list[RankedItem]:
    totals: Counter = Counter()
    failed: Counter = Counter()
    success: Counter = Counter()

    for event in events:
        key = getattr(event, attribute)

        if key is None:
            continue

        totals[key] += 1

        if event.event_type == EventType.SSH_LOGIN_SUCCESS:
            success[key] += 1

    for event in failures:
        key = getattr(event, attribute)

        if key is not None:
            failed[key] += 1

    items = [
        RankedItem(key, count, failed[key], success[key])
        for key, count in totals.items()
    ]

    items.sort(key=lambda item: (-item.events, item.name))

    return items


def collect(
    period: Period,
    events: list[SecurityEvent],
) -> PeriodData:
    failures = deduplicate_ssh_failures(events)

    return PeriodData(
        period=period,
        events=events,
        failures=failures,
        ips=rank_by(events, failures, "source_ip"),
        users=rank_by(events, failures, "username"),
    )


def count_metrics(data: PeriodData) -> dict[str, int]:
    counts = Counter(event.event_type for event in data.events)

    metrics = {
        "total_events": len(data.events),
        "ssh_failed": len(data.failures),
    }

    for name, event_types in METRIC_GROUPS.items():
        metrics[name] = sum(counts[kind] for kind in event_types)

    metrics["unique_source_ips"] = len(data.ips)
    metrics["unique_users"] = len(data.users)

    return metrics


def build_stats(
    data: PeriodData,
    top: int,
    tz: tzinfo,
) -> PeriodStats:
    metrics = count_metrics(data)

    attempts = metrics["ssh_success"] + metrics["ssh_failed"]

    rate = (
        round(metrics["ssh_success"] / attempts * 100, 1)
        if attempts
        else None
    )

    by_type = Counter(
        event.event_type.value for event in data.events
    )

    return PeriodStats(
        start=data.period.start.astimezone(tz),
        end=data.period.end.astimezone(tz),
        metrics=metrics,
        ssh_success_rate=rate,
        by_event_type=dict(
            sorted(by_type.items(), key=lambda pair: (-pair[1], pair[0]))
        ),
        top_ips=data.ips[:top],
        top_users=data.users[:top],
    )


def choose_granularity(
    period: Period,
    requested: str | None,
) -> str:
    if requested is not None:
        return requested

    return "hour" if period.duration <= AUTO_HOURLY_LIMIT else "day"


def build_trend(
    data: PeriodData,
    granularity: str,
    tz: tzinfo,
) -> Trend:
    """
    Group events and SSH failures into hourly or daily buckets using
    local calendar time. Empty buckets are kept so gaps are visible.
    """
    if granularity == "hour":
        step = timedelta(hours=1)
        label_format = "%Y-%m-%d %H:00"
    else:
        step = timedelta(days=1)
        label_format = "%Y-%m-%d"

    def bucket_start(timestamp: datetime) -> datetime:
        local = timestamp.astimezone(tz).replace(tzinfo=None)

        if granularity == "hour":
            return local.replace(minute=0, second=0, microsecond=0)

        return local.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

    events_per_bucket: Counter = Counter(
        bucket_start(event.timestamp) for event in data.events
    )

    failed_per_bucket: Counter = Counter(
        bucket_start(event.timestamp) for event in data.failures
    )

    first = bucket_start(data.period.start)
    last = bucket_start(data.period.end)

    count = int((last - first) / step) + 1

    if count > MAX_BUCKETS:
        raise ValueError(
            f"The period needs {count} {granularity} buckets "
            f"(limit {MAX_BUCKETS}). Use a shorter period"
            + (" or --by day." if granularity == "hour" else ".")
        )

    buckets = []
    current = first

    while current <= last:
        buckets.append(
            TrendBucket(
                label=current.strftime(label_format),
                events=events_per_bucket[current],
                failed=failed_per_bucket[current],
            )
        )

        current += step

    peak = max(buckets, key=lambda bucket: bucket.events)

    return Trend(
        granularity=granularity,
        buckets=buckets,
        peak_label=peak.label if peak.events else None,
        peak_events=peak.events,
    )