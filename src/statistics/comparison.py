from src.statistics.metrics import (
    METRIC_LABELS,
    PeriodData,
    count_metrics,
)
from src.statistics.models import (
    Comparison,
    MetricChange,
    PeriodStats,
    RankedItem,
)


def percent_change(current: int, previous: int) -> float | None:
    """Percentage variation; undefined when the previous value is 0."""
    if previous == 0:
        return None

    return round((current - previous) / previous * 100, 1)


def appeared_and_disappeared(
    current: list[RankedItem],
    previous: list[RankedItem],
    top: int,
) -> tuple[list[RankedItem], int, list[RankedItem], int]:
    """
    Items present only in the current period (new) and only in the
    previous one (gone). Both lists are ordered by activity.
    """
    previous_names = {item.name for item in previous}
    current_names = {item.name for item in current}

    new = [item for item in current if item.name not in previous_names]

    gone = [
        item for item in previous if item.name not in current_names
    ]

    return new[:top], len(new), gone[:top], len(gone)


def compare(
    current: PeriodData,
    previous: PeriodData,
    previous_stats: PeriodStats,
    top: int,
) -> Comparison:
    current_metrics = count_metrics(current)
    previous_metrics = count_metrics(previous)

    changes = [
        MetricChange(
            name=name,
            current=current_metrics[name],
            previous=previous_metrics[name],
            difference=current_metrics[name] - previous_metrics[name],
            change_percent=percent_change(
                current_metrics[name],
                previous_metrics[name],
            ),
        )
        for name in METRIC_LABELS
    ]

    new_ips, new_ips_total, gone_ips, gone_ips_total = (
        appeared_and_disappeared(current.ips, previous.ips, top)
    )

    new_users, new_users_total, gone_users, gone_users_total = (
        appeared_and_disappeared(current.users, previous.users, top)
    )

    return Comparison(
        previous=previous_stats,
        changes=changes,
        new_ips=new_ips,
        new_ips_total=new_ips_total,
        gone_ips=gone_ips,
        gone_ips_total=gone_ips_total,
        new_users=new_users,
        new_users_total=new_users_total,
        gone_users=gone_users,
        gone_users_total=gone_users_total,
    )