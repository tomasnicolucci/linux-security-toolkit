from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class RankedItem:
    name: str
    events: int
    failed: int
    success: int


@dataclass(frozen=True)
class PeriodStats:
    start: datetime
    end: datetime
    metrics: dict[str, int]
    ssh_success_rate: float | None
    by_event_type: dict[str, int]
    top_ips: list[RankedItem]
    top_users: list[RankedItem]


@dataclass(frozen=True)
class TrendBucket:
    label: str
    events: int
    failed: int


@dataclass(frozen=True)
class Trend:
    granularity: str
    buckets: list[TrendBucket]
    peak_label: str | None
    peak_events: int


@dataclass(frozen=True)
class MetricChange:
    name: str
    current: int
    previous: int
    difference: int
    change_percent: float | None


@dataclass(frozen=True)
class Comparison:
    previous: PeriodStats
    changes: list[MetricChange]
    new_ips: list[RankedItem]
    new_ips_total: int
    gone_ips: list[RankedItem]
    gone_ips_total: int
    new_users: list[RankedItem]
    new_users_total: int
    gone_users: list[RankedItem]
    gone_users_total: int


@dataclass
class StatsResult:
    timezone: str
    period: PeriodStats
    trend: Trend
    comparison: Comparison | None = None

    files_processed: list[str] = field(default_factory=list)
    lines_processed: int = 0
    lines_unparsed: int = 0
    events_loaded: int = 0

    errors: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)