
from dataclasses import dataclass, field
from datetime import time
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml


AVAILABLE_RULES = {
    "brute_force",
    "password_spraying",
    "distributed_attack",
    "successful_after_failures",
    "privileged_activity",
    "account_changes",
    "service_errors",
    "outside_business_hours",
    "new_source_ip",
}

DEFAULT_ENABLED_RULES = set(AVAILABLE_RULES)


@dataclass(frozen=True)
class ThresholdConfig:
    threshold: int
    window_minutes: int


@dataclass(frozen=True)
class BusinessHoursConfig:
    start: time = time(8, 0)
    end: time = time(20, 0)
    weekdays: tuple[int, ...] = (0, 1, 2, 3, 4)


@dataclass(frozen=True)
class LogAnalyzerConfig:
    timezone: str = "UTC"

    brute_force: ThresholdConfig = field(
        default_factory=lambda: ThresholdConfig(5, 10)
    )

    password_spraying: ThresholdConfig = field(
        default_factory=lambda: ThresholdConfig(5, 10)
    )

    distributed_attack: ThresholdConfig = field(
        default_factory=lambda: ThresholdConfig(5, 10)
    )

    successful_after_failures: ThresholdConfig = field(
        default_factory=lambda: ThresholdConfig(3, 15)
    )

    service_errors: ThresholdConfig = field(
        default_factory=lambda: ThresholdConfig(5, 10)
    )

    privileged_users: tuple[str, ...] = (
        "root",
        "admin",
    )

    business_hours: BusinessHoursConfig = field(
        default_factory=BusinessHoursConfig
    )

    enabled_rules: frozenset[str] = field(
        default_factory=lambda: frozenset(
            DEFAULT_ENABLED_RULES
        )
    )

    ip_history_path: str = "/app/data/logs/known_ips.json"


def require_mapping(
    value: Any,
    field_name: str,
) -> dict:
    if not isinstance(value, dict):
        raise ValueError(
            f"Configuration '{field_name}' must be a mapping."
        )

    return value


def validate_keys(
    data: dict,
    allowed: set[str],
    section: str,
) -> None:
    unknown = set(data) - allowed

    if unknown:
        raise ValueError(
            f"Unknown configuration keys in '{section}': "
            f"{', '.join(sorted(map(str, unknown)))}"
        )


def parse_positive_int(
    value: Any,
    field_name: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"'{field_name}' must be a positive integer."
        )

    if value <= 0:
        raise ValueError(
            f"'{field_name}' must be greater than zero."
        )

    return value


def parse_threshold(
    data: Any,
    default: ThresholdConfig,
    section: str,
) -> ThresholdConfig:
    if data is None:
        return default

    data = require_mapping(data, section)

    validate_keys(
        data,
        {"threshold", "window_minutes"},
        section,
    )

    return ThresholdConfig(
        threshold=parse_positive_int(
            data.get("threshold", default.threshold),
            f"{section}.threshold",
        ),
        window_minutes=parse_positive_int(
            data.get(
                "window_minutes",
                default.window_minutes,
            ),
            f"{section}.window_minutes",
        ),
    )


def parse_time(value: Any, field_name: str) -> time:
    if not isinstance(value, str):
        raise ValueError(
            f"'{field_name}' must use HH:MM format."
        )

    try:
        parsed = time.fromisoformat(value)
    except ValueError as error:
        raise ValueError(
            f"Invalid time for '{field_name}': {value}"
        ) from error

    if parsed.tzinfo is not None or parsed.second != 0:
        raise ValueError(
            f"'{field_name}' must use HH:MM format."
        )

    return parsed


def parse_business_hours(
    data: Any,
    default: BusinessHoursConfig,
) -> BusinessHoursConfig:
    if data is None:
        return default

    data = require_mapping(data, "business_hours")

    validate_keys(
        data,
        {"start", "end", "weekdays"},
        "business_hours",
    )

    weekdays = data.get(
        "weekdays",
        list(default.weekdays),
    )

    if (
        not isinstance(weekdays, list)
        or not weekdays
        or any(
            isinstance(day, bool)
            or not isinstance(day, int)
            or day < 0
            or day > 6
            for day in weekdays
        )
    ):
        raise ValueError(
            "'business_hours.weekdays' must contain "
            "integers between 0 and 6."
        )

    start = parse_time(
        data.get("start", default.start.strftime("%H:%M")),
        "business_hours.start",
    )

    end = parse_time(
        data.get("end", default.end.strftime("%H:%M")),
        "business_hours.end",
    )

    if start >= end:
        raise ValueError(
            "'business_hours.start' must be earlier than 'end'."
        )

    return BusinessHoursConfig(
        start=start,
        end=end,
        weekdays=tuple(sorted(set(weekdays))),
    )


def parse_string_list(
    value: Any,
    field_name: str,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or any(
            not isinstance(item, str)
            or not item.strip()
            for item in value
        )
    ):
        raise ValueError(
            f"'{field_name}' must be a list of nonempty strings."
        )

    return tuple(dict.fromkeys(value))


def load_config(
    path: Path | None = None,
) -> LogAnalyzerConfig:
    defaults = LogAnalyzerConfig()

    if path is None:
        return defaults

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if data is None:
        data = {}

    data = require_mapping(data, "root")

    validate_keys(
        data,
        {
            "timezone",
            "brute_force",
            "password_spraying",
            "distributed_attack",
            "successful_after_failures",
            "service_errors",
            "privileged_users",
            "business_hours",
            "enabled_rules",
            "ip_history_path",
        },
        "root",
    )

    timezone_name = data.get(
        "timezone",
        defaults.timezone,
    )

    if not isinstance(timezone_name, str):
        raise ValueError("'timezone' must be a string.")

    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise ValueError(
            f"Unknown timezone: {timezone_name}"
        ) from error

    enabled_rules = data.get(
        "enabled_rules",
        sorted(defaults.enabled_rules),
    )

    enabled_rules = parse_string_list(
        enabled_rules,
        "enabled_rules",
    )

    unknown_rules = set(enabled_rules) - AVAILABLE_RULES

    if unknown_rules:
        raise ValueError(
            "Unknown detection rules: "
            + ", ".join(sorted(unknown_rules))
        )

    ip_history_path = data.get(
        "ip_history_path",
        defaults.ip_history_path,
    )

    if (
        not isinstance(ip_history_path, str)
        or not ip_history_path.strip()
    ):
        raise ValueError(
            "'ip_history_path' must be a nonempty string."
        )

    return LogAnalyzerConfig(
        timezone=timezone_name,

        brute_force=parse_threshold(
            data.get("brute_force"),
            defaults.brute_force,
            "brute_force",
        ),

        password_spraying=parse_threshold(
            data.get("password_spraying"),
            defaults.password_spraying,
            "password_spraying",
        ),

        distributed_attack=parse_threshold(
            data.get("distributed_attack"),
            defaults.distributed_attack,
            "distributed_attack",
        ),

        successful_after_failures=parse_threshold(
            data.get("successful_after_failures"),
            defaults.successful_after_failures,
            "successful_after_failures",
        ),

        service_errors=parse_threshold(
            data.get("service_errors"),
            defaults.service_errors,
            "service_errors",
        ),

        privileged_users=parse_string_list(
            data.get(
                "privileged_users",
                list(defaults.privileged_users),
            ),
            "privileged_users",
        ),

        business_hours=parse_business_hours(
            data.get("business_hours"),
            defaults.business_hours,
        ),

        enabled_rules=frozenset(enabled_rules),
        ip_history_path=ip_history_path,
    )
