
from collections import defaultdict
from datetime import timedelta

from src.logs.config import LogAnalyzerConfig
from src.logs.correlation import (
    SSH_FAILURE_TYPES,
    find_event_windows,
    sort_events,
)
from src.logs.models import (
    SecurityEvent,
    SecurityFinding,
    Severity,
)


def deduplicate_failures(
    events: list[SecurityEvent],
) -> list[SecurityEvent]:
    """
    Avoid counting SSH_INVALID_USER and SSH_LOGIN_FAILED
    as separate attempts when they describe the same
    authentication activity.
    """
    ordered = sort_events([
        event
        for event in events
        if event.event_type in SSH_FAILURE_TYPES
        and event.source_ip is not None
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
                event.source_ip == previous.source_ip
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


def calculate_severity(
    attempt_count: int,
    threshold: int,
) -> Severity:
    if attempt_count >= threshold * 4:
        return Severity.CRITICAL

    if attempt_count >= threshold * 2:
        return Severity.HIGH

    return Severity.MEDIUM


def detect_brute_force(
    events: list[SecurityEvent],
    config: LogAnalyzerConfig,
) -> list[SecurityFinding]:
    if "brute_force" not in config.enabled_rules:
        return []

    failures = deduplicate_failures(events)
    grouped = defaultdict(list)

    for event in failures:
        grouped[event.source_ip].append(event)

    findings = []

    for source_ip, ip_events in grouped.items():
        windows = find_event_windows(
            events=ip_events,
            window_minutes=config.brute_force.window_minutes,
            threshold=config.brute_force.threshold,
        )

        for window in windows:
            usernames = sorted({
                event.username
                for event in window
                if event.username is not None
            })

            count = len(window)

            findings.append(
                SecurityFinding(
                    rule_id="brute_force",
                    severity=calculate_severity(
                        count,
                        config.brute_force.threshold,
                    ),
                    title="Possible SSH brute-force attack",
                    description=(
                        f"Detected {count} failed SSH login "
                        f"attempts from {source_ip} within "
                        f"a {config.brute_force.window_minutes}-minute "
                        "time window."
                    ),
                    recommendation=(
                        "Review the source IP and affected accounts. "
                        "Consider SSH key authentication, disabling "
                        "password authentication where appropriate, "
                        "and applying rate limiting or Fail2ban."
                    ),
                    first_seen=window[0].timestamp,
                    last_seen=window[-1].timestamp,
                    event_count=count,
                    source_ip=source_ip,
                    metadata={
                        "targeted_users": usernames,
                        "threshold": config.brute_force.threshold,
                        "window_minutes": (
                            config.brute_force.window_minutes
                        ),
                    },
                    related_events=window,
                )
            )

    return sorted(
        findings,
        key=lambda finding: finding.first_seen,
    )
