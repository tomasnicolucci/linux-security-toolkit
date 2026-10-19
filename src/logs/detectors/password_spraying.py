
from collections import defaultdict

from src.logs.config import LogAnalyzerConfig
from src.logs.correlation import find_event_windows
from src.logs.detectors.brute_force import deduplicate_failures
from src.logs.models import (
    SecurityEvent,
    SecurityFinding,
    Severity,
)


def calculate_spraying_severity(
    user_count: int,
    threshold: int,
) -> Severity:
    if user_count >= threshold * 4:
        return Severity.CRITICAL

    if user_count >= threshold * 2:
        return Severity.HIGH

    return Severity.MEDIUM


def detect_password_spraying(
    events: list[SecurityEvent],
    config: LogAnalyzerConfig,
) -> list[SecurityFinding]:
    if "password_spraying" not in config.enabled_rules:
        return []

    failures = deduplicate_failures(events)

    grouped = defaultdict(list)

    for event in failures:
        if event.source_ip and event.username:
            grouped[event.source_ip].append(event)

    findings = []

    for source_ip, ip_events in grouped.items():
        windows = find_event_windows(
            events=ip_events,
            window_minutes=(
                config.password_spraying.window_minutes
            ),
            threshold=config.password_spraying.threshold,
            distinct_key=lambda event: event.username,
        )

        for window in windows:
            targeted_users = sorted({
                event.username
                for event in window
                if event.username is not None
            })

            user_count = len(targeted_users)

            if user_count < config.password_spraying.threshold:
                continue

            findings.append(
                SecurityFinding(
                    rule_id="password_spraying",
                    severity=calculate_spraying_severity(
                        user_count,
                        config.password_spraying.threshold,
                    ),
                    title="Possible SSH password spraying attack",
                    description=(
                        f"Source IP {source_ip} attempted SSH "
                        f"authentication against {user_count} "
                        "different user accounts within "
                        f"{config.password_spraying.window_minutes} "
                        "minutes."
                    ),
                    recommendation=(
                        "Review the affected accounts and source IP. "
                        "Consider disabling SSH password "
                        "authentication, enforcing strong "
                        "credentials, and implementing "
                        "appropriate rate limiting."
                    ),
                    first_seen=window[0].timestamp,
                    last_seen=window[-1].timestamp,
                    event_count=len(window),
                    source_ip=source_ip,
                    related_events=window,
                    metadata={
                        "targeted_users": targeted_users,
                        "distinct_users": user_count,
                        "threshold": (
                            config.password_spraying.threshold
                        ),
                        "window_minutes": (
                            config.password_spraying.window_minutes
                        ),
                    },
                )
            )

    return sorted(
        findings,
        key=lambda finding: finding.first_seen,
    )
