
from collections import defaultdict

from src.logs.config import LogAnalyzerConfig
from src.logs.correlation import find_event_windows
from src.logs.detectors.brute_force import deduplicate_failures
from src.logs.models import (
    SecurityEvent,
    SecurityFinding,
    Severity,
)


def calculate_distributed_severity(
    ip_count: int,
    threshold: int,
) -> Severity:
    if ip_count >= threshold * 4:
        return Severity.CRITICAL

    if ip_count >= threshold * 2:
        return Severity.HIGH

    return Severity.MEDIUM


def detect_distributed_attack(
    events: list[SecurityEvent],
    config: LogAnalyzerConfig,
) -> list[SecurityFinding]:
    if "distributed_attack" not in config.enabled_rules:
        return []

    failures = deduplicate_failures(events)
    grouped = defaultdict(list)

    for event in failures:
        if event.username and event.source_ip:
            grouped[event.username].append(event)

    findings = []

    for username, user_events in grouped.items():
        windows = find_event_windows(
            events=user_events,
            window_minutes=(
                config.distributed_attack.window_minutes
            ),
            threshold=config.distributed_attack.threshold,
            distinct_key=lambda event: event.source_ip,
        )

        for window in windows:
            source_ips = sorted({
                event.source_ip
                for event in window
                if event.source_ip is not None
            })

            ip_count = len(source_ips)

            if ip_count < config.distributed_attack.threshold:
                continue

            severity = calculate_distributed_severity(
                ip_count,
                config.distributed_attack.threshold,
            )

            if (
                username in config.privileged_users
                and severity == Severity.MEDIUM
            ):
                severity = Severity.HIGH

            findings.append(
                SecurityFinding(
                    rule_id="distributed_attack",
                    severity=severity,
                    title="Possible distributed SSH attack",
                    description=(
                        f"Detected failed SSH authentication "
                        f"attempts against user '{username}' "
                        f"from {ip_count} different IP addresses "
                        f"within "
                        f"{config.distributed_attack.window_minutes} "
                        "minutes."
                    ),
                    recommendation=(
                        "Investigate the targeted account and "
                        "source IP addresses. Review successful "
                        "logins during the same period, enforce "
                        "SSH key authentication where appropriate, "
                        "and consider network-level protections "
                        "against distributed authentication attacks."
                    ),
                    first_seen=window[0].timestamp,
                    last_seen=window[-1].timestamp,
                    event_count=len(window),
                    username=username,
                    related_events=window,
                    metadata={
                        "source_ips": source_ips,
                        "distinct_ips": ip_count,
                        "threshold": (
                            config.distributed_attack.threshold
                        ),
                        "window_minutes": (
                            config.distributed_attack.window_minutes
                        ),
                        "privileged_account": (
                            username in config.privileged_users
                        ),
                    },
                )
            )

    return sorted(
        findings,
        key=lambda finding: finding.first_seen,
    )
