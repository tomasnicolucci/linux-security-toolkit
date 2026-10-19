
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from src.logs.config import LogAnalyzerConfig
from src.logs.correlation import (
    find_success_after_failures,
    get_ssh_successes,
    sort_events,
)
from src.logs.models import (
    SecurityEvent,
    SecurityFinding,
    Severity,
)


def get_login_severity(
    username: str | None,
    config: LogAnalyzerConfig,
    default: Severity = Severity.MEDIUM,
) -> Severity:
    if username in config.privileged_users:
        if default == Severity.HIGH:
            return Severity.CRITICAL

        return Severity.HIGH

    return default


def detect_success_after_failures(
    events: list[SecurityEvent],
    config: LogAnalyzerConfig,
) -> list[SecurityFinding]:
    if "successful_after_failures" not in config.enabled_rules:
        return []

    matches = find_success_after_failures(
        events=events,
        threshold=config.successful_after_failures.threshold,
        window_minutes=(
            config.successful_after_failures.window_minutes
        ),
    )

    findings = []

    for success, failures in matches:
        related_events = sort_events(
            [*failures, success]
        )

        findings.append(
            SecurityFinding(
                rule_id="successful_after_failures",
                severity=get_login_severity(
                    success.username,
                    config,
                    Severity.HIGH,
                ),
                title="Successful SSH login after failed attempts",
                description=(
                    f"User '{success.username}' successfully "
                    f"authenticated from {success.source_ip} "
                    f"after {len(failures)} failed SSH "
                    "authentication events."
                ),
                recommendation=(
                    "Verify whether the successful login was "
                    "authorized. Review the account's recent "
                    "activity, SSH sessions, and executed commands. "
                    "If compromise is suspected, revoke affected "
                    "credentials and investigate the host."
                ),
                first_seen=related_events[0].timestamp,
                last_seen=success.timestamp,
                event_count=len(related_events),
                source_ip=success.source_ip,
                username=success.username,
                related_events=related_events,
                metadata={
                    "failed_attempts": len(failures),
                    "successful_login": True,
                    "threshold": (
                        config.successful_after_failures.threshold
                    ),
                    "window_minutes": (
                        config.successful_after_failures.window_minutes
                    ),
                },
            )
        )

    return findings


def is_outside_business_hours(
    timestamp: datetime,
    config: LogAnalyzerConfig,
) -> bool:
    configured_timezone = ZoneInfo(config.timezone)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(
            tzinfo=timezone.utc
        )

    local_timestamp = timestamp.astimezone(
        configured_timezone
    )

    business_hours = config.business_hours

    if local_timestamp.weekday() not in business_hours.weekdays:
        return True

    local_time = local_timestamp.time().replace(
        tzinfo=None
    )

    return not (
        business_hours.start
        <= local_time
        < business_hours.end
    )


def detect_outside_business_hours(
    events: list[SecurityEvent],
    config: LogAnalyzerConfig,
) -> list[SecurityFinding]:
    if "outside_business_hours" not in config.enabled_rules:
        return []

    findings = []

    for event in get_ssh_successes(events):
        if not is_outside_business_hours(
            event.timestamp,
            config,
        ):
            continue

        local_timestamp = event.timestamp.astimezone(
            ZoneInfo(config.timezone)
        )

        findings.append(
            SecurityFinding(
                rule_id="outside_business_hours",
                severity=get_login_severity(
                    event.username,
                    config,
                ),
                title="SSH login outside permitted hours",
                description=(
                    f"User '{event.username}' successfully "
                    f"authenticated from {event.source_ip} "
                    "outside the configured business hours."
                ),
                recommendation=(
                    "Confirm whether this login was expected. "
                    "Review the source IP, account activity, "
                    "and any associated privileged operations."
                ),
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                event_count=1,
                source_ip=event.source_ip,
                username=event.username,
                related_events=[event],
                metadata={
                    "local_timestamp": (
                        local_timestamp.isoformat()
                    ),
                    "timezone": config.timezone,
                    "business_hours_start": (
                        config.business_hours.start.strftime(
                            "%H:%M"
                        )
                    ),
                    "business_hours_end": (
                        config.business_hours.end.strftime(
                            "%H:%M"
                        )
                    ),
                    "allowed_weekdays": list(
                        config.business_hours.weekdays
                    ),
                },
            )
        )

    return findings


def detect_new_source_ips(
    events: list[SecurityEvent],
    config: LogAnalyzerConfig,
    known_ips: set[str] | None = None,
) -> list[SecurityFinding]:
    if "new_source_ip" not in config.enabled_rules:
        return []

    # None means there is no approved baseline available.
    # An empty set means an approved baseline exists,
    # but it contains no trusted IP addresses.
    if known_ips is None:
        return []

    findings = []
    reported_ips = set()

    for event in sort_events(get_ssh_successes(events)):
        source_ip = event.source_ip

        if source_ip is None:
            continue

        if source_ip in known_ips:
            continue

        if source_ip in reported_ips:
            continue

        reported_ips.add(source_ip)

        related_events = [
            login
            for login in events
            if (
                login.event_type == event.event_type
                and login.source_ip == source_ip
            )
        ]

        related_events = sort_events(related_events)

        affected_users = sorted({
            login.username
            for login in related_events
            if login.username is not None
        })

        privileged_users = sorted(
            set(affected_users)
            & set(config.privileged_users)
        )

        severity = (
            Severity.HIGH
            if privileged_users
            else Severity.MEDIUM
        )

        findings.append(
            SecurityFinding(
                rule_id="new_source_ip",
                severity=severity,
                title="SSH login from an unknown IP address",
                description=(
                    f"Detected {len(related_events)} successful "
                    f"SSH login event(s) from {source_ip}, "
                    "which is not present in the approved "
                    "IP history."
                ),
                recommendation=(
                    "Verify the source IP and associated users. "
                    "Check whether the connections were authorized. "
                    "Only approve the IP after confirming "
                    "that the activity is legitimate."
                ),
                first_seen=related_events[0].timestamp,
                last_seen=related_events[-1].timestamp,
                event_count=len(related_events),
                source_ip=source_ip,
                related_events=related_events,
                metadata={
                    "affected_users": affected_users,
                    "privileged_users": privileged_users,
                    "known_ip": False,
                },
            )
        )

    return findings


def detect_suspicious_logins(
    events: list[SecurityEvent],
    config: LogAnalyzerConfig,
    known_ips: set[str] | None = None,
) -> list[SecurityFinding]:
    findings = []

    findings.extend(
        detect_success_after_failures(
            events,
            config,
        )
    )

    findings.extend(
        detect_outside_business_hours(
            events,
            config,
        )
    )

    findings.extend(
        detect_new_source_ips(
            events,
            config,
            known_ips,
        )
    )

    return sorted(
        findings,
        key=lambda finding: (
            finding.first_seen,
            finding.rule_id,
        ),
    )
