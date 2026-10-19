from src.logs.config import LogAnalyzerConfig
from src.logs.models import EventType, SecurityEvent, SecurityFinding, Severity


def detect_privileged_activity(events: list[SecurityEvent], config: LogAnalyzerConfig) -> list[SecurityFinding]:
    if "privileged_activity" not in config.enabled_rules:
        return []
    findings = []
    for event in events:
        privileged_login = (
            event.event_type == EventType.SSH_LOGIN_SUCCESS
            and event.username in config.privileged_users
        )
        elevated_command = event.event_type in {EventType.SUDO_COMMAND, EventType.SU_SUCCESS}
        auth_failure = event.event_type in {EventType.SUDO_AUTH_FAILED, EventType.SU_FAILED}
        if not (privileged_login or elevated_command or auth_failure):
            continue
        if privileged_login:
            severity, title = Severity.HIGH, "Privileged SSH login"
        elif auth_failure:
            severity, title = Severity.MEDIUM, "Failed privilege escalation"
        else:
            severity, title = Severity.LOW, "Privilege-related activity"
        findings.append(SecurityFinding(
            rule_id="privileged_activity", severity=severity, title=title,
            description=f"{event.event_type.value} by '{event.username or 'unknown'}': {event.message}",
            recommendation="Verify that the account and privileged activity were authorized.",
            first_seen=event.timestamp, last_seen=event.timestamp, event_count=1,
            source_ip=event.source_ip, username=event.username, related_events=[event],
            metadata={"service": event.service, **event.metadata},
        ))
    return sorted(findings, key=lambda finding: finding.first_seen)
