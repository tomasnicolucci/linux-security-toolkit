from src.logs.config import LogAnalyzerConfig
from src.logs.models import EventType, SecurityEvent, SecurityFinding, Severity

ACCOUNT_EVENTS = {
    EventType.USER_CREATED, EventType.USER_DELETED, EventType.PASSWORD_CHANGED,
    EventType.GROUP_CREATED, EventType.GROUP_DELETED, EventType.GROUP_MEMBERSHIP_CHANGED,
}


def detect_account_changes(events: list[SecurityEvent], config: LogAnalyzerConfig) -> list[SecurityFinding]:
    if "account_changes" not in config.enabled_rules:
        return []
    findings = []
    for event in events:
        if event.event_type not in ACCOUNT_EVENTS:
            continue
        severity = Severity.HIGH if event.event_type in {
            EventType.USER_CREATED, EventType.USER_DELETED, EventType.GROUP_MEMBERSHIP_CHANGED,
        } else Severity.MEDIUM
        if event.username in config.privileged_users:
            severity = Severity.CRITICAL if severity == Severity.HIGH else Severity.HIGH
        findings.append(SecurityFinding(
            rule_id="account_changes", severity=severity,
            title=f"Account change: {event.event_type.value}",
            description=f"Account or group administration event: {event.message}",
            recommendation="Verify the change against approved administrative activity and review related audit logs.",
            first_seen=event.timestamp, last_seen=event.timestamp, event_count=1,
            username=event.username, source_ip=event.source_ip, related_events=[event],
            metadata={"service": event.service, **event.metadata},
        ))
    return sorted(findings, key=lambda finding: finding.first_seen)
