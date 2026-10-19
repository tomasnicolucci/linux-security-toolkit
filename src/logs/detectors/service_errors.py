from collections import defaultdict
from src.logs.config import LogAnalyzerConfig
from src.logs.correlation import find_event_windows
from src.logs.models import EventType, SecurityEvent, SecurityFinding, Severity


def detect_service_errors(events: list[SecurityEvent], config: LogAnalyzerConfig) -> list[SecurityFinding]:
    if "service_errors" not in config.enabled_rules:
        return []
    groups = defaultdict(list)
    for event in events:
        if event.event_type == EventType.SERVICE_ERROR:
            groups[(event.hostname, event.service)].append(event)
    findings = []
    for (hostname, service), group in groups.items():
        for window in find_event_windows(
            group, config.service_errors.window_minutes, config.service_errors.threshold
        ):
            count = len(window)
            threshold = config.service_errors.threshold
            severity = Severity.CRITICAL if count >= threshold * 4 else (
                Severity.HIGH if count >= threshold * 2 else Severity.MEDIUM
            )
            findings.append(SecurityFinding(
                rule_id="service_errors", severity=severity,
                title=f"Repeated service errors: {service}",
                description=f"{count} error events for service '{service}' on '{hostname or 'unknown'}'.",
                recommendation="Inspect service logs, dependencies and system resource usage.",
                first_seen=window[0].timestamp, last_seen=window[-1].timestamp,
                event_count=count, related_events=window,
                metadata={"hostname": hostname, "service": service},
            ))
    return sorted(findings, key=lambda finding: finding.first_seen)