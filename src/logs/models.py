from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EventType(str, Enum):
    SSH_LOGIN_FAILED = "ssh_login_failed"
    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_INVALID_USER = "ssh_invalid_user"
    SSH_SESSION_OPENED = "ssh_session_opened"
    SSH_SESSION_CLOSED = "ssh_session_closed"

    SUDO_COMMAND = "sudo_command"
    SUDO_AUTH_FAILED = "sudo_auth_failed"

    SU_SUCCESS = "su_success"
    SU_FAILED = "su_failed"

    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    PASSWORD_CHANGED = "password_changed"
    GROUP_CREATED = "group_created"
    GROUP_DELETED = "group_deleted"
    GROUP_MEMBERSHIP_CHANGED = "group_membership_changed"

    PAM_AUTH_FAILED = "pam_auth_failed"
    SERVICE_ERROR = "service_error"

    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    event_type: EventType
    source: str
    line_number: int
    service: str
    message: str

    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    process_id: int | None = None
    session_id: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str

    first_seen: datetime
    last_seen: datetime
    event_count: int

    source_ip: str | None = None
    username: str | None = None

    related_events: list[SecurityEvent] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    events: list[SecurityEvent] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)

    files_processed: list[str] = field(default_factory=list)
    lines_processed: int = 0
    lines_unparsed: int = 0

    errors: dict[str, str] = field(default_factory=dict)
    statistics: dict[str, Any] = field(default_factory=dict)
