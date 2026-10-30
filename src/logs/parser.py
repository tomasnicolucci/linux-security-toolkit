
import ipaddress
import json
import re
from datetime import datetime, timezone, tzinfo
from typing import Any

from src.logs.models import EventType, SecurityEvent
from src.logs.reader import LogLine


SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[\w@./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

ISO_PATTERN = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?"
    r")\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[\w@./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3,
    "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9,
    "Oct": 10, "Nov": 11, "Dec": 12,
    # Abreviaturas en español que no coinciden con las inglesas.
    "Ene": 1, "Abr": 4, "Ago": 8, "Dic": 12,
}

SSH_FAILED = re.compile(
    r"Failed \S+ for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)

SSH_SUCCESS = re.compile(
    r"Accepted \S+ for (?P<user>\S+) "
    r"from (?P<ip>\S+)",
    re.IGNORECASE,
)

SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)

SUDO_COMMAND = re.compile(
    r"^(?P<user>\S+)\s*:\s*"
    r".*\bCOMMAND=(?P<command>.*)$",
    re.IGNORECASE,
)

SUDO_FAILURE = re.compile(
    r"(?:authentication failure|incorrect password|"
    r"\d+ incorrect password attempts|NOT in sudoers|"
    r"command not allowed)",
    re.IGNORECASE,
)

SU_SUCCESS = re.compile(
    r"Successful su for (?P<target>\S+) by (?P<user>\S+)",
    re.IGNORECASE,
)

SU_FAILURE = re.compile(
    r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+)",
    re.IGNORECASE,
)

PAM_FAILURE = re.compile(
    r"pam_\w+\([^)]*\): authentication failure",
    re.IGNORECASE,
)

PAM_USER = re.compile(r"\buser=(?P<user>\S+)")
PAM_RHOST = re.compile(r"\brhost=(?P<host>\S+)")

SESSION_OPENED = re.compile(
    r"session opened for user (?P<user>\S+)",
    re.IGNORECASE,
)

SESSION_CLOSED = re.compile(
    r"session closed for user (?P<user>\S+)",
    re.IGNORECASE,
)

ACCOUNT_PATTERNS = (
    (EventType.USER_CREATED, re.compile(
        r"new user: name=(?P<user>[^,\s]+)", re.I
    )),
    (EventType.USER_DELETED, re.compile(
        r"delete user ['\"]?(?P<user>[\w.-]+)", re.I
    )),
    (EventType.PASSWORD_CHANGED, re.compile(
        r"password changed for (?P<user>\S+)", re.I
    )),
    (EventType.GROUP_CREATED, re.compile(
        r"new group: name=(?P<user>[^,\s]+)", re.I
    )),
    (EventType.GROUP_DELETED, re.compile(
        r"delete group ['\"]?(?P<user>[\w.-]+)", re.I
    )),
    (EventType.GROUP_MEMBERSHIP_CHANGED, re.compile(
        r"add ['\"]?(?P<user>[\w.-]+)['\"]? to group",
        re.I,
    )),
)

SERVICE_ERROR = re.compile(
    r"\b(error|failed|failure|fatal|crashed|segfault)\b",
    re.IGNORECASE,
)


def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_timestamp(
    value: str,
    tz: tzinfo = timezone.utc,
) -> datetime:
    normalized = value.replace(",", ".")

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    if re.search(r"[+-]\d{4}$", normalized):
        normalized = (
            normalized[:-5]
            + normalized[-5:-2]
            + ":"
            + normalized[-2:]
        )

    timestamp = datetime.fromisoformat(normalized)

    # Un timestamp sin offset se interpreta en la zona horaria
    # configurada, igual que los timestamps syslog tradicionales.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=tz)

    return timestamp.astimezone(timezone.utc)


def parse_syslog_timestamp(
    month: str,
    day: str,
    time_value: str,
    year: int,
    tz: tzinfo = timezone.utc,
) -> datetime:
    month_number = MONTHS.get(month)

    if month_number is None:
        raise ValueError(f"Unknown month abbreviation: {month}")

    hour, minute, second = map(int, time_value.split(":"))

    local_time = datetime(
        year,
        month_number,
        int(day),
        hour,
        minute,
        second,
        tzinfo=tz,
    )

    return local_time.astimezone(timezone.utc)


def parse_journal_json(content: str) -> dict[str, Any] | None:
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    message = data.get("MESSAGE")

    if not isinstance(message, str):
        return None

    timestamp_value = data.get("__REALTIME_TIMESTAMP")

    if timestamp_value is None:
        return None

    try:
        timestamp = datetime.fromtimestamp(
            int(timestamp_value) / 1_000_000,
            tz=timezone.utc,
        )
    except (ValueError, TypeError, OverflowError):
        return None

    service = str(
        data.get("SYSLOG_IDENTIFIER")
        or data.get("_COMM")
        or "unknown"
    )

    pid = data.get("_PID")

    try:
        process_id = int(pid) if pid is not None else None
    except (ValueError, TypeError):
        process_id = None

    return {
        "timestamp": timestamp,
        "hostname": data.get("_HOSTNAME"),
        "service": service,
        "process_id": process_id,
        "message": message,
    }


def extract_event_details(
    service: str,
    message: str,
) -> tuple[EventType, str | None, str | None, dict]:
    service_name = service.lower()
    metadata = {}

    if service_name.startswith("sshd"):
        match = SSH_FAILED.search(message)

        if match:
            return (
                EventType.SSH_LOGIN_FAILED,
                match.group("user"),
                normalize_ip(match.group("ip")),
                metadata,
            )

        match = SSH_SUCCESS.search(message)

        if match:
            return (
                EventType.SSH_LOGIN_SUCCESS,
                match.group("user"),
                normalize_ip(match.group("ip")),
                metadata,
            )

        match = SSH_INVALID_USER.search(message)

        if match:
            return (
                EventType.SSH_INVALID_USER,
                match.group("user"),
                normalize_ip(match.group("ip")),
                metadata,
            )

    if service_name.startswith("sudo"):
        # Failed attempts also contain "COMMAND=" (the command that was
        # refused), so failures must be recognized first. Only the part
        # before the command is inspected.
        if SUDO_FAILURE.search(message.split("COMMAND=", 1)[0]):
            pam_user = PAM_USER.search(message)

            if pam_user:
                user = pam_user.group("user")
            else:
                user = message.split(":", 1)[0].strip()

            return (
                EventType.SUDO_AUTH_FAILED,
                user if user and " " not in user else None,
                None,
                metadata,
            )

        match = SUDO_COMMAND.search(message)

        if match:
            metadata["command"] = match.group("command")

            return (
                EventType.SUDO_COMMAND,
                match.group("user"),
                None,
                metadata,
            )

    if service_name.startswith("su"):
        match = SU_SUCCESS.search(message)

        if match:
            metadata["target_user"] = match.group("target")

            return (
                EventType.SU_SUCCESS,
                match.group("user"),
                None,
                metadata,
            )

        match = SU_FAILURE.search(message)

        if match:
            metadata["target_user"] = match.group("target")

            return (
                EventType.SU_FAILED,
                match.group("user"),
                None,
                metadata,
            )

    for event_type, pattern in ACCOUNT_PATTERNS:
        match = pattern.search(message)

        if match:
            return (
                event_type,
                match.group("user"),
                None,
                metadata,
            )

    match = SESSION_OPENED.search(message)

    if match:
        return (
            EventType.SSH_SESSION_OPENED,
            match.group("user"),
            None,
            metadata,
        )

    match = SESSION_CLOSED.search(message)

    if match:
        return (
            EventType.SSH_SESSION_CLOSED,
            match.group("user"),
            None,
            metadata,
        )

    if PAM_FAILURE.search(message):
        user_match = PAM_USER.search(message)
        host_match = PAM_RHOST.search(message)

        return (
            EventType.PAM_AUTH_FAILED,
            user_match.group("user") if user_match else None,
            normalize_ip(host_match.group("host")) if host_match else None,
            metadata,
        )

    if SERVICE_ERROR.search(message):
        return EventType.SERVICE_ERROR, None, None, metadata

    return EventType.UNKNOWN, None, None, metadata


def parse_log_line(
    log_line: LogLine,
    year: int | None = None,
    tz: tzinfo = timezone.utc,
) -> SecurityEvent | None:
    content = log_line.content.strip()

    if not content:
        return None

    parsed = None

    if content.startswith("{"):
        parsed = parse_journal_json(content)

    if parsed is None:
        match = ISO_PATTERN.match(content)

        if match:
            parsed = {
                "timestamp": parse_timestamp(
                    match.group("timestamp"),
                    tz,
                ),
                "hostname": match.group("hostname"),
                "service": match.group("service"),
                "process_id": (
                    int(match.group("pid"))
                    if match.group("pid")
                    else None
                ),
                "message": match.group("message"),
            }

    if parsed is None:
        match = SYSLOG_PATTERN.match(content)

        if match:
            selected_year = year or datetime.now(
                timezone.utc
            ).year

            parsed = {
                "timestamp": parse_syslog_timestamp(
                    match.group("month"),
                    match.group("day"),
                    match.group("time"),
                    selected_year,
                    tz,
                ),
                "hostname": match.group("hostname"),
                "service": match.group("service"),
                "process_id": (
                    int(match.group("pid"))
                    if match.group("pid")
                    else None
                ),
                "message": match.group("message"),
            }

    if parsed is None:
        return None

    event_type, username, source_ip, metadata = (
        extract_event_details(
            parsed["service"],
            parsed["message"],
        )
    )

    return SecurityEvent(
        timestamp=parsed["timestamp"],
        event_type=event_type,
        source=log_line.source,
        line_number=log_line.line_number,
        service=parsed["service"],
        message=parsed["message"],
        hostname=parsed["hostname"],
        username=username,
        source_ip=source_ip,
        process_id=parsed["process_id"],
        metadata=metadata,
    )
