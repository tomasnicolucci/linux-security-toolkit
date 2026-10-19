# Linux Security Toolkit — Log Analyzer

## Overview

The Linux Log Analyzer is Module 5 of the Linux Security Toolkit.

It analyzes Linux authentication and system logs to identify suspicious activity, authentication attacks, privileged operations, account changes, and service errors.

The module runs as a Python CLI application inside Docker. It performs offline analysis of existing log files and does not modify system logs, block IP addresses, or execute remediation commands.

## Features

### Supported log sources

- `/var/log/auth.log` — Debian/Ubuntu authentication logs
- `/var/log/secure` — RHEL-based authentication logs
- `/var/log/syslog` and `/var/log/messages`
- Rotated log files, including `.1` and `.gz`
- Journalctl exports in supported text and JSON formats

### Security detections

| Detection | Description |
|---|---|
| SSH brute force | Multiple failed SSH authentication attempts from one IP |
| Password spraying | One IP targeting multiple user accounts |
| Distributed attack | Multiple IP addresses targeting one account |
| Successful login after failures | SSH authentication succeeds after repeated failures |
| Suspicious login hours | Successful SSH access outside configured hours |
| Unknown source IP | Successful SSH access from an IP not in the approved baseline |
| Privileged activity | Suspicious root, sudo, or su activity |
| Account changes | User, password, and group modifications |
| Service errors | Repeated service failures and errors |

### Additional capabilities

- Configurable detection thresholds and time windows
- IPv4 and IPv6 support
- Filtering by IP address, username, event type, and date
- Configurable timezone and permitted login hours
- Severity classification: LOW, MEDIUM, HIGH, CRITICAL
- Console reporting and JSON export
- Persistent, explicitly approved SSH source IP history

## Requirements

- Docker
- Docker Compose
- Python 3.13 when running outside Docker

Python dependencies are defined in `requirements.txt`, including `PyYAML` and `tzdata`.

## Installation

Build the Docker image from the project root:

```bash
docker compose build
```

The Docker Compose configuration mounts the following paths:

| Host path | Container path | Purpose |
|---|---|---|
| `./data` | `/app/data` | Persistent application data |
| `./samples` | `/app/samples` | Sample log files, read-only |
| `./config.yaml` | `/app/config.yaml` | Analyzer configuration, read-only |
| `/etc/ssh` | `/host/etc/ssh` | Host SSH configuration, read-only |

The `/etc/ssh` mount is intended for Linux hosts. On Windows, it may need to be removed or adapted.

## Configuration

The analyzer uses a YAML configuration file.

**File: `config.yaml`**

```yaml
timezone: "America/Argentina/Buenos_Aires"

brute_force:
  threshold: 5
  window_minutes: 10

password_spraying:
  threshold: 5
  window_minutes: 10

distributed_attack:
  threshold: 5
  window_minutes: 10

successful_after_failures:
  threshold: 3
  window_minutes: 15

service_errors:
  threshold: 5
  window_minutes: 10

privileged_users:
  - root
  - admin

business_hours:
  start: "08:00"
  end: "20:00"
  weekdays: [0, 1, 2, 3, 4]

enabled_rules:
  - brute_force
  - password_spraying
  - distributed_attack
  - successful_after_failures
  - privileged_activity
  - account_changes
  - service_errors
  - outside_business_hours
  - new_source_ip

ip_history_path: "/app/data/logs/known_ips.json"
```

Weekdays follow Python's convention: Monday is `0`, Sunday is `6`.

Thresholds and time windows can be modified without changing detector code.

## Usage

All commands are executed from the project root.

### Analyze a log file

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --year 2026
```

The `--year` option specifies the year for traditional syslog entries, which do not include a year in their timestamps.

### Analyze a directory

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs --recursive --year 2026
```

### Filter by IP address

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --ip 203.0.113.25 --year 2026
```

### Filter by username

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --user root --year 2026
```

### Filter by event type

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --event-type ssh_login_failed --year 2026
```

The `--event-type` argument can be repeated to include multiple event types.

### Filter by date

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --from 2026-10-01 --to 2026-10-20 --year 2026
```

Date filters use ISO 8601 format. Dates without an explicit timezone are interpreted using the configured timezone.

### Export a JSON report

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --year 2026 --json /app/data/logs/report.json
```

The generated report will be available on the host at:

```text
data/logs/report.json
```

## Approved SSH IP History

The analyzer supports a persistent baseline of approved SSH source IP addresses.

An unknown IP can generate an alert when a successful SSH login is detected.

**Important:** IP addresses are never automatically trusted based on their appearance in existing logs.

### Initialize an empty baseline

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml ips init
```

### Approve an IP address

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml ips approve 192.168.1.10
```

### List approved IP addresses

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml ips list
```

### Revoke an approved IP address

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml ips revoke 192.168.1.10
```

The baseline is stored at:

```text
data/logs/known_ips.json
```

When no approved baseline exists, unknown-IP detection is skipped. An explicitly initialized empty baseline means that no IP addresses have been approved.

## Report Output

Analysis results include:

- Number of processed files and log lines
- Parsed security events
- Detected security findings
- Severity and detection rule
- Source IP addresses and affected users
- First and last occurrence timestamps
- Related events and recommended actions
- Available event statistics
- File processing or parsing errors

JSON reports can be used for further investigation or integration with external tools.

## Detection Limitations

The analyzer identifies suspicious patterns. A finding does not necessarily confirm an attack or a compromised system.

Some important limitations:

- Traditional syslog timestamps do not contain a year or timezone.
- Authentication logs may contain multiple records for one login attempt.
- IP-based attribution can be affected by NAT, VPNs, proxies, or shared networks.
- An approved IP address does not guarantee that activity from that address is legitimate.
- Analysis is limited to the available log files and their contents.
- The analyzer does not continuously monitor logs.
- It does not automatically block IP addresses or change server configuration.

## Security Considerations

- Treat logs as potentially sensitive information.
- Restrict access to generated reports and the IP history file.
- Use read-only mounts for log sources whenever possible.
- Review unknown IPs before approving them.
- Do not rely on this tool as the only security monitoring mechanism.

## Project Structure

```text
src/
└── logs/
    ├── __init__.py
    ├── models.py
    ├── reader.py
    ├── parser.py
    ├── filters.py
    ├── config.py
    ├── correlation.py
    ├── ip_history.py
    ├── reporter.py
    ├── cli.py
    └── detectors/
        ├── __init__.py
        ├── brute_force.py
        ├── password_spraying.py
        ├── distributed_attack.py
        ├── suspicious_login.py
        ├── privileged_activity.py
        ├── account_changes.py
        └── service_errors.py
```

## Module Status

Implementation files have been provided. Full integration and functional verification are still pending.

Automated tests are outside the current implementation scope and can be added separately.