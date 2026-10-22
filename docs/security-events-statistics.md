# Linux Security Toolkit — Security Events Statistics

## Overview

Security Events Statistics is Module 7 of the Linux Security Toolkit.

It reads Linux log files and answers questions the Log Analyzer does not: how much activity there was, when it happened, and how it compares with an earlier period.

The module uses the same file reader, parser and time zone handling as the Log Analyzer, so both modules count exactly the same events.

## Features

- Period summary: total events, SSH failed and successful logins, SSH success rate, privileged activity, privileged failures, account and group changes, service errors, unique source IPs and users
- Distribution of events by type
- Top source IPs and users, with failed and successful logins for each
- Trend by hour or by day, with the peak and a text bar chart
- Comparison with the previous period of equal duration, or with an explicit period
- New and no longer seen source IPs and users
- Console report and JSON export

## Usage

Statistics for all events found:

```bash
docker compose run --rm security-toolkit stats --config /app/config.yaml analyze /app/samples/logs/auth.log --year 2026
```

Statistics for a specific day:

```bash
docker compose run --rm security-toolkit stats --config /app/config.yaml analyze /var/log/auth.log --from 2026-10-19T00:00:00 --to 2026-10-19T23:59:59
```

Compare with the previous period of equal duration:

```bash
docker compose run --rm security-toolkit stats --config /app/config.yaml analyze /app/samples/logs --from 2026-10-19T00:00:00 --to 2026-10-19T23:59:59 --compare-previous
```

Compare with an explicit period:

```bash
docker compose run --rm security-toolkit stats --config /app/config.yaml analyze /app/samples/logs --from 2026-10-19T00:00:00 --to 2026-10-19T23:59:59 --compare-with 2026-10-12T00:00:00 2026-10-12T23:59:59
```

`--config` belongs to the `stats` command and must appear before `analyze`.

## Options

| Option | Description |
|---|---|
| `target` | Log file or directory |
| `--recursive` | Search directories recursively |
| `--year N` | Year for traditional syslog entries |
| `--from DATE` | Start of the period (ISO 8601; default: first event) |
| `--to DATE` | End of the period, inclusive (ISO 8601; default: last event) |
| `--by hour\|day` | Trend granularity (default: hour up to 3 days, otherwise day) |
| `--top N` | Number of IPs and users listed (1 to 100, default 10) |
| `--compare-previous` | Compare with the previous period of equal duration |
| `--compare-with FROM TO` | Compare with an explicit period |
| `--json PATH` | Save the statistics as JSON |

Dates without a time zone are interpreted in the time zone of the configuration file.

## How metrics are counted

- SSH failed logins use the same duplicate removal as the Log Analyzer, so a failed attempt logged twice is counted once.
- The SSH success rate is successful logins divided by successful plus failed logins.
- Percentage changes are not shown when the previous value is 0; the change is marked as `new`.
- A source IP or user is "new" when it appears in the analyzed period and not in the comparison period, and "no longer seen" in the opposite case.
- Trend buckets use local calendar time. Empty buckets are shown so gaps are visible.

## Comparing periods

A comparison needs logs covering both periods, for example rotated files such as `auth.log.1.gz` in a directory. If the logs begin after the start of a period, the report warns that its data may be incomplete. An empty period also produces a warning.

## Limitations

- Traditional syslog timestamps do not contain the year, so `--year` applies to all of them. Logs crossing a year boundary should be analyzed separately.
- All events are loaded in memory.
- The module reports facts; it does not raise alerts or classify activity as an attack. Use the Log Analyzer for detection.
- A period is limited to 400 trend buckets; use `--by day` or a shorter period.

## Project Structure

```text
src/
└── statistics/
    ├── models.py
    ├── loader.py
    ├── periods.py
    ├── metrics.py
    ├── comparison.py
    ├── analyzer.py
    ├── reporter.py
    └── cli.py
```