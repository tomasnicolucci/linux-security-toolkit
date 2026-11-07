# Linux Security Toolkit — Consolidated Audit

## Overview

The consolidated audit runs several modules with one command and produces **one report**: an overall status, the coverage of each module, a summary by severity, every finding with its recommended fix, and, if you provide a previous report, what is new and what was resolved.

It uses the existing modules; nothing is reimplemented. Each module can also be used on its own.

## What it runs

| Module | Checks | Runs |
|---|---|---|
| `users` | Accounts, sudo privileges, password policy, SSH settings and file permissions (Linux User Auditor, rules `UA-*`) | By default |
| `network` | Listening ports, connections and processes, and changes against the network baseline (rules `NC-*`) | By default |
| `integrity` | Every saved File Integrity Checker baseline (rules `INT-*`) | By default |
| `logs` | Authentication logs (Log Analyzer rules) | Only with `--logs` |

A module that fails or cannot run never hides the others, and the report always says what could not be checked.

## Usage

With Docker (the `audit` service shares the network and processes of the host and mounts `/etc` read-only at `/host/etc`):

```bash
# Audit the host
docker compose run --rm audit run --root /host

# Try it with the sample files
docker compose run --rm audit run --root /app/samples/system --no-permission-checks

# Include the authentication log (mount /var/log in docker-compose.yaml first)
docker compose run --rm audit run --root /host --logs /host/var/log/auth.log --year 2026

# Compare with the previous audit and fail if something HIGH or worse exists
docker compose run --rm -T audit run --root /host --previous latest --fail-on HIGH
```

Directly on a server, with the dependencies installed (`pip install -r requirements.txt`):

```bash
sudo python3 -m src.cli audit run --integrity-dir /var/lib/toolkit/integrity
```

## Options

| Option | Description |
|---|---|
| `--only MODULES` | Run only these modules (comma separated: `users`, `network`, `integrity`, `logs`) |
| `--skip MODULES` | Leave these modules out |
| `--root PATH` | Root of the audited system for the `users` module (`/host` in Docker; default `/`) |
| `--logs PATH` | Log file or directory; enables the `logs` module |
| `--recursive` | Search the logs directory recursively |
| `--year N` | Year of traditional syslog entries |
| `--config PATH` | Configuration file of the Log Analyzer |
| `--integrity-dir DIR` | Folder with the integrity baselines (default: the one used by `integrity`) |
| `--network-baseline PATH` | Network baseline (default `data/network/baseline.json`) |
| `--no-permission-checks` | Skip the file permission checks of the `users` module |
| `--previous FILE\|latest` | Previous JSON report to compare with; `latest` uses the newest one in the output folder |
| `--format md\|json\|both\|none` | Report files to save (default `both`) |
| `--output-dir DIR` | Where to save the reports (default `data/audit`) |
| `--fail-on LEVEL` | Exit with status 1 when a finding reaches `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` |
| `--proc-root PATH` | Alternative `/proc` directory, used for tests |

## The report

Reports are saved as `audit-YYYYMMDD-HHMMSS.md` (readable, suitable for a ticket) and `audit-YYYYMMDD-HHMMSS.json` (for other tools). A short summary is also printed on the console, with every critical and high severity finding.

### Overall status

| Status | When |
|---|---|
| `critical` | At least one critical finding |
| `attention` | At least one high severity finding and no critical one |
| `no_serious_problems` | No critical or high severity findings |
| `inconclusive` | No module could be audited |

The status is only about the findings. Whether everything could be checked is reported separately as the **coverage**, so a missing check is never presented as a clean result.

### Module status

| Status | Meaning |
|---|---|
| `ok` | The module ran and could check everything |
| `limited` | The module ran, but something could not be checked (for example `/etc/shadow` could not be read, or there is no network baseline). The notes say what |
| `skipped` | There was nothing to check (for example no integrity baselines exist) |
| `error` | The module failed; the message says why |

The audit is **complete** only when every selected module is `ok`.

### Integrity findings

| ID | Finding | Severity |
|---|---|---|
| `INT-001` | File modified (content or permissions) | High |
| `INT-002` | File added | Medium |
| `INT-003` | File deleted | Medium |

For each baseline and kind of change the first 25 files are listed individually, followed by one finding that counts the rest.

### Changes since the previous report

With `--previous`, each finding is marked as new or unchanged, and the findings that disappeared are listed as resolved. A finding keeps its identity between runs even if a process id or a counter in its title changes (for example "not changed for 120 days").

Only modules that ran in both audits are compared. If a module was skipped or failed in one of them, it is reported as not compared; otherwise its old findings would look resolved by mistake.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The audit completed |
| `1` | A finding reached the `--fail-on` level |
| `2` | Usage error, or no module could be audited |

The reports are saved before the console output, so they exist even if the output is cut by a pipe.

## Running only the user auditor from the toolkit

`users audit` runs the Bash User Auditor from the toolkit command line, with the same options:

```bash
docker compose run --rm security-toolkit users audit --root /app/samples/system --no-permission-checks --min-severity HIGH
```

## Security notes

- Reports are created with mode 600 in a folder with mode 700, and an existing report is never replaced.
- Reports never contain password hashes: the user auditor is always run without `--show-hashes`, and only findings are copied.
- Text that comes from the audited system (user names, log content, file names) is cleaned before it is printed, and escaped in the Markdown report so it cannot become formatting, links or HTML.
- The audit does not contact external services. To investigate remote addresses, use the IP Analyzer separately.
- The `audit` Docker service has the privileges of both the User Auditor and the Network Connections Monitor (read-only `/etc`, the network and process space of the host and the `SYS_PTRACE` capability). Run it only on systems you are allowed to audit.

## Limitations

- The audit reads the current state; it does not watch continuously. Schedule it with `cron` or a systemd timer.
- Integrity baselines whose target is not visible from where the audit runs (for example `/etc/ssh` when `/etc` is not mounted) are skipped with a note.
- Reports of different hosts can be compared, but the report warns about it.
- On Docker Desktop (Windows or macOS), "the host" is the Docker virtual machine, not your computer.

## Project Structure

```text
src/
├── audit/
│   ├── models.py
│   ├── adapters.py
│   ├── runner.py
│   ├── comparison.py
│   ├── render.py
│   └── cli.py
└── users/
    ├── user_auditor.sh
    └── cli.py
```