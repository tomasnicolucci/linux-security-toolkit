# Example Workflows

The modules work on their own, but they are designed to complement each other. These workflows show common ways to combine them. All commands use the sample files included in the repository; replace the paths with your own logs and servers.

## 1. Investigate an SSH attack

Detect suspicious activity in an authentication log, find out who is behind the addresses involved, and see whether the activity is increasing.

```bash
# 1. Analyze the log and keep the JSON report
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --year 2026 --json /app/data/logs/report.json

# 2. Investigate every IP address mentioned in the findings
docker compose run --rm security-toolkit ip --config /app/config.yaml analyze --from-report /app/data/logs/report.json --resolve --rdap

# 3. Compare the period with the previous one
docker compose run --rm security-toolkit stats --config /app/config.yaml analyze /app/samples/logs/auth.log --year 2026 --compare-previous
```

Step 2 orders the addresses by severity, shows the rules that involved each one and whether the address is in your approved baseline. Step 3 needs logs that cover both periods, for example rotated files such as `auth.log.1.gz` in a directory.

## 2. Review what a server exposes

Record the listening ports that are expected, detect changes later, and investigate the remote hosts connected to the server.

```bash
# Save the current listening ports as the expected state
docker compose run --rm network-monitor baseline create

# Later: report new listeners, wider exposure and risky services
docker compose run --rm network-monitor scan --baseline

# Investigate the public remote addresses of the established connections
docker compose run --rm -T network-monitor scan --remote-ips | docker compose run --rm -T security-toolkit ip analyze --file - --resolve --rdap
```

To watch for changes continuously and keep a log of events:

```bash
docker compose run --rm network-monitor watch --interval 5 --log /app/data/network/events.jsonl
```

## 3. Audit a new server and keep an eye on it

```bash
# Accounts, privileges, password policy and SSH settings of the host
docker compose run --rm user-auditor --root /host --min-severity HIGH

# Baseline of the SSH configuration files
docker compose run --rm security-toolkit integrity create /host/etc/ssh --name ssh --recursive

# Baseline of the listening ports
docker compose run --rm network-monitor baseline create
```

Later, repeat the checks:

```bash
docker compose run --rm security-toolkit integrity check --name ssh
docker compose run --rm network-monitor scan --baseline --fail-on HIGH
docker compose run --rm user-auditor --root /host --fail-on HIGH
```

## 4. Protect a report before sharing it

```bash
docker compose run --rm security-toolkit encryption encrypt /app/data/logs/report.json
docker compose run --rm security-toolkit encryption info /app/data/logs/report.json.enc
```

The password is requested on the terminal and is never accepted as a command line argument. The original file is not deleted.

## 5. Audit everything and track what changes

The consolidated audit runs the user, network, file integrity and log checks together and writes one report.

```bash
# First audit
docker compose run --rm audit run --root /host

# Later: compare with the previous audit
docker compose run --rm audit run --root /host --previous latest
```

The second report marks every finding as new or unchanged and lists the ones that were resolved. See the [guide](audit-report.md) for the options and for how coverage is reported.

## Running checks on a schedule

`scan`, `integrity check`, the User Auditor and the consolidated audit return a non-zero exit code when they find problems, which makes them easy to run from `cron` or a systemd timer:

```bash
# Every day at 06:00: run the scan; the exit code is 1 when something HIGH or worse appears
0 6 * * * cd /opt/linux-security-toolkit && docker compose run --rm -T network-monitor scan --baseline --fail-on HIGH

# Every day at 07:00: full audit compared with the previous one
0 7 * * * cd /opt/linux-security-toolkit && docker compose run --rm -T audit run --root /host --previous latest --fail-on HIGH
```

| Command | Exit code 0 | Exit code 1 | Exit code 2 |
|---|---|---|---|
| `network scan --fail-on LEVEL` | No finding at that level | A finding reached the level | Error |
| `user-auditor --fail-on LEVEL` | No finding at that level | A finding reached the level | Error |
| `integrity check` | No changes | Changes detected | Error |
| `audit run --fail-on LEVEL` | No finding at that level | A finding reached the level | Error, or no module could be audited |