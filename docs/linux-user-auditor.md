# Linux Security Toolkit — Linux User Auditor

## Overview

The Linux User Auditor is Module 8 of the Linux Security Toolkit.

It is a read-only audit of user accounts, groups, sudo privileges, password policy and the configuration files that control them. It is written in Bash so it can run directly on a Linux server, without Python or Docker.

The auditor never modifies the system, never runs commands as other users and never tries to crack passwords.

## Requirements

- Bash 4.4 or newer
- GNU coreutils, `grep` and `sed` (present on every mainstream distribution)
- Root privileges to read `/etc/shadow` and `/etc/sudoers`. Without root the audit still runs, reports what it could not read, and skips the checks that depend on it.

## Features

- Inventory of accounts: regular, system, with login shell, locked, without password, expired
- Account checks: UID 0 duplicates, empty passwords, password hashes in `/etc/passwd`, weak hash algorithms, system accounts with interactive shells, password aging, duplicate and orphan entries, malformed lines
- Privilege analysis: who can use sudo (resolving user and command aliases and group membership), passwordless rules, commands that allow shell escapes, wildcards, insecure `Defaults`, and members of root-equivalent groups (`docker`, `lxd`, `disk`, `shadow`)
- Permissions of `passwd`, `shadow`, `group`, `gshadow`, `sudoers`, `sudoers.d` and `sshd_config`
- SSH daemon settings that affect accounts: `PermitRootLogin`, `PermitEmptyPasswords`, `PasswordAuthentication` (first value wins, `Include` honored, `Match` blocks ignored)
- Password policy in `/etc/login.defs`
- Home directories: permissions, ownership, `~/.ssh`, `authorized_keys`, `.rhosts` and `.netrc`
- Login activity: accounts that never logged in or are inactive (uses `lastlog`)
- Console report ordered by severity, JSON export, and exit codes for automation

## Usage

On a server:

```bash
sudo bash src/users/user_auditor.sh
sudo bash src/users/user_auditor.sh --min-severity HIGH
sudo bash src/users/user_auditor.sh --json /var/tmp/user-audit.json
sudo bash src/users/user_auditor.sh --fail-on HIGH
```

With Docker, against the sample files included in the project:

```bash
docker compose run --rm user-auditor --root /app/samples/system --no-permission-checks
```

With Docker, against the host (the `user-auditor` service mounts `/etc` read-only at `/host/etc`):

```bash
docker compose run --rm user-auditor --root /host
```

On Docker Desktop (Windows or macOS), `/etc` belongs to the Docker virtual machine, not to your computer. Use the sample files to try the tool there and run it on a real server for real audits.

## Options

| Option | Description |
|---|---|
| `--root PATH` | Audit the file tree under PATH (default `/`) |
| `--min-severity LEVEL` | Show findings at or above `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` |
| `--fail-on LEVEL` | Exit with status 1 when a finding at or above LEVEL exists |
| `--show-hashes` | Print the password hashes of `/etc/passwd` and `/etc/shadow` |
| `--all-accounts` | List every account in the table |
| `--max-password-age DAYS` | Report passwords older than DAYS (default 365) |
| `--no-permission-checks` | Skip file permission checks (use it with sample trees) |
| `--check-homes` | Check home directories (automatic when `--root` is `/`) |
| `--check-activity` | Check login activity with `lastlog` (automatic when `--root` is `/`) |
| `--inactive-days DAYS` | Inactivity threshold (default 90) |
| `--json PATH` | Save the audit as JSON |
| `--no-color` | Disable colors (the `NO_COLOR` variable is also honored) |

## Password hashes

By default the auditor never prints password hashes: it reports only the algorithm and whether a password is empty, locked or set.

`--show-hashes` adds a table with the hashes stored in `/etc/passwd` and `/etc/shadow` and includes them in the JSON report. Because this is sensitive data:

- the JSON file is created with mode 600
- the console output may remain in terminal history, logs or CI output, so avoid using the option in automated jobs
- hashes must never be shared or committed to a repository

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Audit completed |
| 1 | A finding reached the `--fail-on` severity |
| 2 | Usage error or required files could not be read |

## Findings

| ID | Finding | Severity |
|---|---|---|
| UA-001 | Non-root account with UID 0 | Critical |
| UA-002 | Empty password | Critical with login shell, otherwise Medium |
| UA-003 | Password hash stored in `/etc/passwd` | High |
| UA-004 | Weak or unrecognized hash algorithm | Medium (Low if locked) |
| UA-005 | System account with an interactive shell | Medium |
| UA-006 | Account without an entry in `/etc/shadow` | Medium |
| UA-007 | Shadow entry without an account | Low |
| UA-008 | UID shared by several accounts | High |
| UA-009 | Duplicate user name | High |
| UA-010 | GID shared by several groups | Medium |
| UA-011 | Duplicate group name | Medium |
| UA-012 | Primary group does not exist | Low |
| UA-013 | Group lists an unknown user | Low |
| UA-014 | Malformed or invalid entry | Medium |
| UA-015 | Password never expires | Low |
| UA-016 | Password older than the limit | Low |
| UA-018 | Non-root account with the root group as primary group | Medium |
| UA-020 | Passwordless sudo rule | Medium, High for ALL commands |
| UA-021 | Every user can run any command as root | Critical |
| UA-022 | sudo allows a command that can spawn a root shell | Medium, High without password |
| UA-023 | Wildcard in a sudo command | Medium |
| UA-024 | Insecure sudoers `Defaults` | Medium or High |
| UA-025 | Members of a root-equivalent group | High |
| UA-030 | Insecure permissions on a critical file | Low to Critical |
| UA-040 | SSH root login with password | High |
| UA-041 | SSH accepts empty passwords | Critical |
| UA-042 | SSH password authentication enabled | Low |
| UA-050 | Default maximum password age too long | Low |
| UA-051 | Weak default hash algorithm | Medium |
| UA-060 | Home directory missing | Low |
| UA-061 | Home directory writable by group or others | Medium or High |
| UA-062 | Home directory owned by another user | Medium |
| UA-063 | Insecure `~/.ssh` or `authorized_keys` permissions | Medium or High |
| UA-064 | `.rhosts` or readable `.netrc` file | High or Medium |
| UA-070 | Inactive account | Low |
| UA-071 | Account that never logged in | Low |

## Sample files

`samples/system/etc/` contains a deliberately insecure copy of the account files with fake hashes, so every kind of finding can be demonstrated without touching a real system. Do not use these files on a real machine.

## Limitations

- Only local files are audited. Accounts provided by LDAP, SSSD or NIS are not included.
- The sudoers parser is intentionally simple: it reads the first host specification of each rule, ignores negations and `Host_Alias`/`Runas_Alias`, does not expand netgroups and does not distinguish the scope of `Defaults` entries.
- A sudo command is reported as dangerous when its program is a shell, editor, pager or interpreter known for shell escapes. It does not analyze arguments.
- Login activity depends on the output of `lastlog`, so it runs only on live systems.
- Permission checks use numeric owners, because user names inside a container may not match the host.
- Paths containing spaces are not supported for `--root`.

## Project Structure

```text
src/
└── users/
    └── user_auditor.sh
samples/
└── system/
    └── etc/
```

Shell scripts must use Unix line endings. The repository includes a `.gitattributes` rule for this, and the Docker image normalizes them when it is built.
