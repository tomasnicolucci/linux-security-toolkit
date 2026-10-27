# Linux Security Toolkit — Network Connections Monitor

## Overview

The Network Connections Monitor is Module 10 of the Linux Security Toolkit.

It shows the open ports and network connections of a Linux machine, identifies the process behind each socket and reports suspicious situations. It is read-only: it never blocks traffic or stops processes.

The module reads the kernel tables in `/proc/net` and links each socket to its process through `/proc/<pid>/fd`. It does not depend on `ss` or `netstat` and uses only the Python standard library, so it can run on a server without installing the other dependencies of the toolkit.

## Features

- TCP and UDP sockets over IPv4 and IPv6 (IPv4-mapped addresses are shown as IPv4)
- For each socket: state, local and remote address, process (PID, name, user, command line)
- Classification of listening ports: all interfaces, loopback only, or a specific address
- Findings with severity and recommendations
- Baseline of expected listening ports and detection of changes
- Continuous monitoring with event log
- Output of public remote IPs to feed the IP Analyzer
- Console report and JSON export

## Usage

On a server (recommended, as root):

```bash
sudo python3 -m src.network scan
sudo python3 -m src.network scan --listening
sudo python3 -m src.network scan --established --pid 1234
sudo python3 -m src.network scan --json /var/tmp/network.json --fail-on HIGH
```

The same commands are available inside the toolkit CLI as `python -m src.cli network ...`.

With Docker (the `network-monitor` service uses the network and process space of the host):

```bash
docker compose run --rm network-monitor scan
docker compose run --rm network-monitor baseline create
docker compose run --rm network-monitor scan --baseline
docker compose run --rm network-monitor watch --interval 5 --log /app/data/network/events.jsonl
```

On Docker Desktop (Windows or macOS) "the host" is the Docker virtual machine, not your computer.

Investigate the remote hosts with the IP Analyzer:

```bash
sudo python3 -m src.network scan --remote-ips | python3 -m src.cli ip analyze --file - --resolve --rdap
```

## Commands

| Command | Description |
|---|---|
| `network scan` | Show listening sockets and connections, and report findings |
| `network baseline create` | Save the current listening ports as the expected state |
| `network baseline show` | Show the baseline |
| `network watch` | Report new and closed listeners and connections |

Options of `scan`:

| Option | Description |
|---|---|
| `--listening` | Only listening sockets |
| `--established` | Only established connections |
| `--proto tcp\|udp` | Only one protocol |
| `--port N` | Only sockets using this port |
| `--pid N` | Only sockets of this process |
| `--limit N` | Rows per table (default 100) |
| `--min-severity LEVEL` | Show findings at or above this level |
| `--fail-on LEVEL` | Exit with status 1 when a finding reaches this level |
| `--max-per-ip N` | Connections with one remote IP that raise a finding (default 100) |
| `--syn-threshold N` | Half-open connections that raise a finding (default 50) |
| `--baseline [PATH]` | Compare with the baseline (default `data/network/baseline.json`) |
| `--remote-ips` | Print only the public remote IPs, one per line |
| `--json PATH` | Save the result as JSON |
| `--proc-root PATH` | Alternative `/proc` directory, used for tests |

Options of `watch`: `--interval SECONDS` (default 5, minimum 1), `--count N` (stop after N checks), `--log PATH` (events as JSON lines, mode 600), `--include-loopback`, `--baseline [PATH]`.

Findings are always computed over all sockets, so display filters do not hide them.

## Findings

| ID | Finding | Severity |
|---|---|---|
| NC-001 | Risky service reachable beyond the local machine (Telnet, FTP, TFTP, rsh, SMB, NFS, RDP, VNC, SNMP, databases, Redis, Memcached, MongoDB, Elasticsearch, Docker API) | Medium to Critical |
| NC-002 | Process running a deleted program file | Low, High or Critical |
| NC-003 | Process running from `/tmp`, `/var/tmp` or `/dev/shm` | High |
| NC-004 | Listener not in the baseline, exposed beyond it, or served by another process | Medium or High |
| NC-005 | Listener of the baseline that is not running | Low |
| NC-006 | Many simultaneous connections with one remote IP | Medium |
| NC-007 | Many half-open (SYN_RECV) connections on a port | Medium |
| NC-008 | Listening socket without a visible process | Low |
| NC-009 | Shell, netcat or socat with a network connection | High |

A deleted program file is rated Low when it is in a system directory, because it is normal after a package update; High when it is elsewhere, Critical when it also listens, and Critical when the program exists only in memory (`memfd`).

## Baseline

`baseline create` records protocol, port, bind scope and process name of every listening socket. Later scans report:

- listeners that were not recorded (High, or Medium if they only listen on loopback)
- a port that was limited to loopback and is now exposed (High)
- a port now served by a different process (Medium)
- recorded listeners that are gone (Low)

The baseline is not replaced unless `--force` is used.

## Privileges

Reading the process of each socket requires root. As a normal user only your own processes are identified, and the report says how many processes could not be inspected. The Docker service adds the `SYS_PTRACE` capability for this reason. On hosts with AppArmor, the default Docker profile may still prevent it; in that case run the module directly on the server.

## Limitations

- Only the network namespace of the host is inspected; sockets inside containers are not.
- UDP sockets bound to ports in the ephemeral range are treated as client sockets, so a UDP service on such a port is not listed as a listener.
- `watch` compares periodic snapshots. Connections that start and end between two checks are not seen.
- The list of risky ports is fixed and based on well-known default ports.
- A deleted program file or a shell with a connection is an indicator, not proof of compromise.

## Project Structure

```text
src/
└── network/
    ├── models.py
    ├── procfs.py
    ├── rules.py
    ├── baseline.py
    ├── service.py
    ├── watch.py
    ├── reporter.py
    ├── cli.py
    └── __main__.py
```