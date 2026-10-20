# Linux Security Toolkit — IP Analyzer

## Overview

The IP Analyzer is Module 6 of the Linux Security Toolkit.

It investigates IPv4 and IPv6 addresses: it classifies them, optionally looks up their reverse DNS record and network ownership, and can analyze the addresses reported by the Log Analyzer.

The module never sends traffic to the analyzed address. Network lookups go only to the DNS resolver and to the public RDAP service, and only when explicitly requested.

## Features

- IPv4 and IPv6 validation and normalization
- Classification: `global`, `private`, `loopback`, `link_local`, `carrier_grade_nat`, `documentation`, `benchmarking`, `multicast`, `unspecified`, `broadcast`, `reserved`
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) analyzed as IPv4
- Reverse pointer name for every address
- Optional reverse DNS lookup (`--resolve`)
- Optional ownership lookup through RDAP (`--rdap`): network name, handle, range, CIDR, country, organization and abuse contact
- Approval status against the baseline shared with the Log Analyzer
- Input from arguments, a file, standard input, or a Log Analyzer JSON report
- Console report and JSON export

## Usage

Offline classification:

```bash
docker compose run --rm security-toolkit ip analyze 8.8.8.8 10.0.0.5 ::1
```

Reverse DNS and ownership information:

```bash
docker compose run --rm security-toolkit ip analyze 8.8.8.8 --resolve --rdap
```

Addresses from a file (one per line; blank lines and `#` comments are ignored):

```bash
docker compose run --rm security-toolkit ip analyze --file /app/data/ips.txt
```

Addresses from standard input:

```bash
echo 1.1.1.1 | docker compose run --rm -T security-toolkit ip analyze --file -
```

Analyze the IPs found in a Log Analyzer report:

```bash
docker compose run --rm security-toolkit logs --config /app/config.yaml analyze /app/samples/logs/auth.log --year 2026 --json /app/data/report.json
docker compose run --rm security-toolkit ip --config /app/config.yaml analyze --from-report /app/data/report.json --resolve --rdap
```

Note that `--config` belongs to the `ip` command and must appear before `analyze`.

## Options

| Option | Description |
|---|---|
| `addresses` | IPv4 or IPv6 addresses to analyze |
| `--file PATH` | File with one address per line (`-` for standard input) |
| `--from-report PATH` | JSON report exported by `logs analyze --json` |
| `--resolve` | Reverse DNS (PTR) lookup |
| `--rdap` | RDAP ownership lookup (global addresses only) |
| `--timeout N` | Timeout in seconds per network lookup (default 5, maximum 60) |
| `--limit N` | Maximum number of addresses analyzed (default 50) |
| `--json PATH` | Save the analysis as JSON |
| `--config PATH` | YAML configuration (before `analyze`); provides the approved IP baseline path |

Addresses from several sources are merged and duplicates are removed. Addresses from a report are ordered by severity and number of findings.

## Approved IP baseline

The module reuses the baseline managed with `logs ips init|approve|revoke|list`. Each address is reported as `approved`, `NOT approved`, or `unknown` when no baseline exists.

## Limitations

- The module does not scan ports or otherwise contact the analyzed address.
- Reverse DNS records are controlled by the owner of the address and are not verified; treat them as information, not proof of identity.
- RDAP depends on an external service (`https://rdap.org`) and on the registry data, which can be incomplete or rate limited. A failed lookup is reported per address and does not stop the analysis.
- RDAP is queried only for globally routable addresses.
- There is no ASN, geolocation or reputation data.
- Results are not cached.

## Security and privacy considerations

- With `--rdap`, the analyzed IP addresses are sent to the RDAP service. Do not use it with addresses you cannot share.
- Text received from DNS, RDAP or input files is sanitized before being printed, to avoid terminal control sequences.
- RDAP requests use HTTPS only, redirects to plain HTTP are blocked, and responses are size limited.

## Project Structure

```text
src/
└── ip/
    ├── models.py
    ├── text.py
    ├── classifier.py
    ├── lookup.py
    ├── sources.py
    ├── analyzer.py
    ├── reporter.py
    └── cli.py
```