import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.network.models import (
    HIGH,
    LOW,
    MEDIUM,
    Finding,
    NetworkError,
    Snapshot,
)

DEFAULT_BASELINE = Path("data/network/baseline.json")
BASELINE_VERSION = 1
MAX_BASELINE_BYTES = 1_000_000

SCOPE_RANK = {"loopback": 0, "specific": 1, "all": 2}


@dataclass(frozen=True)
class BaselineEntry:
    proto: str
    port: int
    scope: str
    process: str

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.proto, self.port, self.scope)


@dataclass(frozen=True)
class Baseline:
    created_at: str
    host: str
    entries: tuple[BaselineEntry, ...]


def current_entries(snapshot: Snapshot) -> dict[tuple, BaselineEntry]:
    entries: dict[tuple, BaselineEntry] = {}

    for item in snapshot.listeners:
        entry = BaselineEntry(
            item.proto,
            item.local_port,
            item.scope,
            item.process.name if item.process else "",
        )

        existing = entries.get(entry.key)

        if existing is None or (not existing.process and entry.process):
            entries[entry.key] = entry

    return entries


def create_baseline(
    snapshot: Snapshot,
    path: Path,
    force: bool,
) -> int:
    if path.exists() and not force:
        raise NetworkError(
            f"The baseline already exists: {path} (use --force to "
            "replace it)."
        )

    entries = sorted(
        current_entries(snapshot).values(),
        key=lambda entry: (entry.proto, entry.port, entry.scope),
    )

    document = {
        "version": BASELINE_VERSION,
        "created_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "host": snapshot.host,
        "entries": [asdict(entry) for entry in entries],
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, name = tempfile.mkstemp(
        prefix=".baseline-",
        suffix=".tmp",
        dir=path.parent,
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2)
            stream.write("\n")

        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise

    return len(entries)


def load_baseline(path: Path) -> Baseline:
    if not path.is_file():
        raise NetworkError(
            f"Baseline not found: {path} (create it with "
            "'network baseline create')."
        )

    if path.stat().st_size > MAX_BASELINE_BYTES:
        raise NetworkError(f"The baseline is too large: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = tuple(
            BaselineEntry(
                str(item["proto"]),
                int(item["port"]),
                str(item["scope"]),
                str(item.get("process", "")),
            )
            for item in data["entries"]
        )

        if data["version"] != BASELINE_VERSION:
            raise NetworkError("Unsupported baseline version.")

        return Baseline(
            str(data.get("created_at", "")),
            str(data.get("host", "")),
            entries,
        )
    except NetworkError:
        raise
    except (ValueError, KeyError, TypeError) as error:
        raise NetworkError(f"Invalid baseline file: {path}") from error


def listener_finding(
    item,
    baseline: Baseline,
) -> Finding | None:
    """Compare one listening socket with the baseline (NC-004)."""
    known = {entry.key: entry for entry in baseline.entries}
    key = (item.proto, item.local_port, item.scope)
    process = item.process.name if item.process else ""
    subject = f"{item.proto} {item.local}"

    if key in known:
        previous = known[key].process

        if previous and process and previous != process:
            return Finding(
                "NC-004", MEDIUM, subject,
                f"Port {item.local_port} is now served by '{process}'",
                f"The baseline expects '{previous}' on "
                f"{item.proto}/{item.local_port}, but '{process}' is "
                "listening there now.",
                "Confirm the change is intended, then refresh the "
                "baseline with 'network baseline create --force'.",
            )

        return None

    others = [
        entry for entry in baseline.entries
        if entry.proto == item.proto and entry.port == item.local_port
    ]

    if others and SCOPE_RANK[item.scope] > min(
        SCOPE_RANK[entry.scope] for entry in others
    ):
        return Finding(
            "NC-004", HIGH, subject,
            f"Port {item.local_port} is now exposed beyond the baseline",
            f"{item.proto}/{item.local_port} was limited to "
            f"{others[0].scope} in the baseline and now listens on "
            f"{item.scope} interfaces.",
            "Bind the service back to its original address or update "
            "the baseline if the exposure is intended.",
        )

    severity = MEDIUM if item.scope == "loopback" else HIGH

    return Finding(
        "NC-004", severity, subject,
        f"New listener on {item.proto}/{item.local_port}",
        f"{subject} is listening"
        + (f" ({process})" if process else "")
        + " but it is not in the baseline.",
        "Verify the service is expected, then refresh the baseline with "
        "'network baseline create --force'.",
    )


def compare_baseline(
    snapshot: Snapshot,
    baseline: Baseline,
) -> list[Finding]:
    findings = []
    seen = set()

    for item in snapshot.listeners:
        key = (item.proto, item.local_port, item.scope)

        if key in seen:
            continue

        seen.add(key)
        finding = listener_finding(item, baseline)

        if finding:
            findings.append(finding)

    current = set(current_entries(snapshot))
    current_ports = {(proto, port) for proto, port, _ in current}

    for entry in baseline.entries:
        # A port that still listens with another scope was already
        # reported above, so it is not reported again as missing.
        if (
            entry.key not in current
            and (entry.proto, entry.port) not in current_ports
        ):
            findings.append(Finding(
                "NC-005", LOW, f"{entry.proto} {entry.port}",
                f"Expected listener {entry.proto}/{entry.port} is not "
                "running",
                f"The baseline has {entry.proto}/{entry.port} "
                f"({entry.scope}"
                + (f", {entry.process}" if entry.process else "")
                + ") but nothing listens there now.",
                "Check whether the service stopped, or update the "
                "baseline if it was removed on purpose.",
            ))

    return findings