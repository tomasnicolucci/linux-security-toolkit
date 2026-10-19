import ipaddress
import json
import os
import tempfile
from pathlib import Path


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError(f"Invalid IP address: {value}") from error


def load_known_ips(path: Path) -> set[str] | None:
    """None means no approved baseline exists; an empty set is valid."""
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Invalid IP history file: {path}")
    with path.open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("Unsupported IP history format")
    values = payload.get("approved_ips")
    if not isinstance(values, list) or not all(isinstance(ip, str) for ip in values):
        raise ValueError("Invalid approved_ips list")
    return {normalize_ip(ip) for ip in values}


def save_known_ips(path: Path, ips: set[str]) -> None:
    """Atomic replacement; call only following explicit operator approval."""
    if path.is_symlink():
        raise ValueError("IP history cannot be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "approved_ips": sorted(normalize_ip(ip) for ip in ips)}
    descriptor, temporary = tempfile.mkstemp(prefix=".known_ips_", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def approve_ips(path: Path, addresses: list[str]) -> set[str]:
    """Only called by the explicit `ips approve` CLI command."""
    approved = load_known_ips(path)
    if approved is None:
        approved = set()
    approved.update(normalize_ip(ip) for ip in addresses)
    save_known_ips(path, approved)
    return approved


def revoke_ips(path: Path, addresses: list[str]) -> set[str]:
    approved = load_known_ips(path)
    if approved is None:
        raise ValueError("No approved IP baseline exists")
    approved.difference_update(normalize_ip(ip) for ip in addresses)
    save_known_ips(path, approved)
    return approved