import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


BASELINE_VERSION = 1


def create_baseline_data(
    target: Path,
    recursive: bool,
    exclusions: list[str],
    files: dict,
) -> dict:
    return {
        "version": BASELINE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target.absolute()),
        "recursive": recursive,
        "exclusions": exclusions,
        "files": files,
    }


def save_json(path: Path, data: dict) -> None:
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".integrity-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.chmod(temporary_path, 0o600)

            json.dump(data, temporary, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())

        os.replace(temporary_path, path)

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def load_baseline(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Invalid baseline format.")

    if data.get("version") != BASELINE_VERSION:
        raise ValueError("Unsupported baseline version.")

    if not isinstance(data.get("files"), dict):
        raise ValueError("Baseline contains invalid file records.")

    if not isinstance(data.get("target"), str):
        raise ValueError("Baseline target is missing.")

    if not isinstance(data.get("recursive"), bool):
        raise ValueError("Baseline recursive setting is invalid.")

    if not isinstance(data.get("exclusions"), list) or not all(
        isinstance(item, str) for item in data["exclusions"]
    ):
        raise ValueError("Baseline exclusions are invalid.")

    return data
