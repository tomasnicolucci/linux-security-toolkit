import fnmatch
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from src.integrity.hasher import calculate_sha256


@dataclass(frozen=True)
class FileRecord:
    sha256: str
    size: int
    modified_ns: int
    permissions: str


@dataclass
class ScanResult:
    files: dict[str, dict]
    errors: dict[str, str]


def is_excluded(relative_path: str, patterns: list[str]) -> bool:
    path = Path(relative_path)

    return any(
        fnmatch.fnmatch(relative_path, pattern)
        or fnmatch.fnmatch(path.name, pattern)
        or any(
            fnmatch.fnmatch(part, pattern)
            for part in path.parts
        )
        for pattern in patterns
    )


def scan_target(
    target: Path,
    recursive: bool = False,
    exclusions: list[str] | None = None,
) -> ScanResult:
    exclusions = exclusions or []
    target = target.absolute()

    if target.is_symlink():
        raise ValueError("Symbolic link targets are not supported.")

    if not target.exists():
        raise ValueError(f"Target does not exist: {target}")

    if not target.is_file() and not target.is_dir():
        raise ValueError("Target must be a regular file or directory.")

    files = {}
    errors = {}

    if target.is_file():
        candidates = [(target, target.name)]
    else:
        candidates = []

        def on_walk_error(error: OSError) -> None:
            errors[str(error.filename or target)] = str(error)

        for root, directories, filenames in os.walk(
            target,
            followlinks=False,
            onerror=on_walk_error,
        ):
            root_path = Path(root)

            relative_root = root_path.relative_to(target)

            directories[:] = [
                directory
                for directory in directories
                if not is_excluded(
                    str(relative_root / directory),
                    exclusions,
                )
                and not (root_path / directory).is_symlink()
            ]

            for filename in filenames:
                path = root_path / filename
                relative_path = path.relative_to(target).as_posix()

                if not is_excluded(relative_path, exclusions):
                    candidates.append((path, relative_path))

            if not recursive:
                break

    for path, relative_path in candidates:
        if is_excluded(relative_path, exclusions):
            continue

        try:
            if path.is_symlink():
                errors[relative_path] = "Symbolic link skipped."
                continue

            if not path.is_file():
                errors[relative_path] = "Not a regular file."
                continue

            before = path.stat()
            sha256 = calculate_sha256(path)
            after = path.stat()

            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ino != after.st_ino
            ):
                errors[relative_path] = "File changed during scanning."
                continue

            record = FileRecord(
                sha256=sha256,
                size=after.st_size,
                modified_ns=after.st_mtime_ns,
                permissions=stat.filemode(after.st_mode),
            )

            files[relative_path] = asdict(record)

        except OSError as error:
            errors[relative_path] = str(error)

    return ScanResult(files=files, errors=errors)
