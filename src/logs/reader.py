import gzip
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


LOG_EXTENSIONS = (
    ".log",
    ".log.gz",
)

LOG_NAMES = {
    "auth.log",
    "secure",
    "syslog",
    "messages",
    "journal.log",
}

MAX_LINE_LENGTH = 65536


@dataclass(frozen=True)
class LogLine:
    source: str
    line_number: int
    content: str


@dataclass
class LogReadResult:
    files: list[Path] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def is_log_file(path: Path) -> bool:
    name = path.name.lower()

    if name in LOG_NAMES:
        return True

    if any(name.endswith(extension) for extension in LOG_EXTENSIONS):
        return True

    for base_name in LOG_NAMES:
        if name.startswith(f"{base_name}."):
            suffix = name[len(base_name) + 1:]

            if suffix.isdigit():
                return True

            if suffix.endswith(".gz"):
                rotation = suffix[:-3]
                return rotation.isdigit()

    return False


def discover_log_files(
    target: Path,
    recursive: bool = False,
) -> LogReadResult:
    target = target.absolute()
    result = LogReadResult()

    if target.is_symlink():
        raise ValueError("Symbolic link targets are not supported.")

    if not target.exists():
        raise ValueError(f"Log target does not exist: {target}")

    if target.is_file():
        result.files.append(target)
        return result

    if not target.is_dir():
        raise ValueError(
            "Log target must be a regular file or directory."
        )

    def on_walk_error(error: OSError) -> None:
        source = str(error.filename or target)
        result.errors[source] = str(error)

    for root, directories, filenames in os.walk(
        target,
        followlinks=False,
        onerror=on_walk_error,
    ):
        root_path = Path(root)

        directories[:] = [
            directory
            for directory in directories
            if not (root_path / directory).is_symlink()
        ]

        for filename in filenames:
            path = root_path / filename

            if path.is_symlink():
                continue

            if is_log_file(path):
                result.files.append(path)

        if not recursive:
            break

    result.files.sort(key=lambda path: str(path))
    return result


def read_log_lines(
    path: Path,
) -> Iterator[LogLine]:
    path = path.absolute()

    if path.is_symlink():
        raise ValueError(
            f"Symbolic link not allowed: {path}"
        )

    file_stat = path.stat()

    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(
            f"Not a regular file: {path}"
        )

    opener = gzip.open if path.name.endswith(".gz") else open

    with opener(
        path,
        mode="rt",
        encoding="utf-8",
        errors="replace",
    ) as file:
        for line_number, line in enumerate(file, start=1):
            if len(line) > MAX_LINE_LENGTH:
                raise ValueError(
                    f"Line {line_number} exceeds maximum length "
                    f"({MAX_LINE_LENGTH} characters): {path}"
                )

            yield LogLine(
                source=str(path),
                line_number=line_number,
                content=line.rstrip("\r\n"),
            )
