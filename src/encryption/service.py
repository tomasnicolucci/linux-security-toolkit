import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, TypeVar

from src.encryption.engine import decrypt_stream, encrypt_stream
from src.encryption.format import (
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_KIB,
    DEFAULT_CHUNK_SIZE,
    HEADER_SIZE,
    KDF_ARGON2ID,
    SALT_SIZE,
    EncryptionError,
    Header,
    payload_summary,
)
from src.encryption.keys import KeySource, derive_file_key

ENCRYPTED_SUFFIX = ".enc"
TEMP_PREFIX = ".lstk-"

T = TypeVar("T")


@dataclass(frozen=True)
class Job:
    source: Path
    target: Path | None
    error: str | None = None


@dataclass(frozen=True)
class FileResult:
    action: str
    source: Path
    target: Path | None
    success: bool
    message: str
    size: int = 0


@dataclass(frozen=True)
class FileInfo:
    path: Path
    header: Header
    file_size: int
    blocks: int
    plaintext_size: int


def default_target(source: Path, action: str) -> Path | None:
    if action == "encrypt":
        return source.with_name(source.name + ENCRYPTED_SUFFIX)

    name = source.name

    if name.endswith(ENCRYPTED_SUFFIX) and len(name) > len(ENCRYPTED_SUFFIX):
        return source.with_name(name[: -len(ENCRYPTED_SUFFIX)])

    return None


def walk_directory(root: Path, action: str) -> list[Path]:
    found = []

    for directory, subdirectories, names in os.walk(root, followlinks=False):
        subdirectories.sort()

        for name in sorted(names):
            path = Path(directory) / name

            if path.is_symlink() or not path.is_file():
                continue

            if name.startswith(TEMP_PREFIX):
                continue

            is_encrypted = name.endswith(ENCRYPTED_SUFFIX)

            if (action == "encrypt") == is_encrypted:
                continue

            found.append(path)

    return found


def collect_jobs(
    paths: list[Path],
    action: str,
    recursive: bool,
    output: Path | None,
    exclude: frozenset[Path] = frozenset(),
) -> list[Job]:
    """
    Decide which files to process. Files in `exclude` (the key or
    password file in use) are never processed, so a recursive run
    cannot encrypt its own key.
    """
    if output is not None and len(paths) != 1:
        raise EncryptionError(
            "--output can only be used with a single file."
        )

    jobs = []

    for path in paths:
        if path.is_symlink():
            jobs.append(Job(path, None, "Symbolic links are not supported."))
        elif path.is_dir():
            if output is not None:
                raise EncryptionError(
                    "--output cannot be used with a directory."
                )

            if not recursive:
                jobs.append(
                    Job(path, None, "It is a directory (use --recursive).")
                )
                continue

            for file in walk_directory(path, action):
                if file.resolve() in exclude:
                    continue

                jobs.append(Job(file, default_target(file, action)))
        elif path.is_file():
            target = output or default_target(path, action)

            if path.resolve() in exclude:
                jobs.append(
                    Job(
                        path,
                        None,
                        "It is the key or password file in use.",
                    )
                )
            elif target is None:
                jobs.append(
                    Job(
                        path,
                        None,
                        "Cannot determine the output name; use --output.",
                    )
                )
            else:
                jobs.append(Job(path, target))
        else:
            jobs.append(Job(path, None, "File not found."))

    return jobs


def write_atomic(
    source: Path,
    target: Path,
    force: bool,
    produce: Callable[[BinaryIO], T],
) -> T:
    """
    Write the output to a temporary file in the destination folder and
    move it into place only after it was completely written.
    """
    if target.is_symlink():
        raise EncryptionError("Refusing to write through a symbolic link.")

    if target.is_dir():
        raise EncryptionError("The output path is a directory.")

    if target.resolve() == source.resolve():
        raise EncryptionError("The output file is the same as the input.")

    if target.exists() and not force:
        raise EncryptionError(
            "The output file already exists (use --force to replace it)."
        )

    descriptor, name = tempfile.mkstemp(
        prefix=TEMP_PREFIX,
        suffix=".tmp",
        dir=target.parent,
    )

    temporary = Path(name)

    try:
        with os.fdopen(descriptor, "wb") as writer:
            result = produce(writer)
            writer.flush()
            os.fsync(writer.fileno())

        if target.exists() and not force:
            raise EncryptionError(
                "The output file already exists (use --force to replace it)."
            )

        os.replace(temporary, target)

        return result
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise EncryptionError("Not a regular file.")


def encrypt_file(
    source: Path,
    target: Path,
    key: KeySource,
    force: bool,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    require_regular_file(source)

    uses_password = key.kdf_id == KDF_ARGON2ID

    header = Header(
        kdf_id=key.kdf_id,
        chunk_size=chunk_size,
        kdf_memory_kib=ARGON2_MEMORY_KIB if uses_password else 0,
        kdf_iterations=ARGON2_ITERATIONS if uses_password else 0,
        kdf_lanes=ARGON2_LANES if uses_password else 0,
        salt=os.urandom(SALT_SIZE),
    )

    file_key = derive_file_key(key, header)
    header_bytes = header.pack()

    with source.open("rb") as reader:
        return write_atomic(
            source,
            target,
            force,
            lambda writer: encrypt_stream(
                reader,
                writer,
                file_key,
                header_bytes,
                chunk_size,
            ),
        )


def decrypt_file(
    source: Path,
    target: Path,
    key: KeySource,
    force: bool,
) -> int:
    require_regular_file(source)

    with source.open("rb") as reader:
        header_bytes = reader.read(HEADER_SIZE)
        header = Header.unpack(header_bytes)

        payload_summary(source.stat().st_size, header)

        file_key = derive_file_key(key, header)

        return write_atomic(
            source,
            target,
            force,
            lambda writer: decrypt_stream(
                reader,
                writer,
                file_key,
                header_bytes,
                header.chunk_size,
            ),
        )


def run_job(
    action: str,
    job: Job,
    key: KeySource | None,
    force: bool,
) -> FileResult:
    if job.error or job.target is None or key is None:
        return FileResult(
            action,
            job.source,
            None,
            False,
            job.error or "Nothing to do.",
        )

    try:
        if action == "encrypt":
            size = encrypt_file(job.source, job.target, key, force)
        else:
            size = decrypt_file(job.source, job.target, key, force)
    except EncryptionError as error:
        return FileResult(action, job.source, None, False, str(error))
    except OSError as error:
        return FileResult(
            action,
            job.source,
            None,
            False,
            error.strerror or str(error),
        )

    return FileResult(action, job.source, job.target, True, "OK", size)


def inspect_file(path: Path) -> FileInfo:
    require_regular_file(path)

    with path.open("rb") as reader:
        header = Header.unpack(reader.read(HEADER_SIZE))

    file_size = path.stat().st_size
    blocks, plaintext_size = payload_summary(file_size, header)

    return FileInfo(path, header, file_size, blocks, plaintext_size)