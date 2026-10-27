import getpass
import os
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.encryption.format import (
    KDF_ARGON2ID,
    KDF_HKDF_SHA256,
    KEY_SIZE,
    EncryptionError,
    Header,
)

MIN_PASSWORD_LENGTH = 8
MAX_SECRET_FILE_BYTES = 4096

HKDF_INFO = b"linux-security-toolkit file encryption v1"


@dataclass(frozen=True)
class KeySource:
    """Secret used to protect files: a password or a key file."""

    method: str
    secret: bytes
    warnings: tuple[str, ...] = ()

    @property
    def kdf_id(self) -> int:
        if self.method == "password":
            return KDF_ARGON2ID

        return KDF_HKDF_SHA256


def normalize_password(value: str) -> bytes:
    return unicodedata.normalize("NFC", value).encode("utf-8")


def check_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise EncryptionError(
            f"The password must have at least {MIN_PASSWORD_LENGTH} "
            "characters."
        )


def permission_warnings(path: Path, label: str) -> tuple[str, ...]:
    if os.name != "posix":
        return ()

    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return ()

    if mode & 0o077:
        return (
            f"{label} {path} is accessible by other users "
            f"(mode {mode:o}); use chmod 600.",
        )

    return ()


def read_small_file(path: Path, label: str) -> bytes:
    if not path.is_file():
        raise EncryptionError(f"{label} not found: {path}")

    if path.stat().st_size > MAX_SECRET_FILE_BYTES:
        raise EncryptionError(f"{label} is too large: {path}")

    return path.read_bytes()


def load_key_file(path: Path) -> KeySource:
    data = read_small_file(path, "Key file")

    if len(data) != KEY_SIZE:
        raise EncryptionError(
            f"The key file must contain exactly {KEY_SIZE} bytes "
            "(create one with 'encryption keygen')."
        )

    return KeySource(
        "key-file",
        data,
        permission_warnings(path, "Key file"),
    )


def load_password_file(
    path: Path,
    check_strength: bool,
) -> KeySource:
    data = read_small_file(path, "Password file")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EncryptionError(
            "The password file must be UTF-8 text."
        ) from error

    # Only the final line break is removed.
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]

    if not text:
        raise EncryptionError("The password file is empty.")

    if check_strength:
        check_password_strength(text)

    return KeySource(
        "password",
        normalize_password(text),
        permission_warnings(path, "Password file"),
    )


def prompt_password(confirm: bool) -> KeySource:
    if not sys.stdin.isatty():
        raise EncryptionError(
            "No terminal is available to ask for the password. "
            "Use --password-file or --key-file."
        )

    password = getpass.getpass("Password: ")

    if not password:
        raise EncryptionError("The password cannot be empty.")

    if confirm:
        check_password_strength(password)

        if getpass.getpass("Repeat password: ") != password:
            raise EncryptionError("The passwords do not match.")

    return KeySource("password", normalize_password(password))


def generate_key_file(path: Path, force: bool) -> None:
    if path.is_symlink():
        raise EncryptionError(f"Refusing to write through a symlink: {path}")

    if path.exists() and not force:
        raise EncryptionError(
            f"The file already exists: {path} (use --force to replace it)."
        )

    path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC

    if not force:
        flags |= os.O_EXCL

    descriptor = os.open(path, flags, 0o600)

    with os.fdopen(descriptor, "wb") as stream:
        stream.write(os.urandom(KEY_SIZE))

    path.chmod(0o600)


def derive_file_key(source: KeySource, header: Header) -> bytes:
    """Derive the unique key of one file from the secret and its salt."""
    if source.kdf_id != header.kdf_id:
        if header.kdf_id == KDF_ARGON2ID:
            raise EncryptionError(
                "The file was encrypted with a password, "
                "not with a key file."
            )

        raise EncryptionError(
            "The file was encrypted with a key file, "
            "not with a password."
        )

    if header.kdf_id == KDF_ARGON2ID:
        return Argon2id(
            salt=header.salt,
            length=KEY_SIZE,
            iterations=header.kdf_iterations,
            lanes=header.kdf_lanes,
            memory_cost=header.kdf_memory_kib,
        ).derive(source.secret)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=header.salt,
        info=HKDF_INFO,
    ).derive(source.secret)