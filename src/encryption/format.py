import struct
from dataclasses import dataclass


MAGIC = b"LSTK-ENC"
VERSION = 1

CIPHER_AES_256_GCM = 1

KDF_ARGON2ID = 1
KDF_HKDF_SHA256 = 2

SALT_SIZE = 32
KEY_SIZE = 32
TAG_SIZE = 16

DEFAULT_CHUNK_SIZE = 1024 * 1024
MIN_CHUNK_SIZE = 4096
MAX_CHUNK_SIZE = 16 * 1024 * 1024

# Argon2id parameters used for new files (RFC 9106, second option).
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4

# Limits applied to values read from files, which are untrusted.
MAX_ARGON2_MEMORY_KIB = 1024 * 1024
MAX_ARGON2_ITERATIONS = 20
MAX_ARGON2_LANES = 16

# magic, version, cipher, kdf, reserved, chunk size,
# kdf memory (KiB), kdf iterations, kdf lanes, salt
HEADER_STRUCT = struct.Struct(">8sBBBBIIII32s")
HEADER_SIZE = HEADER_STRUCT.size

KDF_NAMES = {
    KDF_ARGON2ID: "Argon2id (password)",
    KDF_HKDF_SHA256: "HKDF-SHA256 (key file)",
}

CIPHER_NAMES = {
    CIPHER_AES_256_GCM: "AES-256-GCM",
}


class EncryptionError(ValueError):
    """An expected failure that can be reported to the user."""


class AuthenticationError(EncryptionError):
    """The key is wrong or the data was modified."""


@dataclass(frozen=True)
class Header:
    kdf_id: int
    chunk_size: int
    kdf_memory_kib: int
    kdf_iterations: int
    kdf_lanes: int
    salt: bytes
    cipher_id: int = CIPHER_AES_256_GCM
    version: int = VERSION

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            self.cipher_id,
            self.kdf_id,
            0,
            self.chunk_size,
            self.kdf_memory_kib,
            self.kdf_iterations,
            self.kdf_lanes,
            self.salt,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        if len(data) < HEADER_SIZE:
            raise EncryptionError("Not an encrypted file (too short).")

        (
            magic,
            version,
            cipher_id,
            kdf_id,
            reserved,
            chunk_size,
            memory,
            iterations,
            lanes,
            salt,
        ) = HEADER_STRUCT.unpack(data[:HEADER_SIZE])

        if magic != MAGIC:
            raise EncryptionError("Not an encrypted file (bad signature).")

        if version != VERSION:
            raise EncryptionError(
                f"Unsupported file version: {version}."
            )

        if cipher_id not in CIPHER_NAMES or reserved != 0:
            raise EncryptionError("Unsupported or corrupted header.")

        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise EncryptionError("Corrupted header (invalid chunk size).")

        if kdf_id == KDF_ARGON2ID:
            if not (
                8 * lanes <= memory <= MAX_ARGON2_MEMORY_KIB
                and 1 <= iterations <= MAX_ARGON2_ITERATIONS
                and 1 <= lanes <= MAX_ARGON2_LANES
            ):
                raise EncryptionError(
                    "Corrupted header (invalid key derivation parameters)."
                )
        elif kdf_id == KDF_HKDF_SHA256:
            if memory or iterations or lanes:
                raise EncryptionError("Corrupted header.")
        else:
            raise EncryptionError("Unsupported key derivation method.")

        return cls(
            kdf_id=kdf_id,
            chunk_size=chunk_size,
            kdf_memory_kib=memory,
            kdf_iterations=iterations,
            kdf_lanes=lanes,
            salt=salt,
            cipher_id=cipher_id,
            version=version,
        )


def payload_summary(
    file_size: int,
    header: Header,
) -> tuple[int, int]:
    """
    Return (blocks, plaintext size) for an encrypted file of the given
    size. Raises EncryptionError if the size cannot be valid.
    """
    payload = file_size - HEADER_SIZE
    block = header.chunk_size + TAG_SIZE

    if payload < TAG_SIZE:
        raise EncryptionError("The file is truncated.")

    blocks = -(-payload // block)
    plaintext = payload - blocks * TAG_SIZE

    if plaintext < 0:
        raise EncryptionError("The file is truncated.")

    return blocks, plaintext