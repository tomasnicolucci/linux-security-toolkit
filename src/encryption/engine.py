import struct
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.encryption.format import (
    TAG_SIZE,
    AuthenticationError,
    EncryptionError,
)


def block_nonce(counter: int, final: bool) -> bytes:
    """
    Nonce of one block: a 64-bit block counter and a flag marking the
    last block. Every file has its own key, so nonces cannot repeat.
    The flag makes truncated or extended files fail authentication.
    """
    return struct.pack(">QI", counter, 1 if final else 0)


def encrypt_stream(
    reader: BinaryIO,
    writer: BinaryIO,
    key: bytes,
    header: bytes,
    chunk_size: int,
) -> int:
    """
    Encrypt a stream in blocks of chunk_size bytes. The header is
    written first and authenticated with every block. Returns the
    number of plaintext bytes processed.
    """
    cipher = AESGCM(key)
    writer.write(header)

    total = 0
    counter = 0
    current = reader.read(chunk_size)

    while True:
        following = reader.read(chunk_size)
        final = not following

        writer.write(
            cipher.encrypt(
                block_nonce(counter, final),
                current,
                header,
            )
        )

        total += len(current)

        if final:
            return total

        counter += 1
        current = following


def decrypt_stream(
    reader: BinaryIO,
    writer: BinaryIO,
    key: bytes,
    header: bytes,
    chunk_size: int,
) -> int:
    """
    Decrypt a stream produced by encrypt_stream. The reader must be
    positioned right after the header. Returns the number of plaintext
    bytes written.
    """
    cipher = AESGCM(key)
    block_size = chunk_size + TAG_SIZE

    total = 0
    counter = 0
    current = reader.read(block_size)

    if len(current) < TAG_SIZE:
        raise EncryptionError("The file is truncated.")

    while True:
        following = reader.read(block_size)
        final = not following

        try:
            plaintext = cipher.decrypt(
                block_nonce(counter, final),
                current,
                header,
            )
        except InvalidTag as error:
            raise AuthenticationError(
                "Wrong key or corrupted file."
            ) from error

        writer.write(plaintext)
        total += len(plaintext)

        if final:
            return total

        counter += 1
        current = following