from src.encryption.format import CIPHER_NAMES, KDF_ARGON2ID, KDF_NAMES
from src.encryption.service import FileInfo, FileResult


def format_size(size: int) -> str:
    value = float(size)

    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            if unit == "B":
                return f"{int(value)} {unit}"

            return f"{value:.1f} {unit}"

        value /= 1024

    return f"{size} B"


def print_result(result: FileResult) -> None:
    if result.success:
        print(
            f"[OK] {result.action} {result.source} -> {result.target} "
            f"({format_size(result.size)})"
        )
    else:
        print(f"[FAILED] {result.action} {result.source}: {result.message}")


def print_summary(results: list[FileResult]) -> None:
    succeeded = sum(result.success for result in results)

    print(
        f"Processed: {len(results)} | Succeeded: {succeeded} | "
        f"Failed: {len(results) - succeeded}"
    )


def print_info(info: FileInfo) -> None:
    header = info.header

    print(f"File: {info.path}")
    print(f"  Format version: {header.version}")
    print(f"  Cipher: {CIPHER_NAMES[header.cipher_id]}")
    print(f"  Key derivation: {KDF_NAMES[header.kdf_id]}")

    if header.kdf_id == KDF_ARGON2ID:
        print(
            f"  Argon2id: {header.kdf_memory_kib // 1024} MiB, "
            f"{header.kdf_iterations} iterations, "
            f"{header.kdf_lanes} lanes"
        )

    print(f"  Block size: {format_size(header.chunk_size)}")
    print(f"  Blocks: {info.blocks}")
    print(f"  Encrypted size: {format_size(info.file_size)}")
    print(f"  Original size: {format_size(info.plaintext_size)}")
    print(f"  Salt: {header.salt.hex()}")