# Linux Security Toolkit — File Encryption

## Overview

File Encryption is Module 9 of the Linux Security Toolkit.

It encrypts and decrypts files with authenticated encryption (AES-256-GCM). The key comes from a password or from a random key file. Large files are processed in blocks, so memory use does not depend on the file size.

> The module uses its own file format. It is designed for this project and is not compatible with tools such as OpenSSL, GPG or age. For production secrets, use an audited tool.

## Features

- Encrypt and decrypt one or many files, or whole directories with `--recursive`
- Password protection with Argon2id key derivation
- Key files with 32 random bytes created by `encryption keygen`
- Detection of wrong keys, modified data, truncated files and extra data
- Atomic output: a failed operation never leaves a partial file
- `info` command that shows the header of an encrypted file without needing the key

## Usage

Files must be inside a folder mounted in the container, such as `data/` (available as `/app/data`).

```bash
docker compose run --rm security-toolkit encryption keygen /app/data/encryption/backup.key
docker compose run --rm security-toolkit encryption encrypt /app/data/encryption/notes.txt
docker compose run --rm security-toolkit encryption decrypt /app/data/encryption/notes.txt.enc
docker compose run --rm security-toolkit encryption info /app/data/encryption/notes.txt.enc
docker compose run --rm security-toolkit encryption encrypt /app/data/encryption --recursive --key-file /app/data/encryption/backup.key
```

Without `--key-file` or `--password-file`, the password is requested on the terminal without showing it, and it is asked twice when encrypting.

## Commands

| Command | Description |
|---|---|
| `encryption keygen PATH [--force]` | Create a random key file with mode 600 |
| `encryption encrypt FILE... [options]` | Encrypt files; output is `FILE.enc` |
| `encryption decrypt FILE... [options]` | Decrypt `.enc` files |
| `encryption info FILE` | Show the file header |

Options of `encrypt` and `decrypt`:

| Option | Description |
|---|---|
| `--recursive` | Process the files inside directories |
| `-o`, `--output PATH` | Output file (single input file only) |
| `--force` | Replace existing output files |
| `--key-file PATH` | Use a key file |
| `--password-file PATH` | Read the password from a file |

`--key-file` and `--password-file` cannot be combined. The password is never accepted as a command line argument, because it would remain in the shell history and in the process list.

## Security design

- **Cipher:** AES-256-GCM. The file is split into blocks of 1 MiB. Each block is authenticated.
- **Per-file key:** each file has a random 32-byte salt. With a password, the key is derived with Argon2id (64 MiB, 3 iterations, 4 lanes). With a key file, it is derived with HKDF-SHA256. Two files never share a key, so nonces cannot repeat.
- **Block nonces:** a 64-bit block counter plus a flag that marks the last block. This detects reordered, duplicated, truncated or extended files.
- **Header authentication:** the whole header is authenticated with every block, so changing any header field makes decryption fail.
- **Untrusted headers:** key derivation parameters and block size read from a file are validated against limits before use.
- **Atomic writes:** output goes to a temporary file in the destination folder and is renamed only after it is complete and flushed to disk. Output files have mode 600.
- **No overwriting:** existing files are replaced only with `--force`. Symbolic links are never followed or written through.
- **Key protection:** with `--recursive`, the key file or password file in use is never processed.
- **Generic errors:** a wrong key and a modified file produce the same message, because authenticated encryption cannot distinguish them.

## File format (version 1)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Signature `LSTK-ENC` |
| 8 | 1 | Version |
| 9 | 1 | Cipher (1 = AES-256-GCM) |
| 10 | 1 | Key derivation (1 = Argon2id, 2 = HKDF-SHA256) |
| 11 | 1 | Reserved (0) |
| 12 | 4 | Block size |
| 16 | 4 | Argon2id memory (KiB) |
| 20 | 4 | Argon2id iterations |
| 24 | 4 | Argon2id lanes |
| 28 | 32 | Salt |
| 60 | ... | Blocks: ciphertext of up to one block size plus a 16-byte tag |

All numbers are big-endian.

## Limitations

- The original file is not deleted. Secure deletion is not reliable on SSDs or journaling file systems.
- A lost password or key file cannot be recovered.
- The file name and approximate size are not hidden.
- There is no public-key encryption, key rotation, compression or archive support.
- On Docker for Windows or macOS, bind-mounted files appear to be accessible by everyone, so the warning about key file permissions is expected there.

## Project Structure

```text
src/
└── encryption/
    ├── format.py
    ├── keys.py
    ├── engine.py
    ├── service.py
    ├── reporter.py
    └── cli.py
```