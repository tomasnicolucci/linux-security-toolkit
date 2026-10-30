import io
import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.encryption import keys
from src.encryption.engine import decrypt_stream, encrypt_stream
from src.encryption.format import (
    HEADER_SIZE,
    KDF_ARGON2ID,
    KDF_HKDF_SHA256,
    TAG_SIZE,
    AuthenticationError,
    EncryptionError,
    Header,
    payload_summary,
)
from src.encryption.keys import (
    KeySource,
    derive_file_key,
    generate_key_file,
    load_key_file,
    load_password_file,
    prompt_password,
)
from src.encryption.service import (
    collect_jobs,
    decrypt_file,
    encrypt_file,
    inspect_file,
    run_job,
    Job,
)
from tests.helpers import requires_linux, run_cli

CHUNK = 4096
SECRET = bytes(range(32))
KEY_SOURCE = KeySource("key-file", SECRET)
HEADER_STRUCT = struct.Struct(">8sBBBBIIII32s")


def make_header(**overrides):
    values = dict(
        kdf_id=KDF_HKDF_SHA256,
        chunk_size=CHUNK,
        kdf_memory_kib=0,
        kdf_iterations=0,
        kdf_lanes=0,
        salt=b"s" * 32,
    )
    values.update(overrides)

    return Header(**values)


def encrypt_bytes(data, chunk=CHUNK):
    header = make_header(chunk_size=chunk)
    key = derive_file_key(KEY_SOURCE, header)
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, key, header.pack(), chunk)

    return out.getvalue()


def decrypt_bytes(blob, chunk=CHUNK):
    header_bytes = blob[:HEADER_SIZE]
    header = Header.unpack(header_bytes)
    key = derive_file_key(KEY_SOURCE, header)
    reader = io.BytesIO(blob)
    reader.seek(HEADER_SIZE)
    out = io.BytesIO()
    decrypt_stream(reader, out, key, header_bytes, header.chunk_size)

    return out.getvalue()


class HeaderTests(unittest.TestCase):
    def test_round_trip(self):
        header = make_header(
            kdf_id=KDF_ARGON2ID,
            kdf_memory_kib=65536,
            kdf_iterations=3,
            kdf_lanes=4,
        )

        self.assertEqual(Header.unpack(header.pack()), header)
        self.assertEqual(len(header.pack()), HEADER_SIZE)

    def test_hostile_headers_are_rejected(self):
        def raw(**fields):
            values = dict(
                magic=b"LSTK-ENC", version=1, cipher=1, kdf=1, reserved=0,
                chunk=1048576, memory=65536, iterations=3, lanes=4,
                salt=b"s" * 32,
            )
            values.update(fields)

            return HEADER_STRUCT.pack(*values.values())

        cases = {
            "bad signature": raw(magic=b"NOTMAGIC"),
            "future version": raw(version=9),
            "unknown cipher": raw(cipher=7),
            "reserved bits": raw(reserved=1),
            "unknown kdf": raw(kdf=7),
            "tiny block size": raw(chunk=10),
            "huge block size": raw(chunk=2**31),
            "huge memory": raw(memory=2**32 - 1),
            "too little memory": raw(memory=8, lanes=4),
            "huge iterations": raw(iterations=10**6),
            "zero lanes": raw(lanes=0),
            "too short": b"LSTK-ENC",
            "hkdf with parameters": raw(kdf=2, memory=5),
        }

        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(EncryptionError):
                    Header.unpack(data)

    def test_payload_summary(self):
        header = make_header()

        self.assertEqual(payload_summary(HEADER_SIZE + TAG_SIZE, header), (1, 0))
        self.assertEqual(
            payload_summary(HEADER_SIZE + CHUNK + 2 * TAG_SIZE + 10, header),
            (2, CHUNK + 10),
        )

        with self.assertRaises(EncryptionError):
            payload_summary(HEADER_SIZE + 5, header)


class EngineTests(unittest.TestCase):
    def test_round_trip_around_block_boundaries(self):
        for size in (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 17):
            with self.subTest(size=size):
                data = os.urandom(size)
                blob = encrypt_bytes(data)
                blocks = max(1, -(-size // CHUNK))

                self.assertEqual(len(blob), HEADER_SIZE + size + TAG_SIZE * blocks)
                self.assertEqual(decrypt_bytes(blob), data)

    def test_plaintext_does_not_appear_in_the_output(self):
        marker = b"TOP-SECRET-MARKER" * 10

        self.assertNotIn(b"TOP-SECRET-MARKER", encrypt_bytes(marker))

    def test_tampering_is_detected(self):
        blob = encrypt_bytes(os.urandom(3 * CHUNK + 5))
        block = CHUNK + TAG_SIZE
        first = blob[HEADER_SIZE:HEADER_SIZE + block]
        second = blob[HEADER_SIZE + block:HEADER_SIZE + 2 * block]
        rest = blob[HEADER_SIZE + 2 * block:]

        def flip(position):
            data = bytearray(blob)
            data[position] ^= 1
            return bytes(data)

        cases = {
            "salt": flip(40),
            "first block": flip(HEADER_SIZE + 100),
            "tag": flip(HEADER_SIZE + block - 1),
            "last block": flip(len(blob) - 5),
            "truncated at a block boundary": blob[:HEADER_SIZE + 2 * block],
            "truncated in the middle": blob[:HEADER_SIZE + block + 500],
            "extra byte": blob + b"\0",
            "swapped blocks": blob[:HEADER_SIZE] + second + first + rest,
            "duplicated block": blob[:HEADER_SIZE] + first + second + second + rest,
        }

        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(EncryptionError):
                    decrypt_bytes(data)

    def test_wrong_key_is_reported_as_authentication_error(self):
        blob = encrypt_bytes(b"data")
        header_bytes = blob[:HEADER_SIZE]
        header = Header.unpack(header_bytes)
        wrong = derive_file_key(KeySource("key-file", b"\x01" * 32), header)
        reader = io.BytesIO(blob)
        reader.seek(HEADER_SIZE)

        with self.assertRaises(AuthenticationError):
            decrypt_stream(reader, io.BytesIO(), wrong, header_bytes, CHUNK)


class KeyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_key_files(self):
        path = self.root / "k.key"

        generate_key_file(path, force=False)

        self.assertEqual(path.stat().st_size, 32)
        self.assertEqual(load_key_file(path).method, "key-file")

        with self.assertRaises(EncryptionError):
            generate_key_file(path, force=False)

        before = path.read_bytes()
        generate_key_file(path, force=True)

        self.assertNotEqual(path.read_bytes(), before)

    @requires_linux
    def test_key_files_are_private(self):
        path = self.root / "k.key"

        generate_key_file(path, force=False)

        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_wrong_size_key_file(self):
        path = self.root / "short.key"
        path.write_bytes(b"x" * 31)

        with self.assertRaises(EncryptionError):
            load_key_file(path)

        with self.assertRaises(EncryptionError):
            load_key_file(self.root / "missing.key")

    def test_password_file_handling(self):
        cases = {
            "secret-password\n": b"secret-password",
            "secret-password\r\n": b"secret-password",
            "secret-password": b"secret-password",
            "with spaces inside\n": b"with spaces inside",
        }

        for text, expected in cases.items():
            with self.subTest(text=text):
                path = self.root / "p.txt"
                path.write_bytes(text.encode())

                self.assertEqual(load_password_file(path, True).secret, expected)

    def test_password_file_errors(self):
        path = self.root / "p.txt"

        for content, strict in ((b"", True), (b"short", True), (b"\xff\xfe", False)):
            with self.subTest(content=content):
                path.write_bytes(content)

                with self.assertRaises(EncryptionError):
                    load_password_file(path, strict)

        path.write_bytes(b"short")

        self.assertEqual(load_password_file(path, False).secret, b"short")

    def test_passwords_are_normalized(self):
        self.assertEqual(
            keys.normalize_password("e\u0301"),
            keys.normalize_password("\u00e9"),
        )

    def test_prompt_needs_a_terminal(self):
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False

            with self.assertRaises(EncryptionError):
                prompt_password(confirm=True)

    def test_prompt_confirmation(self):
        with mock.patch("sys.stdin") as stdin, \
                mock.patch("getpass.getpass", side_effect=["long-password", "long-password"]):
            stdin.isatty.return_value = True

            self.assertEqual(prompt_password(confirm=True).secret, b"long-password")

        with mock.patch("sys.stdin") as stdin, \
                mock.patch("getpass.getpass", side_effect=["long-password", "another-one"]):
            stdin.isatty.return_value = True

            with self.assertRaises(EncryptionError):
                prompt_password(confirm=True)

        with mock.patch("sys.stdin") as stdin, \
                mock.patch("getpass.getpass", return_value="abc"):
            stdin.isatty.return_value = True

            with self.assertRaises(EncryptionError):
                prompt_password(confirm=True)

    def test_each_file_gets_a_different_key(self):
        first = derive_file_key(KEY_SOURCE, make_header(salt=b"a" * 32))
        second = derive_file_key(KEY_SOURCE, make_header(salt=b"b" * 32))

        self.assertNotEqual(first, second)

    def test_using_the_wrong_method_gives_a_clear_message(self):
        password = KeySource("password", b"long-password")

        with self.assertRaises(EncryptionError) as context:
            derive_file_key(password, make_header())

        self.assertIn("key file", str(context.exception))

        argon = make_header(
            kdf_id=KDF_ARGON2ID, kdf_memory_kib=65536, kdf_iterations=3, kdf_lanes=4,
        )

        with self.assertRaises(EncryptionError) as context:
            derive_file_key(KEY_SOURCE, argon)

        self.assertIn("password", str(context.exception))


class ServiceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.password = KeySource("password", b"correct horse battery")

    def write(self, name, data=b"hello"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def leftovers(self):
        return [p.name for p in self.root.rglob(".lstk-*")]

    def test_password_round_trip(self):
        source = self.write("notes.txt", os.urandom(300_000))
        original = source.read_bytes()
        encrypted = self.root / "notes.txt.enc"

        encrypt_file(source, encrypted, self.password, force=False)
        source.unlink()
        decrypt_file(encrypted, source, self.password, force=False)

        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(self.leftovers(), [])

    @requires_linux
    def test_outputs_are_private(self):
        source = self.write("a.txt")
        target = self.root / "a.txt.enc"

        encrypt_file(source, target, KEY_SOURCE, force=False)

        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_wrong_password_leaves_no_output(self):
        source = self.write("a.txt")
        encrypted = self.root / "a.txt.enc"
        encrypt_file(source, encrypted, self.password, force=False)
        source.unlink()

        with self.assertRaises(AuthenticationError):
            decrypt_file(encrypted, source, KeySource("password", b"another password"), force=False)

        self.assertFalse(source.exists())
        self.assertEqual(self.leftovers(), [])

    def test_existing_output_is_protected(self):
        source = self.write("a.txt")
        target = self.write("a.txt.enc", b"precious")

        with self.assertRaises(EncryptionError):
            encrypt_file(source, target, KEY_SOURCE, force=False)

        self.assertEqual(target.read_bytes(), b"precious")

        encrypt_file(source, target, KEY_SOURCE, force=True)

        self.assertNotEqual(target.read_bytes(), b"precious")

    def test_output_cannot_be_the_input(self):
        source = self.write("a.txt")

        with self.assertRaises(EncryptionError):
            encrypt_file(source, source, KEY_SOURCE, force=True)

        self.assertEqual(source.read_bytes(), b"hello")

    @requires_linux
    def test_symbolic_links_are_refused(self):
        source = self.write("a.txt")
        link = self.root / "link.txt"
        link.symlink_to(source)
        victim = self.write("victim.enc", b"keep")
        (self.root / "a.txt.enc").symlink_to(victim)

        with self.assertRaises(EncryptionError):
            encrypt_file(link, self.root / "x.enc", KEY_SOURCE, force=False)

        with self.assertRaises(EncryptionError):
            encrypt_file(source, self.root / "a.txt.enc", KEY_SOURCE, force=True)

        self.assertEqual(victim.read_bytes(), b"keep")

    def test_same_input_gives_different_ciphertexts(self):
        source = self.write("a.txt")

        encrypt_file(source, self.root / "1.enc", KEY_SOURCE, force=False)
        encrypt_file(source, self.root / "2.enc", KEY_SOURCE, force=False)

        self.assertNotEqual(
            (self.root / "1.enc").read_bytes()[HEADER_SIZE:],
            (self.root / "2.enc").read_bytes()[HEADER_SIZE:],
        )

    def test_inspect_does_not_need_the_key(self):
        source = self.write("a.txt", b"x" * 5000)
        encrypted = self.root / "a.txt.enc"
        encrypt_file(source, encrypted, self.password, force=False)

        info = inspect_file(encrypted)

        self.assertEqual(info.plaintext_size, 5000)
        self.assertEqual(info.header.kdf_id, KDF_ARGON2ID)

        with self.assertRaises(EncryptionError):
            inspect_file(source)

    def test_job_planning(self):
        self.write("a.txt")
        self.write("sub/b.txt")
        self.write("sub/c.txt.enc")
        self.write("top.key", b"k" * 32)

        encrypt = collect_jobs([self.root], "encrypt", True, None, frozenset({(self.root / "top.key").resolve()}))
        decrypt = collect_jobs([self.root], "decrypt", True, None)

        self.assertEqual(
            sorted(job.source.name for job in encrypt),
            ["a.txt", "b.txt"],
        )
        self.assertEqual([job.source.name for job in decrypt], ["c.txt.enc"])
        self.assertEqual(decrypt[0].target.name, "c.txt")

    def test_job_planning_errors(self):
        file = self.write("plain.bin")

        jobs = collect_jobs([self.root, self.root / "missing", file], "decrypt", False, None)

        self.assertEqual(
            [job.error for job in jobs],
            [
                "It is a directory (use --recursive).",
                "File not found.",
                "Cannot determine the output name; use --output.",
            ],
        )

        with self.assertRaises(EncryptionError):
            collect_jobs([file, file], "encrypt", False, self.root / "o")

        excluded = collect_jobs([file], "encrypt", False, None, frozenset({file.resolve()}))

        self.assertIn("key or password file", excluded[0].error)

    def test_failures_are_reported_per_file(self):
        result = run_job("encrypt", Job(self.root / "missing", self.root / "x.enc"), KEY_SOURCE, False)

        self.assertFalse(result.success)


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.password = self.root / "password.txt"
        self.password.write_text("correct horse battery staple\n")

    def test_full_workflow_with_a_password(self):
        document = self.root / "doc.txt"
        document.write_text("contenido secreto\n")

        code, output = run_cli("encryption", "encrypt", document, "--password-file", self.password)
        self.assertEqual(code, 0, output)
        self.assertIn("Succeeded: 1", output)

        code, output = run_cli("encryption", "info", self.root / "doc.txt.enc")
        self.assertIn("Argon2id (password)", output)

        document.unlink()
        code, output = run_cli("encryption", "decrypt", self.root / "doc.txt.enc", "--password-file", self.password)

        self.assertEqual(code, 0, output)
        self.assertEqual(document.read_text(), "contenido secreto\n")

    def test_workflow_with_a_key_file_and_wrong_credentials(self):
        key = self.root / "k.key"
        document = self.root / "doc.txt"
        document.write_text("data")

        self.assertEqual(run_cli("encryption", "keygen", key)[0], 0)
        self.assertEqual(run_cli("encryption", "keygen", key)[0], 2)
        self.assertEqual(run_cli("encryption", "encrypt", document, "--key-file", key)[0], 0)
        document.unlink()

        code, output = run_cli("encryption", "decrypt", self.root / "doc.txt.enc", "--password-file", self.password)

        self.assertEqual(code, 2)
        self.assertIn("key file", output)
        self.assertFalse(document.exists())

        code, _ = run_cli("encryption", "decrypt", self.root / "doc.txt.enc", "--key-file", key)

        self.assertEqual(code, 0)
        self.assertEqual(document.read_text(), "data")

    def test_recursive_run_never_encrypts_its_own_key(self):
        vault = self.root / "vault"
        vault.mkdir()
        (vault / "doc.txt").write_text("x")
        key = vault / "k.key"
        run_cli("encryption", "keygen", key)

        code, output = run_cli("encryption", "encrypt", vault, "--recursive", "--key-file", key)

        self.assertEqual(code, 0, output)
        self.assertTrue((vault / "doc.txt.enc").exists())
        self.assertFalse((vault / "k.key.enc").exists())

    def test_without_a_terminal_a_password_cannot_be_requested(self):
        document = self.root / "doc.txt"
        document.write_text("x")

        code, output = run_cli("encryption", "encrypt", document, input_text="")

        self.assertEqual(code, 2)
        self.assertIn("terminal", output)

    def test_conflicting_key_options(self):
        document = self.root / "doc.txt"
        document.write_text("x")

        code, _ = run_cli(
            "encryption", "encrypt", document,
            "--key-file", self.root / "k", "--password-file", self.password,
        )

        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
