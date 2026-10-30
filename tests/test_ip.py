import argparse
import contextlib
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.integrity import cli as integrity_cli
from src.integrity.baseline import (
    create_baseline_data,
    load_baseline,
    save_json,
)
from src.integrity.checker import compare_integrity
from src.integrity.hasher import calculate_sha256
from src.integrity.scanner import is_excluded, scan_target
from tests.helpers import requires_linux

EMPTY_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


class TemporaryDirectoryTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, relative, content="data"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path


class HasherTests(TemporaryDirectoryTestCase):
    def test_known_digests(self):
        empty = self.write("empty", "")
        abc = self.write("abc", "abc")

        self.assertEqual(calculate_sha256(empty), EMPTY_SHA256)
        self.assertEqual(
            calculate_sha256(abc),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_large_files_are_read_in_chunks(self):
        path = self.root / "big"
        path.write_bytes(b"x" * (3 * 1024 * 1024 + 5))

        self.assertEqual(len(calculate_sha256(path)), 64)


class ScannerTests(TemporaryDirectoryTestCase):
    def test_exclusion_patterns(self):
        self.assertTrue(is_excluded("a/b/file.log", ["*.log"]))
        self.assertTrue(is_excluded("a/cache/x", ["cache"]))
        self.assertFalse(is_excluded("a/b/file.txt", ["*.log"]))

    def test_non_recursive_scan_ignores_subdirectories(self):
        self.write("top.txt")
        self.write("sub/inner.txt")

        result = scan_target(self.root)

        self.assertEqual(set(result.files), {"top.txt"})
        self.assertEqual(result.errors, {})

    def test_recursive_scan_with_exclusions(self):
        self.write("top.txt")
        self.write("sub/inner.txt")
        self.write("sub/skip.log")
        self.write("cache/data.txt")

        result = scan_target(
            self.root,
            recursive=True,
            exclusions=["*.log", "cache"],
        )

        self.assertEqual(set(result.files), {"top.txt", "sub/inner.txt"})

    def test_records_hash_size_and_permissions(self):
        path = self.write("file.txt", "abc")
        path.chmod(0o640)

        record = scan_target(self.root).files["file.txt"]

        self.assertEqual(record["size"], 3)
        self.assertEqual(
            record["permissions"],
            stat.filemode(path.stat().st_mode),
        )
        self.assertEqual(len(record["sha256"]), 64)

    def test_single_file_target(self):
        path = self.write("one.txt")

        result = scan_target(path)

        self.assertEqual(set(result.files), {"one.txt"})

    def test_rejects_invalid_targets(self):
        with self.assertRaises(ValueError):
            scan_target(self.root / "missing")

    @requires_linux
    def test_symbolic_links_are_never_followed(self):
        target = self.write("real.txt")
        (self.root / "link.txt").symlink_to(target)
        (self.root / "linkdir").symlink_to(self.root, target_is_directory=True)

        result = scan_target(self.root, recursive=True)

        self.assertEqual(set(result.files), {"real.txt"})
        self.assertIn("link.txt", result.errors)

        with self.assertRaises(ValueError):
            scan_target(self.root / "link.txt")


class CheckerTests(TemporaryDirectoryTestCase):
    def test_detects_every_kind_of_change(self):
        for name in ("same", "changed", "removed", "perm"):
            self.write(name, name)

        baseline = scan_target(self.root).files

        self.write("changed", "different content")
        (self.root / "removed").unlink()
        (self.root / "perm").chmod(0o600)
        self.write("new", "new")

        report = compare_integrity(baseline, scan_target(self.root))

        self.assertEqual(report.unchanged, ["same"])
        self.assertEqual(report.modified, ["changed", "perm"])
        self.assertEqual(report.added, ["new"])
        self.assertEqual(report.deleted, ["removed"])
        self.assertEqual(report.to_dict()["summary"]["modified"], 2)

    def test_files_with_errors_are_not_reported_as_deleted(self):
        self.write("a.txt")
        baseline = scan_target(self.root).files
        current = scan_target(self.root)
        current.files.clear()
        current.errors["a.txt"] = "Permission denied"

        report = compare_integrity(baseline, current)

        self.assertEqual(report.deleted, [])
        self.assertEqual(report.errors, {"a.txt": "Permission denied"})

    def test_everything_under_an_unreadable_directory_is_not_deleted(self):
        self.write("locked/a.txt")
        baseline = scan_target(self.root, recursive=True).files
        current = scan_target(self.root, recursive=True)
        current.files.clear()
        current.errors["locked"] = "Permission denied"

        self.assertEqual(compare_integrity(baseline, current).deleted, [])


class BaselineFileTests(TemporaryDirectoryTestCase):
    def valid(self):
        return create_baseline_data(self.root, True, ["*.log"], {})

    def test_round_trip(self):
        path = self.root / "out" / "baseline.json"

        save_json(path, self.valid())
        loaded = load_baseline(path)

        self.assertEqual(loaded["recursive"], True)
        self.assertEqual(loaded["exclusions"], ["*.log"])
        self.assertEqual(loaded["target"], str(self.root.absolute()))

    @requires_linux
    def test_file_is_private_and_no_temporary_files_remain(self):
        path = self.root / "baseline.json"

        save_json(path, self.valid())

        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(
            [item.name for item in self.root.iterdir()],
            ["baseline.json"],
        )

    def test_rejects_invalid_content(self):
        valid = self.valid()
        broken = {
            "not an object": [],
            "wrong version": {**valid, "version": 99},
            "files not an object": {**valid, "files": []},
            "target missing": {**valid, "target": None},
            "recursive not boolean": {**valid, "recursive": "yes"},
            "bad exclusions": {**valid, "exclusions": [1]},
        }

        for name, data in broken.items():
            with self.subTest(name):
                path = self.root / "bad.json"
                path.write_text(json.dumps(data))

                with self.assertRaises(ValueError):
                    load_baseline(path)


class CommandTests(TemporaryDirectoryTestCase):
    def setUp(self):
        super().setUp()
        self.data = self.root / "data"
        self.target = self.root / "target"
        self.target.mkdir()

        patcher = mock.patch.object(integrity_cli, "DATA_DIR", self.data)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_command(self, handler, **kwargs):
        output = io.StringIO()
        code = 0

        with contextlib.redirect_stdout(output):
            try:
                handler(argparse.Namespace(**kwargs))
            except SystemExit as error:
                code = error.code

        return code, output.getvalue()

    def create(self, name="demo", **extra):
        return self.run_command(
            integrity_cli.handle_create,
            target=str(self.target),
            name=name,
            recursive=extra.get("recursive", True),
            exclude=extra.get("exclude", []),
        )

    def check(self, name="demo", output=None):
        return self.run_command(
            integrity_cli.handle_check,
            name=name,
            output=output,
        )

    def test_create_then_check_without_changes(self):
        (self.target / "a.txt").write_text("a")

        code, text = self.create()

        self.assertEqual(code, 0)
        self.assertIn("Files recorded: 1", text)
        self.assertEqual(self.check()[0], 0)

    def test_check_reports_changes_with_exit_code_1(self):
        (self.target / "a.txt").write_text("a")
        self.create()
        (self.target / "a.txt").write_text("changed")
        (self.target / "b.txt").write_text("b")

        report = self.root / "report.json"
        code, text = self.check(output=str(report))

        self.assertEqual(code, 1)
        self.assertIn("[MODIFIED] a.txt", text)
        self.assertIn("[ADDED] b.txt", text)
        self.assertEqual(json.loads(report.read_text())["summary"]["added"], 1)

    def test_update_accepts_the_new_state(self):
        (self.target / "a.txt").write_text("a")
        self.create()
        (self.target / "a.txt").write_text("changed")

        code, _ = self.run_command(integrity_cli.handle_update, name="demo")

        self.assertEqual(code, 0)
        self.assertEqual(self.check()[0], 0)

    def test_create_refuses_to_replace_a_baseline(self):
        self.create()

        with self.assertRaises(ValueError):
            self.create()

    def test_baseline_names_are_validated(self):
        for name in ("../escape", "a/b", "", "x" * 65, "with space"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    integrity_cli.baseline_path(name)

    def test_hash_command(self):
        path = self.target / "abc"
        path.write_text("abc")

        code, text = self.run_command(
            integrity_cli.handle_hash,
            target=str(path),
        )

        self.assertEqual(code, 0)
        self.assertIn("ba7816bf8f01cfea", text)

        with self.assertRaises(ValueError):
            integrity_cli.handle_hash(
                argparse.Namespace(target=str(self.target))
            )


if __name__ == "__main__":
    unittest.main()
