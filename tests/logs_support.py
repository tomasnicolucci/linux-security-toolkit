"""Shared helpers for the test suite."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

IS_LINUX = sys.platform.startswith("linux")

requires_linux = unittest.skipUnless(
    IS_LINUX,
    "This test needs a Linux system.",
)


def project_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment that lets child processes import the project."""
    paths = [str(PROJECT_ROOT)]

    if os.environ.get("PYTHONPATH"):
        paths.append(os.environ["PYTHONPATH"])

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(paths)}
    env.update(extra or {})

    return env


def run_module(
    module: str,
    *args: object,
    cwd: Path | None = None,
    input_text: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Run `python -m module args...` and return (exit code, output)."""
    result = subprocess.run(
        [sys.executable, "-m", module, *map(str, args)],
        cwd=cwd or PROJECT_ROOT,
        env=project_env(extra_env),
        capture_output=True,
        text=True,
        input=input_text,
        timeout=180,
    )

    return result.returncode, result.stdout + result.stderr


def run_cli(*args: object, **kwargs) -> tuple[int, str]:
    return run_module("src.cli", *args, **kwargs)


def real_zxcvbn_available() -> bool:
    try:
        from zxcvbn import zxcvbn

        result = zxcvbn("password")
    except Exception:
        return False

    return isinstance(result, dict) and "score" in result


def real_tldextract_available() -> bool:
    try:
        import tldextract

        extractor = tldextract.TLDExtract(suffix_list_urls=())
        parts = extractor("www.example.co.uk")
    except Exception:
        return False

    return parts.suffix == "co.uk"
