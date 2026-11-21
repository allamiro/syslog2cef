"""The pattern files shipped under examples/patterns/ must keep passing
their own examples, so the files the docs point people at never rot."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_FILES = ("examples/patterns/sshd.json", "examples/patterns/acme-line.json")


def test_shipped_example_pattern_files_pass_check_patterns():
    # The sdist (and the RPM %check that runs from it) ships no examples/.
    for relpath in EXAMPLE_FILES:
        if not (REPO_ROOT / relpath).exists():
            pytest.skip(f"{relpath} is not in this source tree")

    argv = [sys.executable, "-m", "syslogcef"]
    for relpath in EXAMPLE_FILES:
        argv += ["--patterns", relpath]
    result = subprocess.run(
        argv + ["--check-patterns"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert lines, "no output from --check-patterns"
    assert all(line.startswith("PASS ") for line in lines[:-1]), result.stdout
    total = re.fullmatch(r"(\d+)/(\d+) examples passed", lines[-1])
    assert total is not None, lines[-1]
    passed, examples = int(total.group(1)), int(total.group(2))
    assert passed == examples == len(lines) - 1
    assert examples > 0
    # Both files contribute examples.
    assert any(line.startswith("PASS sshd_auth ") for line in lines)
    assert any(line.startswith("PASS acme_fw ") for line in lines)
