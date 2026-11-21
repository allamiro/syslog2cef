"""Checks on the release workflows, packaging scripts and their docs.

These files are not in the sdist the RPM %check runs from, so every test
skips outside a git checkout.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

RELEASE_BUILD_JOBS = {"build-python", "build-rpm", "build-standalone", "build-apk"}


def _checkout_file(relpath: str) -> Path:
    path = REPO_ROOT / relpath
    if not path.exists():
        pytest.skip(f"{relpath} is not in this source tree")
    return path


def _jobs(workflow: str) -> dict[str, str]:
    """Split a workflow's ``jobs:`` section into {job id: job text}."""
    text = _checkout_file(workflow).read_text()
    jobs_section = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\n", jobs_section, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def _needs(job_text: str) -> set[str]:
    match = re.search(r"^    needs: *(.+)$", job_text, flags=re.M)
    if not match:
        return set()
    return {name.strip() for name in match.group(1).strip("[] ").split(",")}


# --- release workflow ordering -------------------------------------------


def test_container_image_is_pushed_only_after_the_release_builds():
    jobs = _jobs(".github/workflows/release.yml")
    assert RELEASE_BUILD_JOBS <= _needs(jobs["build-docker"])
    # ...and the GitHub release, which promises an image, waits for it.
    assert "build-docker" in _needs(jobs["github-release"])


def test_pypi_publishes_only_after_every_release_build():
    # PyPI versions are immutable: publishing before a failing RPM, Debian,
    # APK or image build leaves a version that can never be re-released.
    needs = _needs(_jobs(".github/workflows/release.yml")["publish-pypi"])
    assert RELEASE_BUILD_JOBS | {"build-docker"} <= needs
