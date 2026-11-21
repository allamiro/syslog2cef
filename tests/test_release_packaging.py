"""Checks on the release workflows, packaging scripts and their docs.

These files are not in the sdist the RPM %check runs from, so every test
skips outside a git checkout.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
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


@pytest.mark.parametrize(
    "workflow, job",
    [(".github/workflows/ci.yml", "rpm"), (".github/workflows/release.yml", "build-rpm")],
)
def test_rpm_jobs_install_the_dnf_builddep_plugin(workflow, job):
    # build-rpm.sh runs `dnf builddep`, which DNF5 ships in dnf5-plugins.
    # Install it explicitly rather than relying on the base image.
    job_text = _jobs(workflow)[job]
    assert "bash packaging/rpm/build-rpm.sh" in job_text
    assert re.search(r"dnf install -y[^\n]*(\\\n[^\n]*)*\bdnf5-plugins\b", job_text)


# --- Dependabot auto-merge gate ------------------------------------------


def _step_script(job_text: str, step_name: str) -> str:
    """Return the dedented ``run: |`` block of the named step."""
    step = job_text.split(f"- name: {step_name}", 1)[1]
    block = step.split("run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith(" " * 10):
            break
        lines.append(line[10:])
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    "update_type, expected",
    [
        ("version-update:semver-major", "merge=false"),
        ("security-update:semver-major", "merge=false"),
        ("version-update:semver-minor", "merge=true"),
        ("security-update:semver-patch", "merge=true"),
    ],
)
def test_dependabot_gate_holds_every_major_update(tmp_path, update_type, expected):
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    job = _jobs(".github/workflows/dependabot-auto-merge.yml")["auto-merge"]
    script = _step_script(job, "Decide whether this may merge unattended")
    output = tmp_path / "github_output"
    env = dict(
        os.environ,
        UPDATE_TYPE=update_type,
        DEPENDENCY_NAMES="pytest",
        GITHUB_OUTPUT=str(output),
    )
    subprocess.run(["bash", "-c", script], env=env, check=True)
    assert output.read_text().splitlines()[0] == expected
