"""Checks on the release workflows, packaging scripts and their docs.

These files are not in the sdist the RPM %check runs from, so every test
skips outside a git checkout.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
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


# --- Debian maintainer scripts -------------------------------------------


def _write_stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def deb_tree(tmp_path):
    """Stage the .deb with build-deb.sh, keeping the tree instead of packing it."""
    script = _checkout_file("packaging/debian/build-deb.sh")
    if shutil.which("bash") is None or shutil.which("gzip") is None:
        pytest.skip("bash and gzip are required")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # dpkg-deb --build --root-owner-group <stage> <out.deb>
    _write_stub(bin_dir, "dpkg-deb", 'cp -R "$3" "$4"\n')
    pyz = tmp_path / "syslog2cef.pyz"
    pyz.write_text("")
    out = tmp_path / "out"
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    subprocess.run(["bash", str(script), "9.9.9", str(pyz), str(out)], env=env, check=True)
    return out / "syslog2cef_9.9.9-1_all.deb"


def _run_maintainer_script(tree: Path, name: str, args, tmp_path: Path) -> list[str]:
    """Run a maintainer script against stub systemctl/sysusers on a systemd host."""
    bin_dir = tmp_path / "maint-bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "systemctl.log"
    log.write_text("")
    _write_stub(bin_dir, "systemctl", f'echo "$*" >> "{log}"\n')
    _write_stub(bin_dir, "systemd-sysusers", "exit 0\n")
    systemd_dir = tmp_path / "run-systemd-system"
    systemd_dir.mkdir(exist_ok=True)
    source = (tree / "DEBIAN" / name).read_text()
    assert "/run/systemd/system" in source
    patched = tmp_path / name
    patched.write_text(source.replace("/run/systemd/system", str(systemd_dir)))
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    subprocess.run(["sh", str(patched), *args], env=env, check=True)
    return log.read_text().splitlines()


def test_deb_upgrade_restarts_running_services(deb_tree, tmp_path):
    # dpkg runs the old prerm with "upgrade" (which leaves the service
    # running) and then the new postinst with "configure <old-version>".
    # Without a restart the daemon keeps executing the replaced zipapp.
    calls = _run_maintainer_script(deb_tree, "postinst", ["configure", "0.4.1-1"], tmp_path)
    assert "daemon-reload" in calls
    restarts = [c for c in calls if c.startswith("try-restart")]
    assert restarts, calls
    assert "syslogcef.service" in restarts[0].split()
    assert "syslogcef@*.service" in restarts[0].split()
    # The restart must come after systemd has re-read the new unit files.
    assert calls.index("daemon-reload") < calls.index(restarts[0])


def test_deb_fresh_install_does_not_start_the_service(deb_tree, tmp_path):
    calls = _run_maintainer_script(deb_tree, "postinst", ["configure"], tmp_path)
    assert not [c for c in calls if "start" in c], calls


# --- documentation matches what the release produces ----------------------


@pytest.mark.parametrize(
    "doc", ["README.md", "RELEASING.md", "packaging/rpm/README.md", "fuzz/README.md"]
)
def test_docs_use_the_renamed_artifact_filenames(doc):
    # Since 0.4.1 every sdist, SRPM, RPM and zipapp is named syslog2cef-*;
    # only the command, service and paths keep the syslogcef name.
    text = _checkout_file(doc).read_text()
    stale = re.findall(r"syslogcef-(?:\*|X\.Y|\d)[^\s`]*", text)
    assert not stale, f"{doc} references old artifact names: {stale}"


def test_readme_signature_claim_matches_the_release_workflow():
    workflow = _checkout_file(".github/workflows/release.yml").read_text()
    readme = _checkout_file("README.md").read_text()
    detached_globs = re.findall(r"for artifact in ([^;]+); do\s+gpg", workflow)
    assert detached_globs
    rpm_has_detached = any("*.rpm" in globs for globs in detached_globs)
    assert not rpm_has_detached, "update the README signature section"
    # RPMs carry an embedded rpmsign signature, not a detached .asc.
    assert "Every asset ships with a detached" not in readme
    assert "rpm --checksig" in readme


def test_fuzz_readme_reproduces_crashes_from_the_artifact_directory():
    text = _checkout_file("fuzz/README.md").read_text()
    # The documented docker run mounts ./artifacts as the crash directory.
    assert '-v "$PWD/artifacts":/artifacts' in text
    assert "-artifact_prefix=/artifacts/" in text
    repro = re.findall(r"python fuzz/fuzz_convert\.py (\S*crash-\S+)", text)
    assert repro and all(path.startswith("artifacts/") for path in repro), repro


def test_fuzz_corpus_exercises_rsyslog_json_priority_and_program_fields():
    from syslogcef.parsers import parse_rsyslog_json

    corpus = _checkout_file("fuzz/corpus")
    events = []
    for seed in sorted(corpus.iterdir()):
        line = seed.read_text().strip()
        if line.startswith("{"):
            event = parse_rsyslog_json(line)
            assert event is not None, seed.name
            events.append(event)
    # rsyslog's jsonmesg/RSYSLOG_* templates carry pri and programname;
    # without a seed using them the fuzzer starts blind to those paths.
    assert any(e.pri is not None and e.app and e.ts for e in events)
