"""End-to-end pattern authoring through the command line.

One pattern file exercises everything together: a line pattern written
with shorthands for a header no built-in parser knows, a msg pattern with
an app filter, a mapping referenced by a path relative to the pattern
file, and examples. The CLI runs as a subprocess from an unrelated working
directory, so the relative mapping path must resolve against the pattern
file, not the current directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

VPN_LOGIN = "ACMEVPN 2026-11-21T10:00:00Z gw1 vpnd[77]: login ok for alice from 198.51.100.20 port 50111"
VPN_TUNNEL = "ACMEVPN 2026-11-21T10:00:05Z gw1 vpnd[77]: tunnel up peer=192.0.2.1"
OTHER_APP = "<38>Nov 21 10:00:09 gw1 otherd[5]: login ok for bob from 10.0.0.1 port 1"
RFC_VPN_LOGIN = "<38>Nov 21 10:00:10 gw2 vpnd[8]: login failed for carol from 203.0.113.9 port 40000"
UNKNOWN = "something nobody can parse"
LINES = [VPN_LOGIN, VPN_TUNNEL, OTHER_APP, RFC_VPN_LOGIN, UNKNOWN]

PATTERNS = {
    "patterns": [
        {
            "name": "acme_vpn",
            "description": "Acme VPN gateway header",
            "regex": (
                r"^ACMEVPN %{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} "
                r"%{WORD:app}\[%{INT:pid}\]: (?P<msg>%{GREEDYDATA})$"
            ),
            "timestamp_format": "iso8601",
            "examples": [
                {"line": VPN_TUNNEL, "expect": {"host": "gw1", "app": "vpnd", "pid": 77, "peer": "192.0.2.1"}},
                {"line": OTHER_APP, "matches": False},
            ],
        },
        {
            "name": "vpn_login",
            "match": "msg",
            "app": ["vpnd"],
            "regex": r"^login (?P<outcome>ok|failed) for %{USER:suser} from %{IP:src} port %{PORT:spt}$",
            "mapping": "maps/vpn-mapping.json",
            "examples": [
                {"line": VPN_LOGIN, "expect": {"suser": "alice", "src": "198.51.100.20", "spt": 50111, "outcome": "ok"}},
                {"line": RFC_VPN_LOGIN, "expect": {"suser": "carol", "src": "203.0.113.9", "host": "gw2"}},
                {"line": OTHER_APP, "matches": False},
            ],
        },
    ]
}

MAPPING = {
    "deviceVendor": "Acme",
    "deviceProduct": "VPN",
    "deviceVersion": "1",
    "eventClassId": "vpn.login.%(outcome)s",
    "name": "VPN login %(outcome)s",
    "extensions": {
        "src": "%(src)s",
        "spt": "%(spt)s",
        "suser": "%(suser)s",
        "outcome": "%(outcome)s",
        "shost": "%(host)s",
    },
}


@pytest.fixture
def workspace(tmp_path: Path) -> Dict[str, Path]:
    pattern_dir = tmp_path / "patterns"
    (pattern_dir / "maps").mkdir(parents=True)
    pattern_file = pattern_dir / "vpn.json"
    pattern_file.write_text(json.dumps(PATTERNS, indent=2), encoding="utf-8")
    (pattern_dir / "maps" / "vpn-mapping.json").write_text(json.dumps(MAPPING), encoding="utf-8")
    log = tmp_path / "vpn.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    return {"patterns": pattern_file, "log": log, "cwd": elsewhere}


def run_cli(workspace: Dict[str, Path], *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(REPO_ROOT), env.get("PYTHONPATH")]))
    return subprocess.run(
        [sys.executable, "-m", "syslogcef", "--patterns", str(workspace["patterns"]), *args],
        capture_output=True,
        text=True,
        cwd=str(workspace["cwd"]),
        env=env,
        timeout=60,
    )


def explain_blocks(stdout: str) -> List[List[str]]:
    return [block.split("\n") for block in stdout.rstrip("\n").split("\n\n")]


def test_check_patterns_passes(workspace):
    result = run_cli(workspace, "--check-patterns")

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stderr == ""
    assert result.stdout == (
        "PASS acme_vpn example 1\n"
        "PASS acme_vpn example 2\n"
        "PASS vpn_login example 1\n"
        "PASS vpn_login example 2\n"
        "PASS vpn_login example 3\n"
        "5/5 examples passed\n"
    )


def test_explain_shows_patterns_mapping_and_captured_fields(workspace):
    result = run_cli(workspace, "--explain", str(workspace["log"]))

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    blocks = explain_blocks(result.stdout)
    assert [block[0] for block in blocks] == [f"--- line {n}" for n in range(1, len(LINES) + 1)]

    login, tunnel, other, rfc_login, unknown = blocks

    assert login[1:6] == [
        f"raw:     {VPN_LOGIN}",
        "parser:  custom:acme_vpn",
        "pattern: acme_vpn",
        "msg pattern: vpn_login",
        "mapping: pattern vpn_login",
    ]
    for field in ("src = 198.51.100.20", "spt = 50111", "suser = alice", "outcome = ok", "host = gw1", "app = vpnd"):
        assert f"  {field}" in login
    assert login[-1].startswith("cef:     CEF:0|Acme|VPN|1|vpn.login.ok|VPN login ok|")

    assert tunnel[2:5] == ["parser:  custom:acme_vpn", "pattern: acme_vpn", "msg pattern: -"]
    assert tunnel[5].startswith("mapping: auto ")
    assert "  peer = 192.0.2.1" in tunnel

    # The app filter keeps the msg pattern off other programs' lines.
    assert other[2:5] == ["parser:  rfc3164", "pattern: -", "msg pattern: -"]
    assert not any(line.startswith("  suser = ") for line in other)

    # A msg pattern applies after a built-in parser too.
    assert rfc_login[2:6] == ["parser:  rfc3164", "pattern: -", "msg pattern: vpn_login", "mapping: pattern vpn_login"]
    assert "  suser = carol" in rfc_login

    assert unknown[3:5] == ["pattern: -", "msg pattern: -"]


def test_stats_shows_msg_pattern_section(workspace):
    result = run_cli(workspace, "--stats", str(workspace["log"]))

    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == len(LINES)
    stats = result.stderr.splitlines()
    assert stats[0] == f"syslogcef: {len(LINES)} lines"
    assert stats[1] == "  by parser:"
    assert "    custom:acme_vpn  2" in stats
    assert "    rfc3164  2" in stats
    section = stats.index("  by msg pattern:")
    assert stats[section + 1] == "    vpn_login  2"
    assert stats[section + 2].startswith("  unmatched (adaptive or unknown): ")


def test_conversion_emits_captures_through_pattern_mapping(workspace):
    result = run_cli(workspace, str(workspace["log"]))

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    login, tunnel, other, rfc_login, _ = result.stdout.splitlines()

    assert login.startswith("CEF:0|Acme|VPN|1|vpn.login.ok|VPN login ok|")
    extension = login.split("|", 7)[7]
    for pair in ("src=198.51.100.20", "spt=50111", "suser=alice", "outcome=ok", "shost=gw1"):
        assert pair in extension.split(" ")

    assert rfc_login.startswith("CEF:0|Acme|VPN|1|vpn.login.failed|VPN login failed|")
    assert "suser=carol" in rfc_login and "src=203.0.113.9" in rfc_login

    # Lines the msg pattern did not match keep automatic mapping selection.
    for cef in (tunnel, other):
        assert not cef.startswith("CEF:0|Acme|VPN|")
        assert "suser=" not in cef


def test_explicit_mapping_overrides_pattern_mapping(workspace, tmp_path: Path):
    override = tmp_path / "override.json"
    override.write_text(
        json.dumps({"deviceVendor": "Override", "deviceProduct": "Test", "extensions": {"duser": "%(suser)s"}}),
        encoding="utf-8",
    )

    result = run_cli(workspace, "--mapping", str(override), str(workspace["log"]))

    assert result.returncode == 0, result.stderr
    login = result.stdout.splitlines()[0]
    assert login.startswith("CEF:0|Override|Test|")
    assert "duser=alice" in login
