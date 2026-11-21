"""Tests for the --explain and --stats introspection flags."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from syslogcef import custom, explain
from syslogcef.api import StreamConverter, normalize_event, parse_syslog
from syslogcef.mappings import CISCO_ASA, LINUX

REPO_ROOT = Path(__file__).resolve().parent.parent
ASA_MAPPING = REPO_ROOT / "syslogcef" / "mappings" / "cisco_asa.json"

RFC3164 = "<34>Oct 11 22:14:15 mymachine su[123]: user=alice action=login"
ASA = "<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"
ADAPTIVE = "2020/04/23 12:32:48 fw-edge-01 session established peer=10.0.0.1"


def run_cli(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "syslogcef", *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def blocks(stdout: str) -> list:
    return stdout.rstrip("\n").split("\n\n")


# --- --explain ---------------------------------------------------------------

def test_explain_rfc3164_block_format():
    result = run_cli("--explain", stdin=RFC3164 + "\n")

    assert result.returncode == 0, result.stderr
    lines = result.stdout.rstrip("\n").split("\n")
    assert lines[:7] == [
        "--- line 1",
        "raw:     " + RFC3164,
        "parser:  rfc3164",
        "pattern: -",
        "msg pattern: -",
        "mapping: auto linux",
        "fields:",
    ]
    assert lines[-1].startswith("cef:     CEF:0|Linux|Syslog|")
    field_lines = lines[7:-1]
    assert field_lines, "expected at least one field"
    assert all(line.startswith("  ") and " = " in line for line in field_lines)
    keys = [line[2:].split(" = ", 1)[0] for line in field_lines]
    assert keys == sorted(keys)
    assert "raw" not in keys
    assert "  host = mymachine" in field_lines
    assert "  app = su" in field_lines
    assert "  user = alice" in field_lines


def test_explain_asa_line_auto_mapping_and_block_separation():
    result = run_cli("--explain", stdin=RFC3164 + "\n" + ASA + "\n")

    assert result.returncode == 0, result.stderr
    first, second = blocks(result.stdout)
    assert first.startswith("--- line 1\n")
    assert second.startswith("--- line 2\n")
    assert "\nmapping: auto cisco_asa\n" in second
    assert "\n  event_code = ASA-6-302013\n" in second
    assert "\ncef:     CEF:0|Cisco|ASA|" in second


def test_explain_with_explicit_mapping():
    result = run_cli("--explain", "--mapping", str(ASA_MAPPING), stdin=RFC3164 + "\n")

    assert result.returncode == 0, result.stderr
    assert "\nmapping: --mapping\n" in result.stdout
    assert "\ncef:     CEF:0|Cisco|ASA|" in result.stdout


def test_explain_custom_line_pattern_parser(tmp_path: Path):
    patterns = tmp_path / "p.json"
    patterns.write_text(
        json.dumps({"patterns": [{"name": "acme", "regex": r"^ACME (?P<host>\S+) (?P<msg>.*)$"}]}),
        encoding="utf-8",
    )
    result = run_cli("--explain", "--patterns", str(patterns), stdin="ACME fw01 hello world\n")

    assert result.returncode == 0, result.stderr
    assert "\nparser:  custom:acme\n" in result.stdout
    assert "\n  host = fw01\n" in result.stdout


@pytest.mark.parametrize(
    "extra",
    [["--send", "udp://127.0.0.1:9"], ["--output", "out.cef"], ["--multiprocess"]],
)
def test_explain_rejected_combinations(extra, tmp_path: Path):
    result = subprocess.run(
        [sys.executable, "-m", "syslogcef", "--explain", *extra],
        input=RFC3164 + "\n",
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )

    assert result.returncode == 2
    assert f"--explain cannot be combined with {extra[0]}" in result.stderr
    assert result.stdout == ""
    assert not (tmp_path / "out.cef").exists()


# --- --stats -----------------------------------------------------------------

def test_stats_counts_sorting_and_unmatched_samples():
    stdin = "\n".join([RFC3164, ASA, RFC3164, ADAPTIVE]) + "\n"
    result = run_cli("--stats", stdin=stdin)

    assert result.returncode == 0, result.stderr
    assert result.stderr.rstrip("\n").split("\n") == [
        "syslogcef: 4 lines",
        "  by parser:",
        "    rfc3164  3",
        "    adaptive  1",
        "  unmatched (adaptive or unknown): 1",
        "    " + ADAPTIVE,
    ]


def test_stats_stdout_still_only_cef():
    stdin = "\n".join([RFC3164, ASA, ADAPTIVE]) + "\n"
    plain = run_cli(stdin=stdin)
    with_stats = run_cli("--stats", stdin=stdin)

    assert plain.returncode == with_stats.returncode == 0
    assert with_stats.stdout == plain.stdout
    out_lines = with_stats.stdout.rstrip("\n").split("\n")
    assert len(out_lines) == 3
    assert all(line.startswith("CEF:0|") for line in out_lines)
    assert "syslogcef: 3 lines" not in with_stats.stdout
    assert with_stats.stderr.startswith("syslogcef: 3 lines\n")


def test_stats_with_output_file(tmp_path: Path):
    out = tmp_path / "out.cef"
    result = run_cli("--stats", "--output", str(out), stdin=RFC3164 + "\n")

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert out.read_text(encoding="utf-8").startswith("CEF:0|")
    assert result.stderr.startswith("syslogcef: 1 lines\n")


def test_stats_with_explain():
    result = run_cli("--stats", "--explain", stdin=RFC3164 + "\n")

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("--- line 1\n")
    assert "syslogcef:" not in result.stdout
    assert result.stderr.startswith("syslogcef: 1 lines\n")


@pytest.mark.skipif(sys.platform == "win32", reason="needs SIGINT delivery")
def test_stats_printed_when_tail_is_interrupted(tmp_path: Path):
    log = tmp_path / "in.log"
    log.write_text(RFC3164 + "\n" + ADAPTIVE + "\n", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "syslogcef", "--tail", "--stats", str(log)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
    )
    try:
        # --tail flushes every record, so two lines mean both were counted.
        assert proc.stdout.readline().startswith("CEF:0|")
        assert proc.stdout.readline().startswith("CEF:0|")
        proc.send_signal(signal.SIGINT)
        _, err = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()

    assert err.startswith("syslogcef: 2 lines\n  by parser:\n")
    assert "  unmatched (adaptive or unknown): 1\n    " + ADAPTIVE + "\n" in err


def test_stats_rejected_with_multiprocess():
    result = run_cli("--stats", "--multiprocess", stdin=RFC3164 + "\n")

    assert result.returncode == 2
    assert "--stats cannot be combined with --multiprocess" in result.stderr
    assert result.stdout == ""


def test_convert_unchanged_without_flags():
    stdin = "\n".join([RFC3164, ASA]) + "\n"
    result = run_cli(stdin=stdin)

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.rstrip("\n").split("\n") == [
        StreamConverter().convert(RFC3164),
        StreamConverter().convert(ASA),
    ]


# --- StreamConverter.convert_event -------------------------------------------

def test_convert_event_matches_convert():
    converter = StreamConverter()
    cef, event = converter.convert_event(ASA)

    assert cef == StreamConverter().convert(ASA)
    assert event.source_hint == "rfc3164"
    assert event.kv["event_code"] == "ASA-6-302013"


def test_convert_event_tracks_continuation_context():
    converter = StreamConverter()
    converter.convert_event(RFC3164, source="a")
    _, event = converter.convert_event("  continued text", source="a")

    assert event.source_hint == "continuation"
    assert event.host == "mymachine"


# --- explain.py helpers ------------------------------------------------------

def test_truncate():
    assert explain.truncate("short") == "short"
    assert explain.truncate("x" * 200) == "x" * 200
    assert explain.truncate("x" * 201) == "x" * 200 + "..."
    assert explain.truncate("abcdef", 3) == "abc..."


def test_bundled_name_is_identity_based():
    assert explain.bundled_name(CISCO_ASA) == "cisco_asa"
    assert explain.bundled_name(LINUX) == "linux"
    assert explain.bundled_name(dict(LINUX)) is None


def test_mapping_label_explicit_and_auto():
    asa = normalize_event(parse_syslog(ASA))
    linux = normalize_event(parse_syslog(RFC3164))

    assert explain.mapping_label(asa, {"name": "x"}) == "--mapping"
    assert explain.mapping_label(asa) == "auto cisco_asa"
    assert explain.mapping_label(linux) == "auto linux"


def test_mapping_label_pattern_mapping(monkeypatch):
    event = normalize_event(parse_syslog(RFC3164))

    monkeypatch.setattr(custom, "mapping_for", lambda ev: ("sshd_auth", LINUX), raising=False)
    assert explain.mapping_label(event) == "pattern sshd_auth"
    assert explain.mapping_label(event, CISCO_ASA) == "--mapping"

    monkeypatch.setattr(custom, "mapping_for", lambda ev: None, raising=False)
    assert explain.mapping_label(event) == "auto linux"


def test_format_explain_reads_pattern_attributes_and_truncates():
    event = normalize_event(parse_syslog(RFC3164))
    event.extras["long"] = "y" * 250
    event.pattern = "line_pat"
    event.msg_pattern = "msg_pat"

    text = explain.format_explain(7, event, "CEF:0|x", "auto linux")
    lines = text.split("\n")

    assert lines[0] == "--- line 7"
    assert lines[3] == "pattern: line_pat"
    assert lines[4] == "msg pattern: msg_pat"
    assert "  long = " + "y" * 200 + "..." in lines
    assert lines[-1] == "cef:     CEF:0|x"
    assert not text.endswith("\n")


def _fake(hint: str, raw: str = "", msg_pattern=None):
    return SimpleNamespace(source_hint=hint, raw=raw, msg_pattern=msg_pattern)


def test_stats_format_sorting_msg_patterns_and_sample_limit():
    stats = explain.Stats()
    for i in range(7):
        stats.add(_fake("unknown", raw=f"junk {i}"))
    stats.add(_fake("adaptive", raw="z" * 300))
    for _ in range(2):
        stats.add(_fake("rfc5424", msg_pattern="sshd"))
        stats.add(_fake("rfc3164", msg_pattern="cron"))
    stats.add(_fake("rfc3164", msg_pattern="sshd"))

    assert stats.format().split("\n") == [
        "syslogcef: 13 lines",
        "  by parser:",
        "    unknown  7",
        "    rfc3164  3",
        "    rfc5424  2",
        "    adaptive  1",
        "  by msg pattern:",
        "    sshd  3",
        "    cron  2",
        "  unmatched (adaptive or unknown): 8",
        "    junk 0",
        "    junk 1",
        "    junk 2",
        "    junk 3",
        "    junk 4",
    ]


def test_stats_format_empty_and_without_msg_pattern_attribute():
    assert explain.Stats().format().split("\n") == [
        "syslogcef: 0 lines",
        "  by parser:",
        "  unmatched (adaptive or unknown): 0",
    ]
    stats = explain.Stats()
    stats.add(SimpleNamespace(source_hint="kv", raw="a=b"))
    assert "by msg pattern" not in stats.format()
