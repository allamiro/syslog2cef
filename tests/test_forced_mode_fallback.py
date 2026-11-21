"""A forced --mode must not stop a stream at the first line it rejects.

The CLI converts a rejected line as a raw-message event and logs one
warning; library callers keep the old behaviour (ParserError) unless they
pass ``on_parse_error="raw"``.
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from syslogcef import StreamConverter, custom
from syslogcef.parsers import ParserError

REPO_ROOT = Path(__file__).resolve().parent.parent

VALID = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - valid record"
GARBAGE = "garbage that is not RFC 5424"
CONTINUATION = "    continued text"


@pytest.fixture(autouse=True)
def _clean_registry():
    custom.clear_registry()
    yield
    custom.clear_registry()


def run_cli(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "syslogcef", *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def warnings_in(stderr: str) -> list:
    return [line for line in stderr.splitlines() if line.startswith("WARNING:")]


# --- CLI -----------------------------------------------------------------


def test_cli_forced_mode_converts_rejected_line_and_warns_once(tmp_path: Path):
    log = tmp_path / "mixed.log"
    log.write_text(f"{VALID}\n{GARBAGE}\n{GARBAGE} again\n", encoding="utf-8")

    result = run_cli("--mode", "rfc5424", str(log))

    assert result.returncode == 0, result.stderr
    records = result.stdout.splitlines()
    assert len(records) == 3
    assert all(record.startswith("CEF:0|") for record in records)
    assert "shost=mymachine.example.com" in records[0]
    assert f"msg={GARBAGE}" in records[1]
    assert f"cs1={GARBAGE}" in records[1]
    assert f"msg={GARBAGE} again" in records[2]
    # One warning for the first rejected line, naming the mode and quoting
    # the line; the second rejection is DEBUG only.
    assert "Traceback" not in result.stderr
    warnings = warnings_in(result.stderr)
    assert len(warnings) == 1
    assert "'rfc5424'" in warnings[0]
    assert repr(GARBAGE) in warnings[0]
    assert result.stderr.count("\n") == 1


def test_cli_forced_mode_one_valid_one_garbage(tmp_path: Path):
    log = tmp_path / "mixed.log"
    log.write_text(f"{VALID}\n{GARBAGE}\n", encoding="utf-8")

    result = run_cli("--mode", "rfc5424", str(log))

    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == 2
    assert len(warnings_in(result.stderr)) == 1


def test_cli_forced_mode_stdin_does_not_print_extra_stdout():
    result = run_cli("--mode", "rfc5424", stdin=f"{GARBAGE}\n{VALID}\n")

    assert result.returncode == 0, result.stderr
    # stdout carries only CEF; the warning goes to stderr.
    assert [line[:6] for line in result.stdout.splitlines()] == ["CEF:0|", "CEF:0|"]
    assert "rejected" not in result.stdout


def test_cli_forced_mode_stats_counts_rejected_lines_as_unknown(tmp_path: Path):
    log = tmp_path / "mixed.log"
    log.write_text(f"{VALID}\n{GARBAGE}\n", encoding="utf-8")

    result = run_cli("--mode", "rfc5424", "--stats", str(log))

    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == 2
    assert "    unknown  1\n" in result.stderr
    assert "    rfc5424  1\n" in result.stderr
    assert "  unmatched (adaptive or unknown): 1\n    " + GARBAGE + "\n" in result.stderr


def test_cli_forced_mode_rejected_line_still_gets_msg_patterns(tmp_path: Path):
    patterns = tmp_path / "patterns.json"
    patterns.write_text(
        json.dumps({"patterns": [{"name": "acme_action", "match": "msg", "regex": r"action=(?P<act>\w+)"}]}),
        encoding="utf-8",
    )
    mapping = tmp_path / "mapping.json"
    mapping.write_text(json.dumps({"extensions": {"act": "%(act)s"}}), encoding="utf-8")
    log = tmp_path / "mixed.log"
    log.write_text("not a header action=deny\n", encoding="utf-8")

    result = run_cli("--mode", "rfc5424", "--patterns", str(patterns), "--mapping", str(mapping), str(log))

    assert result.returncode == 0, result.stderr
    assert "act=deny" in result.stdout


def test_cli_multiprocess_forced_mode_survives_rejected_line(tmp_path: Path):
    log = tmp_path / "mixed.log"
    log.write_text(f"{VALID}\n{GARBAGE}\n{VALID}\n{GARBAGE}\n", encoding="utf-8")

    result = run_cli("--mode", "rfc5424", "--multiprocess", "--pool-size", "2", str(log))

    assert result.returncode == 0, result.stderr
    records = result.stdout.splitlines()
    assert len(records) == 4
    assert f"msg={GARBAGE}" in records[1]
    assert "Traceback" not in result.stderr
    # Logged by the parent, so once in total rather than once per worker.
    assert len(warnings_in(result.stderr)) == 1


def test_cli_listen_forced_mode_keeps_running_after_garbage_datagram():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proc = subprocess.Popen(
        [sys.executable, "-m", "syslogcef", "--listen", f"udp:127.0.0.1:{port}", "--mode", "rfc5424"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
    )
    # A reader thread drains stdout into a queue: select() on a buffered
    # text pipe misses records already pulled into Python's buffer.
    records: "queue.Queue[str]" = queue.Queue()

    def drain() -> None:
        for record in proc.stdout:
            records.put(record)

    threading.Thread(target=drain, daemon=True).start()
    lines = []
    try:
        deadline = time.monotonic() + 20
        next_send = 0.0
        # Resend the garbage-then-valid pair until both records come back:
        # datagrams sent before the listener binds are lost. A repeated
        # rejection is logged at DEBUG, so the warning count stays at one.
        while not (any("shost=mymachine" in line for line in lines) and any(f"msg={GARBAGE}" in line for line in lines)):
            assert time.monotonic() < deadline, f"no output from syslogcef: {lines!r}"
            assert proc.poll() is None, "syslogcef exited after a rejected datagram"
            if time.monotonic() >= next_send:
                sender.sendto(GARBAGE.encode("utf-8"), ("127.0.0.1", port))
                sender.sendto(VALID.encode("utf-8"), ("127.0.0.1", port))
                next_send = time.monotonic() + 0.5
            try:
                lines.append(records.get(timeout=0.2))
            except queue.Empty:
                pass
        # Still listening after the rejected datagram.
        assert proc.poll() is None
    finally:
        sender.close()
        proc.terminate()
        _, err = proc.communicate(timeout=10)

    assert all(line.startswith("CEF:0|") for line in lines)
    assert "Traceback" not in err
    assert len(warnings_in(err)) == 1


# --- library -------------------------------------------------------------


def test_library_forced_mode_still_raises_by_default():
    converter = StreamConverter(mode="rfc5424")

    with pytest.raises(ParserError):
        converter.convert(GARBAGE)


def test_library_rejects_unknown_on_parse_error():
    with pytest.raises(ValueError, match="on_parse_error"):
        StreamConverter(mode="rfc5424", on_parse_error="bogus")


def test_library_raw_policy_builds_raw_event(caplog):
    converter = StreamConverter(mode="rfc5424", on_parse_error="raw")

    with caplog.at_level(logging.DEBUG, logger="syslogcef.api"):
        cef, event = converter.convert_event(GARBAGE)
        converter.convert(GARBAGE + " again")

    assert cef.startswith("CEF:0|")
    assert event.source_hint == "unknown"
    assert event.host is None
    assert event.pri is None
    assert event.msg == GARBAGE
    assert event.raw == GARBAGE
    records = [r for r in caplog.records if "rejected a line" in r.getMessage()]
    assert [r.levelno for r in records] == [logging.WARNING, logging.DEBUG]


def test_library_raw_policy_truncates_logged_excerpt(caplog):
    long_line = "x" * 5000
    converter = StreamConverter(mode="rfc5424", on_parse_error="raw")

    with caplog.at_level(logging.WARNING, logger="syslogcef.api"):
        converter.convert(long_line)

    (record,) = caplog.records
    assert repr("x" * 200 + "...") in record.getMessage()
    assert "x" * 201 not in record.getMessage()


def test_library_raw_policy_keeps_continuation_inheritance(caplog):
    converter = StreamConverter(mode="rfc5424", on_parse_error="raw")

    with caplog.at_level(logging.WARNING, logger="syslogcef.api"):
        converter.convert(VALID)
        _, event = converter.convert_event(CONTINUATION)

    assert event.source_hint == "continuation"
    assert event.host == "mymachine.example.com"
    assert event.msg == "continued text"
    # A continuation with context is not a rejection.
    assert caplog.records == []


def test_library_raw_policy_rejected_line_does_not_become_context():
    converter = StreamConverter(mode="rfc5424", on_parse_error="raw")

    converter.convert(GARBAGE)
    _, event = converter.convert_event(CONTINUATION)

    # No context yet, so the indented line is itself a rejected line.
    assert event.source_hint == "unknown"
    assert event.host is None


def _crashing_parser(line):
    raise RuntimeError("bug in a registered parser")


def test_forced_registered_parser_crash_is_a_rejected_line():
    # A register_parser() function that raises something other than
    # ParserError must not stop the stream either.
    custom.register_parser("crashy", _crashing_parser)

    with pytest.raises(ParserError) as info:
        StreamConverter(mode="crashy").convert("anything")
    assert isinstance(info.value.__cause__, RuntimeError)

    cef = StreamConverter(mode="crashy", on_parse_error="raw").convert("anything at all")
    assert cef.startswith("CEF:0|")
    assert "anything at all" in cef
