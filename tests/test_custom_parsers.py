from __future__ import annotations

import json
import signal
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from syslogcef import PatternFileError, convert_line, load_patterns, parse_syslog, register_parser
from syslogcef import custom


@pytest.fixture(autouse=True)
def _clean_registry():
    # _mp_load_patterns() ignores SIGINT, as a pool worker should. Called
    # here in the test process, that would leak into every later
    # subprocess (an ignored signal stays ignored across exec), and
    # Ctrl-C tests further on would never see their SIGINT.
    sigint = signal.getsignal(signal.SIGINT)
    custom.clear_registry()
    yield
    custom.clear_registry()
    signal.signal(signal.SIGINT, sigint)


def write_patterns(tmp_path: Path, *entries) -> Path:
    path = tmp_path / "patterns.json"
    path.write_text(json.dumps({"patterns": list(entries)}), encoding="utf-8")
    return path


ACME = {
    "name": "acme_fw",
    "regex": r"^ACME (?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<app>\w+)\[(?P<pid>\d+)\]: (?P<msg>.*)$",
    "timestamp_format": "%Y-%m-%d %H:%M:%S",
}


def test_pattern_file_parses_unknown_format(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    event = parse_syslog("ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed tcp 10.0.0.1 -> 10.0.0.2")

    assert event.source_hint == "custom:acme_fw"
    assert event.host == "fw01"
    assert event.app == "nat"
    assert event.pid == "42"
    assert event.msg.startswith("allowed tcp")
    assert event.ts == datetime(2026, 8, 11, 7, 0, 0, tzinfo=timezone.utc)


def test_pattern_used_as_explicit_mode(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    cef = convert_line("ACME 2026-08-11 07:00:00 fw01 nat[42]: hello", mode="acme_fw")

    assert cef.startswith("CEF:0|")


def test_priority_before_beats_builtin_parsers(tmp_path: Path):
    # This line parses fine as RFC3164; priority=before must win anyway.
    entry = {
        "name": "grabby",
        "regex": r"^<\d+>(?P<msg>.*)$",
        "priority": "before",
    }
    load_patterns(write_patterns(tmp_path, entry))

    event = parse_syslog("<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection")

    assert event.source_hint == "custom:grabby"


def test_priority_after_runs_after_builtins(tmp_path: Path):
    entry = {
        "name": "fallback",
        "regex": r"^(?P<msg>.*)$",
    }
    load_patterns(write_patterns(tmp_path, entry))

    rfc3164 = parse_syslog("<166>Jan  1 12:34:56 router1 app: hello")
    assert rfc3164.source_hint != "custom:fallback"

    weird = parse_syslog("no known parser matches this ~~ shape ~~ at all")
    assert weird.source_hint == "custom:fallback"


def test_iso8601_and_epoch_timestamp_formats(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "iso", "regex": r"^I (?P<ts>\S+) (?P<msg>.*)$", "timestamp_format": "iso8601"},
            {"name": "epoch", "regex": r"^E (?P<ts>[\d.]+) (?P<msg>.*)$", "timestamp_format": "epoch"},
        )
    )

    iso = parse_syslog("I 2026-08-11T07:00:00Z hello", mode="iso")
    assert iso.ts == datetime(2026, 8, 11, 7, 0, 0, tzinfo=timezone.utc)

    epoch = parse_syslog("E 1770000000 hello", mode="epoch")
    assert epoch.ts == datetime.fromtimestamp(1770000000, tz=timezone.utc)


def test_yearless_timestamp_gets_inferred_year(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "noyear", "regex": r"^N (?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<msg>.*)$", "timestamp_format": "%b %d %H:%M:%S"},
        )
    )

    event = parse_syslog("N Aug 11 07:00:00 hello", mode="noyear")

    assert event.ts is not None and event.ts.year != 1900


def test_bad_timestamp_never_drops_the_event(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    event = parse_syslog("ACME 2026-99-99 99:99:99 fw01 nat[1]: bad ts", mode="acme_fw")

    assert event.ts is None
    assert event.msg == "bad ts"


def test_register_parser_programmatic():
    from syslogcef.parsers import ParsedEvent

    def parse_marker(line):
        if not line.startswith("MARK "):
            return None
        return ParsedEvent(
            pri=None, facility=None, severity=None, ts=None, ts_orig="",
            host="marker", app=None, pid=None, msgid=None,
            msg=line[5:], raw=line, source_hint="custom:marker",
        )

    register_parser("marker", parse_marker)

    event = parse_syslog("MARK hello", mode="marker")
    assert event.host == "marker" and event.msg == "hello"

    with pytest.raises(ValueError):
        register_parser("marker", parse_marker)
    with pytest.raises(ValueError):
        register_parser("rfc3164", parse_marker)


@pytest.mark.parametrize(
    "entry, message_part",
    [
        ({"regex": r"^x$"}, "missing 'name'"),
        ({"name": "x"}, "missing 'regex'"),
        ({"name": "x", "regex": "("}, "invalid regex"),
        # Extra named groups are captured fields now; only derived field
        # names are refused.
        ({"name": "x", "regex": r"(?P<severity>\d+)"}, "reserved for derived fields"),
        ({"name": "x", "regex": r"(?P<ts>\d+)"}, "requires 'timestamp_format'"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "timestamp_format": "%Y"}, "no 'ts' group"),
        ({"name": "x", "regex": r"(?P<ts>\d+)", "timestamp_format": "bogus"}, "must be a strptime format"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "priority": "middle"}, "'priority' must be"),
        ({"name": "rfc3164", "regex": r"(?P<msg>.*)"}, "shadows a built-in"),
    ],
)
def test_pattern_file_validation_errors(tmp_path: Path, entry, message_part):
    with pytest.raises(PatternFileError, match=message_part):
        load_patterns(write_patterns(tmp_path, entry))


def test_duplicate_names_rejected(tmp_path: Path):
    entry = {"name": "dup", "regex": r"^(?P<msg>.*)$"}
    with pytest.raises(PatternFileError, match="duplicate name"):
        load_patterns(write_patterns(tmp_path, entry, entry))


def test_out_of_range_epoch_keeps_event(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "epoch2", "regex": r"^E (?P<ts>[\d.]+) (?P<msg>.*)$", "timestamp_format": "epoch"},
        )
    )

    event = parse_syslog("E 99999999999999999999 still here", mode="epoch2")

    assert event.ts is None
    assert event.msg == "still here"


def test_leap_day_yearless_timestamp(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "leap", "regex": r"^L (?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<msg>.*)$", "timestamp_format": "%b %d %H:%M:%S"},
        )
    )

    ref = datetime(2024, 3, 1, tzinfo=timezone.utc)
    event = custom.get_registered("leap")("L Feb 29 12:00:00 leap day", now=ref)

    assert event.ts is not None
    assert (event.ts.month, event.ts.day) == (2, 29)
    assert event.ts.year == 2024


def test_yearless_timestamp_preserves_offset_and_microseconds(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "tzoff", "regex": r"^T (?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2}\.\d+ [+-]\d{4}) (?P<msg>.*)$", "timestamp_format": "%b %d %H:%M:%S.%f %z"},
        )
    )

    event = parse_syslog("T Aug 11 07:00:00.123456 +0530 hello", mode="tzoff")

    assert event.ts is not None
    assert event.ts.microsecond == 123456
    assert event.ts.utcoffset() == timedelta(hours=5, minutes=30)


def test_invalid_strptime_directive_rejected_at_load(tmp_path: Path):
    entry = {"name": "x", "regex": r"(?P<ts>\d+)", "timestamp_format": "%Q"}
    with pytest.raises(PatternFileError, match="unsupported strptime directive"):
        load_patterns(write_patterns(tmp_path, entry))


@pytest.mark.parametrize(
    "entry",
    [
        {"name": "x", "regex": r"(?P<ts>\d+)", "timestamp_format": ["%Y"]},
        {"name": "x", "regex": r"(?P<msg>.*)", "priority": ["before"]},
        {"name": "x", "regex": r"(?P<msg>.*)", "priority": {"value": "before"}},
    ],
)
def test_non_string_fields_rejected_not_typeerror(tmp_path: Path, entry):
    with pytest.raises(PatternFileError):
        load_patterns(write_patterns(tmp_path, entry))


def test_registered_fn_with_local_named_now():
    from syslogcef.parsers import ParsedEvent

    def parse_with_local(line):
        now = "just a local, not a parameter"  # noqa: F841
        if not line.startswith("LOCAL "):
            return None
        return ParsedEvent(
            pri=None, facility=None, severity=None, ts=None, ts_orig="",
            host=None, app=None, pid=None, msgid=None,
            msg=line[6:], raw=line, source_hint="custom:local",
        )

    register_parser("localnow", parse_with_local)

    event = parse_syslog("LOCAL hello", mode="localnow")
    assert event.msg == "hello"


def test_mp_load_patterns_clears_inherited_registry(tmp_path: Path):
    from syslogcef.cli import _mp_load_patterns

    pattern_file = write_patterns(tmp_path, ACME)
    load_patterns(pattern_file)  # parent process load
    # Simulates a fork-start worker inheriting the populated registry:
    # without the internal clear this raises duplicate-name errors.
    _mp_load_patterns([str(pattern_file)])

    event = parse_syslog("ACME 2026-08-11 07:00:00 fw01 nat[42]: ok", mode="acme_fw")
    assert event.source_hint == "custom:acme_fw"


def test_cli_patterns_end_to_end(tmp_path: Path):
    from syslogcef.cli import main

    pattern_file = write_patterns(tmp_path, ACME)
    log = tmp_path / "in.log"
    log.write_text("ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed tcp\n", encoding="utf-8")
    out = tmp_path / "out.cef"

    assert main([str(log), "--patterns", str(pattern_file), "-o", str(out)]) == 0
    assert "CEF:0|" in out.read_text(encoding="utf-8")


def test_cli_rejects_broken_pattern_file(tmp_path: Path):
    from syslogcef.cli import main

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    with pytest.raises(SystemExit):
        main(["--patterns", str(bad)])


def test_cli_rejects_unknown_mode(tmp_path: Path):
    from syslogcef.cli import main

    with pytest.raises(SystemExit):
        main(["--mode", "nonexistent"])

def test_yearless_pattern_timestamp_is_dated_in_the_past(tmp_path: Path):
    # Issue #112: custom patterns share the built-in year inference.
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "past", "regex": r"^P (?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<msg>.*)$", "timestamp_format": "%b %d %H:%M:%S"},
        )
    )
    parse = custom.get_registered("past")

    late_november = datetime(2026, 11, 20, tzinfo=timezone.utc)
    assert parse("P Jan 01 12:34:56 x", now=late_november).ts.year == 2026
    assert parse("P Nov 25 10:00:00 x", now=late_november).ts.year == 2025

    new_years_eve = datetime(2026, 12, 31, 23, 59, 58, tzinfo=timezone.utc)
    assert parse("P Jan 01 00:00:05 x", now=new_years_eve).ts.year == 2027


def _parse_marker(line):
    # Module level so a pool worker can find it by reference.
    from syslogcef.parsers import ParsedEvent

    if not line.startswith("MARK "):
        return None
    return ParsedEvent(
        pri=None, facility=None, severity=None, ts=None, ts_orig="",
        host="marker", app=None, pid=None, msgid=None,
        msg=line[5:], raw=line, source_hint="custom:marker",
    )


def test_mp_load_patterns_keeps_programmatic_parsers(tmp_path: Path):
    # Review on #72: a worker reloads --patterns files, but must not lose
    # parsers a wrapper registered with register_parser().
    from syslogcef.cli import _mp_load_patterns

    register_parser("marker", _parse_marker)
    pattern_file = write_patterns(tmp_path, ACME)
    load_patterns(pattern_file)

    _mp_load_patterns([str(pattern_file)])  # as a fork-started worker does

    assert custom.get_registered("marker") is _parse_marker
    assert parse_syslog("ACME 2026-08-11 07:00:00 fw01 nat[42]: ok", mode="acme_fw").source_hint == "custom:acme_fw"


def test_mp_reload_keeps_a_register_parser_override_of_a_file_pattern(tmp_path: Path):
    # Review on #130: a wrapper loads a pattern file, then overrides one of
    # its names with register_parser(..., replace=True). A fork-started
    # worker reloading the file must keep the override instead of failing
    # with "duplicate name" (which made the pool hang).
    from syslogcef.cli import _mp_load_patterns

    pattern_file = write_patterns(tmp_path, ACME)
    load_patterns(pattern_file)
    register_parser("acme_fw", _parse_marker, replace=True)

    _mp_load_patterns([str(pattern_file)])  # as a fork-started worker does

    assert custom.get_registered("acme_fw") is _parse_marker
    line = "ACME 2026-08-11 07:00:00 fw01 nat[42]: ok"
    # The file's regex stays out of auto-detection, as before the reload.
    assert parse_syslog(line).source_hint != "custom:acme_fw"
    # Reloading again (a second worker, or a pool restart) still works.
    _mp_load_patterns([str(pattern_file)])
    assert custom.get_registered("acme_fw") is _parse_marker


def test_multiprocess_runs_a_programmatic_parser_mode(tmp_path: Path, monkeypatch):
    import multiprocessing

    from syslogcef import cli

    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("needs the fork start method")
    # Fork, so workers inherit the parent's registration as they do by
    # default on Linux before Python 3.14.
    monkeypatch.setattr(cli, "Pool", multiprocessing.get_context("fork").Pool)
    register_parser("marker", _parse_marker)
    pattern_file = write_patterns(tmp_path, ACME)
    load_patterns(pattern_file)

    out = list(
        cli.process_lines(
            ["MARK hello"], mode="marker", mapping=None,
            use_multiprocessing=True, pool_size=1, pattern_files=[str(pattern_file)],
        )
    )

    assert len(out) == 1 and "shost=marker" in out[0]


def test_replacing_a_loaded_pattern_removes_it_from_auto_detection(tmp_path: Path):
    # Review on #72: after register_parser(..., replace=True) the old
    # regex must not keep running under the same name in auto-detection.
    load_patterns(write_patterns(tmp_path, dict(ACME, priority="before")))

    register_parser("acme_fw", _parse_marker, replace=True)

    event = parse_syslog("ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed tcp")
    assert event.source_hint != "custom:acme_fw"
    assert parse_syslog("MARK hi", mode="acme_fw").host == "marker"


def test_escaped_percent_is_not_a_year_directive(tmp_path: Path):
    # Review on #72: "%%Y" is a literal "%Y", so the format has no year and
    # the year must be inferred instead of left at strptime's 1900.
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "literal", "regex": r"^L (?P<ts>%Y-\d{2}-\d{2}) (?P<msg>.*)$", "timestamp_format": "%%Y-%m-%d"},
        )
    )
    parse = custom.get_registered("literal")

    event = parse("L %Y-08-11 hello", now=datetime(2026, 11, 20, tzinfo=timezone.utc))

    assert event.ts == datetime(2026, 8, 11, tzinfo=timezone.utc)
