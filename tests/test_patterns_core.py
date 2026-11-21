"""Pattern authoring core: captured fields, msg patterns, per-pattern
mappings, example structure, and load-time validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from syslogcef import PatternFileError, convert_line, load_patterns, normalize_event, parse_syslog, to_cef
from syslogcef import custom
from syslogcef.cli import process_lines
from syslogcef.mappings import CISCO_ASA
from syslogcef.parsers import ParsedEvent

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)

SSHD_LINE = "<38>Jan  2 03:04:05 web01 sshd[123]: Failed password for root from 10.0.0.1 port 2222 ssh2"
CRON_LINE = "<38>Jan  2 03:04:05 web01 cron[9]: Failed password for root from 10.0.0.1 port 2222 ssh2"

SSHD_FAILED = {
    "name": "sshd_failed",
    "match": "msg",
    "app": "sshd",
    "regex": r"Failed password for (?P<suser>\S+) from (?P<src>[\d.]+) port (?P<spt>\d+)",
}

ACME = {
    "name": "acme_fw",
    "regex": (
        r"^ACME (?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
        r"(?P<app>\w+)\[(?P<pid>\d+)\]: (?P<action>\w+) (?P<src_ip>[\d.]+) -> (?P<dst>[\d.]+)(?P<rest>.*)$"
    ),
    "timestamp_format": "%Y-%m-%d %H:%M:%S",
}
ACME_LINE = "ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed 10.0.0.1 -> 10.0.0.2 proto=tcp"

SRC_MAPPING = {
    "deviceVendor": "Acme",
    "deviceProduct": "Firewall",
    "name": "%(action)s",
    "extensions": {"src": "%(src)s", "dst": "%(dst)s", "act": "%(action)s"},
}


@pytest.fixture(autouse=True)
def _clean_registry():
    custom.clear_registry()
    yield
    custom.clear_registry()


def write_patterns(directory: Path, *entries, name: str = "patterns.json") -> Path:
    path = directory / name
    path.write_text(json.dumps({"patterns": list(entries)}), encoding="utf-8")
    return path


def write_mapping(path: Path, mapping=SRC_MAPPING) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mapping), encoding="utf-8")
    return path


def cef_ext(cef: str) -> str:
    return cef.split("|", 7)[7]


# --- line pattern captures -------------------------------------------------


def test_line_pattern_extra_groups_become_fields(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    event = parse_syslog(ACME_LINE)

    assert event.pattern == "acme_fw"
    assert event.msg_pattern is None
    assert event.source_hint == "custom:acme_fw"
    # Envelope groups stay in the envelope, never in fields.
    assert event.host == "fw01" and event.app == "nat" and event.pid == "42"
    assert event.fields == {
        "action": "allowed",
        "src_ip": "10.0.0.1",
        "dst": "10.0.0.2",
        "rest": " proto=tcp",
    }


def test_optional_group_that_did_not_participate_is_skipped(tmp_path: Path):
    entry = {"name": "opt", "regex": r"^OPT (?P<a>\w+)(?: (?P<b>\w+))?$"}
    load_patterns(write_patterns(tmp_path, entry))

    assert parse_syslog("OPT one").fields == {"a": "one"}
    assert parse_syslog("OPT one two").fields == {"a": "one", "b": "two"}


def test_capture_reaches_cef_through_mapping_template(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    cef = convert_line(ACME_LINE, mapping=SRC_MAPPING)

    assert cef.startswith("CEF:0|Acme|Firewall|")
    assert "|allowed|" in cef
    ext = cef_ext(cef)
    # src comes from the src_ip capture via alias canonicalization.
    assert "src=10.0.0.1" in ext
    assert "dst=10.0.0.2" in ext
    assert "act=allowed" in ext


def test_capture_alias_is_canonicalized(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    normalized = normalize_event(parse_syslog(ACME_LINE))

    assert normalized.kv["src_ip"] == "10.0.0.1"
    assert normalized.kv["src"] == "10.0.0.1"
    fields = normalized.as_field_dict()
    assert fields["src"] == "10.0.0.1"
    assert fields["action"] == "allowed"
    # The message's own key=value text still parses alongside captures.
    assert fields["proto"] == "tcp"


def test_capture_wins_over_message_kv_and_raw_kv_excludes_captures(tmp_path: Path):
    entry = {"name": "kvish", "regex": r"^KV (?P<host>\S+) (?P<msg>user=(?P<user>\w+) .*)$"}
    load_patterns(write_patterns(tmp_path, entry))
    event = parse_syslog("KV box user=alice src=1.1.1.1")
    event.fields["user"] = "bob"  # a capture that disagrees with the text

    normalized = normalize_event(event)

    assert normalized.kv["user"] == "bob"
    assert normalized.kv["suser"] == "bob"
    assert normalized.extras["raw_kv"] == "user=alice src=1.1.1.1"
    assert normalized.fields == {"user": "bob"}
    assert normalized.pattern == "kvish"


def test_line_captures_are_sanitized_like_the_message(tmp_path: Path):
    entry = {"name": "nul", "regex": r"^NUL (?P<tag>\S+) (?P<msg>.*)$"}
    load_patterns(write_patterns(tmp_path, entry))

    normalized = normalize_event(parse_syslog("NUL a\x00b hello"))

    assert "\x00" not in normalized.kv["tag"]
    assert "\x00" not in normalized.fields["tag"]
    assert "\x00" not in to_cef(normalized, SRC_MAPPING)


def test_normalize_carries_pattern_metadata(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME, SSHD_FAILED))

    normalized = normalize_event(parse_syslog(ACME_LINE))
    assert normalized.pattern == "acme_fw"
    assert normalized.msg_pattern is None

    normalized = normalize_event(parse_syslog(SSHD_LINE))
    assert normalized.pattern is None
    assert normalized.msg_pattern == "sshd_failed"
    assert normalized.fields == {"suser": "root", "src": "10.0.0.1", "spt": "2222"}


def test_events_without_patterns_have_empty_defaults():
    event = parse_syslog(SSHD_LINE)
    assert event.fields == {} and event.pattern is None and event.msg_pattern is None
    normalized = normalize_event(event)
    assert normalized.fields == {} and normalized.pattern is None and normalized.msg_pattern is None


# --- msg patterns ----------------------------------------------------------


def test_msg_pattern_after_builtin_rfc3164(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED))

    event = parse_syslog(SSHD_LINE)

    assert event.source_hint == "rfc3164"
    assert event.msg_pattern == "sshd_failed"
    assert event.fields == {"suser": "root", "src": "10.0.0.1", "spt": "2222"}
    # The parsed envelope is untouched.
    assert event.app == "sshd" and event.host == "web01"
    assert event.msg.startswith("Failed password")

    ext = cef_ext(convert_line(SSHD_LINE, mapping=CISCO_ASA))
    assert "src=10.0.0.1" in ext and "spt=2222" in ext


def test_msg_pattern_app_filter_non_match(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED))

    event = parse_syslog(CRON_LINE)

    assert event.app == "cron"
    assert event.msg_pattern is None
    assert event.fields == {}


def test_msg_pattern_app_filter_is_case_insensitive_and_accepts_lists(tmp_path: Path):
    entry = dict(SSHD_FAILED, app=["SSHD", "Cron"])
    load_patterns(write_patterns(tmp_path, entry))

    assert custom.loaded_patterns()[0].apps == ("sshd", "cron")
    assert parse_syslog(SSHD_LINE).msg_pattern == "sshd_failed"
    assert parse_syslog(CRON_LINE).msg_pattern == "sshd_failed"
    assert parse_syslog(SSHD_LINE.replace("sshd[123]", "SshD[123]")).msg_pattern == "sshd_failed"
    assert parse_syslog(SSHD_LINE.replace("sshd[123]", "login[1]")).msg_pattern is None


def test_msg_pattern_without_app_filter_applies_to_any_app(tmp_path: Path):
    entry = {k: v for k, v in SSHD_FAILED.items() if k != "app"}
    load_patterns(write_patterns(tmp_path, entry))

    assert custom.loaded_patterns()[0].apps == ()
    assert parse_syslog(CRON_LINE).msg_pattern == "sshd_failed"


def test_msg_pattern_with_app_filter_skips_events_without_app(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED))

    event = parse_syslog("Failed password for root from 10.0.0.1 port 2222 ssh2")

    assert event.app is None
    assert event.msg_pattern is None


def test_msg_pattern_uses_search_not_match(tmp_path: Path):
    entry = {"name": "anywhere", "match": "msg", "regex": r"port (?P<spt>\d+)"}
    load_patterns(write_patterns(tmp_path, entry))

    assert parse_syslog(SSHD_LINE).fields == {"spt": "2222"}


def test_msg_pattern_after_forced_mode(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED))

    event = parse_syslog(SSHD_LINE, mode="rfc3164", now=NOW)

    assert event.source_hint == "rfc3164"
    assert event.msg_pattern == "sshd_failed"
    assert event.fields["src"] == "10.0.0.1"


def test_msg_pattern_after_line_pattern_and_fields_merge(tmp_path: Path):
    line_entry = {
        "name": "acme_ssh",
        "regex": r"^ACME (?P<host>\S+) (?P<app>\w+): (?P<msg>.*) via (?P<iface>\w+) src=(?P<src>[\d.]+)$",
    }
    msg_entry = dict(SSHD_FAILED, regex=r"for (?P<suser>\S+) from (?P<src>[\d.]+)")
    load_patterns(write_patterns(tmp_path, line_entry, msg_entry))

    event = parse_syslog("ACME gw sshd: Failed password for root from 10.0.0.9 via eth0 src=10.0.0.1")
    # Via forced --mode on the line pattern name as well.
    forced = parse_syslog(
        "ACME gw sshd: Failed password for root from 10.0.0.9 via eth0 src=10.0.0.1", mode="acme_ssh"
    )

    for ev in (event, forced):
        assert ev.pattern == "acme_ssh"
        assert ev.msg_pattern == "sshd_failed"
        # The msg capture of src wins over the line capture of src.
        assert ev.fields == {"iface": "eth0", "src": "10.0.0.9", "suser": "root"}


def test_msg_pattern_after_adaptive_parse(tmp_path: Path):
    entry = {"name": "anyport", "match": "msg", "regex": r"port (?P<spt>\d+)"}
    load_patterns(write_patterns(tmp_path, entry))

    event = parse_syslog("weird-format-line something happened on port 8080")

    assert event.msg_pattern == "anyport"
    assert event.fields == {"spt": "8080"}


def test_first_msg_pattern_wins(tmp_path: Path):
    first = {"name": "first", "match": "msg", "regex": r"from (?P<src>[\d.]+)"}
    second = {"name": "second", "match": "msg", "regex": r"port (?P<spt>\d+)"}
    load_patterns(write_patterns(tmp_path, first, second))

    event = parse_syslog(SSHD_LINE)

    assert event.msg_pattern == "first"
    assert event.fields == {"src": "10.0.0.1"}


def test_first_msg_pattern_wins_across_files(tmp_path: Path):
    a = write_patterns(tmp_path, {"name": "a", "match": "msg", "regex": r"port (?P<spt>\d+)"}, name="a.json")
    b = write_patterns(tmp_path, {"name": "b", "match": "msg", "regex": r"from (?P<src>[\d.]+)"}, name="b.json")
    load_patterns(a)
    load_patterns(b)

    assert parse_syslog(SSHD_LINE).msg_pattern == "a"


def test_later_msg_pattern_used_when_earlier_does_not_match(tmp_path: Path):
    first = {"name": "nope", "match": "msg", "regex": r"Accepted publickey"}
    second = dict(SSHD_FAILED)
    load_patterns(write_patterns(tmp_path, first, second))

    assert parse_syslog(SSHD_LINE).msg_pattern == "sshd_failed"


def test_msg_patterns_are_not_modes(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED))

    assert custom.get_registered("sshd_failed") is None
    with pytest.raises(ValueError, match="msg pattern"):
        custom.register_parser("sshd_failed", lambda line: None)


def test_apply_msg_patterns_never_raises(tmp_path: Path, monkeypatch):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED, dict(SSHD_FAILED, name="backup")))
    broken, backup = custom.loaded_patterns()

    def boom(event):
        raise RuntimeError("broken")

    monkeypatch.setattr(broken, "match_msg", boom)
    event = custom.apply_msg_patterns(parse_syslog(SSHD_LINE))
    assert event.msg_pattern == "backup"

    odd = ParsedEvent(None, None, None, None, "", None, "sshd", None, None, msg=None)  # type: ignore[arg-type]
    assert custom.apply_msg_patterns(odd) is odd
    assert odd.msg_pattern is None


def test_apply_msg_patterns_without_patterns_is_identity():
    event = parse_syslog(SSHD_LINE)
    assert custom.apply_msg_patterns(event) is event
    assert event.fields == {}


def test_msg_pattern_through_stream_converter(tmp_path: Path):
    path = write_patterns(tmp_path, dict(SSHD_FAILED, mapping="cisco_asa"))
    load_patterns(path)

    out = list(process_lines([SSHD_LINE, CRON_LINE], mode=None, mapping=None, use_multiprocessing=False, pool_size=None))

    assert out[0].startswith("CEF:0|Cisco|ASA|")
    assert "src=10.0.0.1" in cef_ext(out[0])
    assert out[1].startswith("CEF:0|Linux|Syslog|")


def test_msg_pattern_and_pattern_mapping_with_multiprocess(tmp_path: Path):
    write_mapping(tmp_path / "maps" / "acme.json")
    path = write_patterns(tmp_path, dict(SSHD_FAILED, regex=r"(?P<action>Failed) password for (?P<suser>\S+) from (?P<src>[\d.]+)", mapping="maps/acme.json"))
    load_patterns(path)

    out = list(
        process_lines(
            [SSHD_LINE, CRON_LINE],
            mode=None,
            mapping=None,
            use_multiprocessing=True,
            pool_size=1,
            pattern_files=[str(path)],
        )
    )

    assert out[0].startswith("CEF:0|Acme|Firewall|")
    assert "src=10.0.0.1" in cef_ext(out[0])
    assert out[1].startswith("CEF:0|Linux|Syslog|")


# --- per-pattern mappings --------------------------------------------------


def test_pattern_mapping_bundled_name(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, dict(SSHD_FAILED, mapping="cisco_asa")))

    event = normalize_event(parse_syslog(SSHD_LINE))
    name, mapping = custom.mapping_for(event)

    assert name == "sshd_failed"
    assert mapping["deviceVendor"] == "Cisco"
    cef = to_cef(event)
    assert cef.startswith("CEF:0|Cisco|ASA|")
    assert "src=10.0.0.1" in cef_ext(cef)


def test_pattern_mapping_relative_path_resolves_against_pattern_file(tmp_path: Path, monkeypatch):
    patterns_dir = tmp_path / "conf"
    patterns_dir.mkdir()
    write_mapping(patterns_dir / "maps" / "acme.json")
    load_patterns(write_patterns(patterns_dir, dict(ACME, mapping="maps/acme.json")))
    # A different working directory must not matter.
    monkeypatch.chdir(tmp_path)

    cef = convert_line(ACME_LINE)

    assert cef.startswith("CEF:0|Acme|Firewall|")
    assert "src=10.0.0.1" in cef_ext(cef)
    pattern = custom.loaded_patterns()[0]
    assert pattern.mapping_ref == "maps/acme.json"


def test_pattern_mapping_absolute_path(tmp_path: Path):
    mapping_path = write_mapping(tmp_path / "elsewhere" / "acme.json")
    load_patterns(write_patterns(tmp_path, dict(ACME, mapping=str(mapping_path))))

    assert convert_line(ACME_LINE).startswith("CEF:0|Acme|Firewall|")


def test_explicit_mapping_overrides_pattern_mapping(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, dict(SSHD_FAILED, mapping="cisco_asa")))

    cef = convert_line(SSHD_LINE, mapping={"deviceVendor": "Explicit", "deviceProduct": "Map"})

    assert cef.startswith("CEF:0|Explicit|Map|")


def test_pattern_without_mapping_falls_back_to_guess(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED))

    event = normalize_event(parse_syslog(SSHD_LINE))

    assert custom.mapping_for(event) is None
    assert to_cef(event).startswith("CEF:0|Linux|Syslog|")


def test_msg_pattern_mapping_wins_over_line_pattern_mapping(tmp_path: Path):
    write_mapping(tmp_path / "acme.json")
    line_entry = {
        "name": "acme_line",
        "regex": r"^ACME (?P<host>\S+) (?P<app>\w+): (?P<msg>.*)$",
        "mapping": "acme.json",
    }
    with_mapping = dict(SSHD_FAILED, mapping="cisco_asa")
    load_patterns(write_patterns(tmp_path, line_entry, with_mapping))

    line = "ACME gw sshd: Failed password for root from 10.0.0.9 port 22"
    event = normalize_event(parse_syslog(line))
    assert custom.mapping_for(event)[0] == "sshd_failed"
    assert to_cef(event).startswith("CEF:0|Cisco|ASA|")

    # A msg pattern without a mapping falls back to the line pattern's.
    other = normalize_event(parse_syslog("ACME gw cron: tick"))
    assert other.msg_pattern is None
    assert custom.mapping_for(other)[0] == "acme_line"
    assert to_cef(other).startswith("CEF:0|Acme|Firewall|")


def test_msg_pattern_without_mapping_falls_back_to_line_pattern_mapping(tmp_path: Path):
    write_mapping(tmp_path / "acme.json")
    line_entry = {
        "name": "acme_line",
        "regex": r"^ACME (?P<host>\S+) (?P<app>\w+): (?P<msg>.*)$",
        "mapping": "acme.json",
    }
    load_patterns(write_patterns(tmp_path, line_entry, SSHD_FAILED))

    event = normalize_event(parse_syslog("ACME gw sshd: Failed password for root from 10.0.0.9 port 22"))

    assert event.msg_pattern == "sshd_failed"
    assert custom.mapping_for(event)[0] == "acme_line"


def test_mapping_for_accepts_duck_typed_events():
    assert custom.mapping_for(object()) is None


# --- examples, metadata, registry -----------------------------------------


def test_examples_are_validated_and_stored(tmp_path: Path):
    examples = [
        {"line": SSHD_LINE, "expect": {"src": "10.0.0.1", "spt": 2222}},
        {"line": CRON_LINE, "matches": False},
    ]
    path = write_patterns(tmp_path, dict(SSHD_FAILED, examples=examples), ACME)
    load_patterns(path)

    msg_pattern, line_pattern = custom.loaded_patterns()
    assert msg_pattern.name == "sshd_failed"
    assert msg_pattern.match == "msg"
    assert msg_pattern.examples == examples
    assert msg_pattern.source == str(path)
    assert msg_pattern.mapping_ref is None
    assert line_pattern.name == "acme_fw"
    assert line_pattern.match == "line"
    assert line_pattern.apps == ()
    assert line_pattern.examples == []


def test_loaded_patterns_keeps_load_order_across_kinds_and_files(tmp_path: Path):
    a = write_patterns(
        tmp_path,
        {"name": "l_after", "regex": r"^A (?P<msg>.*)$"},
        {"name": "m1", "match": "msg", "regex": r"x"},
        {"name": "l_before", "regex": r"^B (?P<msg>.*)$", "priority": "before"},
        name="a.json",
    )
    b = write_patterns(tmp_path, {"name": "m2", "match": "msg", "regex": r"y"}, name="b.json")
    load_patterns(a)
    load_patterns(b)

    assert [p.name for p in custom.loaded_patterns()] == ["l_after", "m1", "l_before", "m2"]
    # A copy: callers cannot mutate the registry through it.
    custom.loaded_patterns().clear()
    assert len(custom.loaded_patterns()) == 4


def test_clear_registry_clears_msg_patterns_and_mappings(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, dict(SSHD_FAILED, mapping="cisco_asa"), ACME))
    event = normalize_event(parse_syslog(SSHD_LINE))
    assert custom.mapping_for(event) is not None

    custom.clear_registry()

    assert custom.loaded_patterns() == []
    assert custom.mapping_for(event) is None
    assert parse_syslog(SSHD_LINE).msg_pattern is None
    assert custom.get_registered("acme_fw") is None
    # Same names load again without duplicate errors.
    load_patterns(write_patterns(tmp_path, dict(SSHD_FAILED, mapping="cisco_asa"), ACME))


def test_shorthand_hook_runs_before_compile(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(custom, "_expand_shorthands", lambda src: src.replace("%{IP:src}", r"(?P<src>[\d.]+)"))
    load_patterns(write_patterns(tmp_path, dict(SSHD_FAILED, regex=r"from %{IP:src} port")))

    assert parse_syslog(SSHD_LINE).fields == {"src": "10.0.0.1"}


def test_shorthand_value_error_becomes_pattern_file_error(tmp_path: Path, monkeypatch):
    def fail(src):
        raise ValueError("unknown shorthand %{NOPE}; known: IP")

    monkeypatch.setattr(custom, "_expand_shorthands", fail)
    with pytest.raises(PatternFileError, match=r"pattern 'sshd_failed'.*unknown shorthand %\{NOPE\}"):
        load_patterns(write_patterns(tmp_path, SSHD_FAILED))


def test_expand_shorthands_is_the_shorthands_module():
    from syslogcef import shorthands

    assert custom._expand_shorthands is shorthands.expand


def test_pattern_file_with_shorthands_loads_and_captures(tmp_path: Path):
    entry = {
        "name": "sshd_failed",
        "match": "msg",
        "app": "sshd",
        "regex": "Failed password for %{USER:suser} from %{IP:src} port %{PORT:spt}",
    }
    load_patterns(write_patterns(tmp_path, entry))

    event = parse_syslog(SSHD_LINE)
    assert event.msg_pattern == "sshd_failed"
    assert event.fields == {"suser": "root", "src": "10.0.0.1", "spt": "2222"}


def test_line_pattern_with_shorthands_fills_envelope_and_fields(tmp_path: Path):
    entry = {
        "name": "acme_short",
        "regex": (
            r"^ACME (?P<ts>%{TIMESTAMP_ISO8601}) %{HOSTNAME:host} %{WORD:app}\[%{INT:pid}\]: "
            r"%{WORD:action} %{IPV4:src_ip} -> %{IP:dst}%{GREEDYDATA:rest}$"
        ),
        "timestamp_format": "%Y-%m-%d %H:%M:%S",
    }
    load_patterns(write_patterns(tmp_path, entry))

    event = parse_syslog(ACME_LINE, now=NOW)
    assert event.pattern == "acme_short"
    assert (event.host, event.app, event.pid) == ("fw01", "nat", "42")
    assert event.ts == datetime(2026, 8, 11, 7, 0, 0, tzinfo=timezone.utc)
    assert event.fields == {"action": "allowed", "src_ip": "10.0.0.1", "dst": "10.0.0.2", "rest": " proto=tcp"}
    assert normalize_event(event).as_field_dict()["src"] == "10.0.0.1"


def test_unknown_shorthand_in_file_names_file_and_pattern(tmp_path: Path):
    path = write_patterns(tmp_path, dict(SSHD_FAILED, regex="from %{NOPE:src} port"))
    with pytest.raises(PatternFileError, match=r"unknown shorthand %\{NOPE\}; known: ") as excinfo:
        load_patterns(path)
    message = str(excinfo.value)
    assert str(path) in message
    assert "pattern 'sshd_failed'" in message
    assert custom.loaded_patterns() == []


def test_shorthand_reserved_capture_name_is_rejected(tmp_path: Path):
    path = write_patterns(tmp_path, dict(SSHD_FAILED, regex="at %{SYSLOGTIMESTAMP:timestamp}"))
    with pytest.raises(PatternFileError, match="reserved for derived fields"):
        load_patterns(path)


# --- load errors -----------------------------------------------------------


@pytest.mark.parametrize(
    "entry, message_part",
    [
        # Reserved (derived) names, both kinds.
        ({"name": "x", "regex": r"^(?P<facility>\d+) (?P<msg>.*)$"}, "reserved for derived fields"),
        ({"name": "x", "regex": r"(?P<rt>\d+)"}, "reserved for derived fields"),
        ({"name": "x", "regex": r"(?P<dvcpid>\d+)"}, "reserved for derived fields"),
        ({"name": "x", "match": "msg", "regex": r"(?P<raw_kv>.*)"}, "reserved for derived fields"),
        ({"name": "x", "match": "msg", "regex": r"(?P<message_short>.*)"}, "reserved for derived fields"),
        ({"name": "x", "match": "msg", "regex": r"(?P<timestamp>.*)"}, "reserved for derived fields"),
        # Envelope groups in a msg pattern.
        ({"name": "x", "match": "msg", "regex": r"(?P<host>\S+)"}, "envelope group"),
        ({"name": "x", "match": "msg", "regex": r"(?P<msg>.*)"}, "envelope group"),
        ({"name": "x", "match": "msg", "regex": r"(?P<ts>\d+)"}, "envelope group"),
        ({"name": "x", "match": "msg", "regex": r"(?P<app>\w+) (?P<pid>\d+)"}, "envelope group"),
        # Kind-specific keys.
        ({"name": "x", "regex": r"(?P<msg>.*)", "app": "sshd"}, "'app' only applies to 'match': 'msg'"),
        ({"name": "x", "match": "msg", "regex": r"x", "timestamp_format": "%Y"}, "'timestamp_format' only applies to line"),
        ({"name": "x", "match": "msg", "regex": r"x", "priority": "before"}, "'priority' only applies to line"),
        ({"name": "x", "match": "msg", "regex": r"x", "priority": "after"}, "'priority' only applies to line"),
        ({"name": "x", "match": "both", "regex": r"x"}, "'match' must be 'line' or 'msg'"),
        ({"name": "x", "match": None, "regex": r"x"}, "'match' must be 'line' or 'msg'"),
        ({"name": "x", "match": "msg", "regex": r"x", "app": ""}, "'app' must be"),
        ({"name": "x", "match": "msg", "regex": r"x", "app": []}, "'app' must be"),
        ({"name": "x", "match": "msg", "regex": r"x", "app": ["sshd", 3]}, "'app' must be"),
        ({"name": "x", "match": "msg", "regex": r"x", "app": {"a": 1}}, "'app' must be"),
        # Unknown keys (typos).
        ({"name": "x", "regex": r"(?P<msg>.*)", "exmaples": []}, r"unknown key\(s\) \['exmaples'\]"),
        ({"name": "x", "match": "msg", "regex": r"x", "apps": "sshd"}, r"unknown key\(s\) \['apps'\]"),
        # Examples shape.
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": {"line": "a"}}, "'examples' must be a list"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": None}, "'examples' must be a list"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": ["a line"]}, r"examples\[0\]: must be an object"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"expect": {}}]}, r"examples\[0\]: 'line' is required"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": ""}]}, r"examples\[0\]: 'line' is required"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": 5}]}, r"examples\[0\]: 'line' is required"),
        (
            {"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": "a"}, {"line": "b", "expcet": {}}]},
            r"examples\[1\]: unknown key\(s\) \['expcet'\]",
        ),
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": "a", "expect": ["src"]}]}, "'expect' must be an object"),
        (
            {"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": "a", "expect": {"src": ["1"]}}]},
            "'expect' value for 'src' must be a string or a number",
        ),
        (
            {"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": "a", "expect": {"ok": True}}]},
            "'expect' value for 'ok' must be a string or a number",
        ),
        (
            {"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": "a", "expect": {"n": None}}]},
            "'expect' value for 'n' must be a string or a number",
        ),
        ({"name": "x", "regex": r"(?P<msg>.*)", "examples": [{"line": "a", "matches": "no"}]}, "'matches' must be true or false"),
        # Mapping references.
        ({"name": "x", "regex": r"(?P<msg>.*)", "mapping": "does_not_exist"}, "is not a bundled mapping"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "mapping": "missing/file.json"}, "cannot be read"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "mapping": ""}, "'mapping' must be a bundled mapping name or a path"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "mapping": 42}, "'mapping' must be a bundled mapping name or a path"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "mapping": None}, "'mapping' must be a bundled mapping name or a path"),
    ],
)
def test_load_errors(tmp_path: Path, entry, message_part):
    path = write_patterns(tmp_path, entry)
    with pytest.raises(PatternFileError, match=message_part) as excinfo:
        load_patterns(path)
    message = str(excinfo.value)
    assert str(path) in message
    assert "pattern 'x'" in message


def test_invalid_mapping_content_is_a_load_error(tmp_path: Path):
    (tmp_path / "bad.json").write_text(json.dumps({"extensions": ["not", "an", "object"]}), encoding="utf-8")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "template.json").write_text(json.dumps({"name": "%(oops"}), encoding="utf-8")

    for ref, part in (
        ("bad.json", "'extensions' must be an object"),
        ("broken.json", "invalid 'mapping' 'broken.json'"),
        ("template.json", "incomplete format key"),
    ):
        custom.clear_registry()
        with pytest.raises(PatternFileError, match=part):
            load_patterns(write_patterns(tmp_path, {"name": "x", "regex": r"(?P<msg>.*)", "mapping": ref}))


def test_msg_pattern_duplicate_name_rejected(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, SSHD_FAILED, name="a.json"))
    with pytest.raises(PatternFileError, match="duplicate name"):
        load_patterns(write_patterns(tmp_path, SSHD_FAILED, name="b.json"))
    with pytest.raises(PatternFileError, match="duplicate name"):
        load_patterns(write_patterns(tmp_path, dict(ACME, name="sshd_failed"), name="c.json"))


def test_msg_pattern_cannot_shadow_builtin(tmp_path: Path):
    with pytest.raises(PatternFileError, match="shadows a built-in"):
        load_patterns(write_patterns(tmp_path, dict(SSHD_FAILED, name="rfc3164")))


def test_failed_load_registers_nothing(tmp_path: Path):
    good_msg = dict(SSHD_FAILED, mapping="cisco_asa")
    bad = {"name": "bad", "match": "msg", "regex": r"(?P<host>\S+)"}
    with pytest.raises(PatternFileError):
        load_patterns(write_patterns(tmp_path, ACME, good_msg, bad))

    assert custom.loaded_patterns() == []
    assert custom.get_registered("acme_fw") is None
    event = parse_syslog(SSHD_LINE)
    assert event.msg_pattern is None
    assert custom.mapping_for(event) is None


# --- backwards compatibility -----------------------------------------------

# Pattern file in the pre-existing format (no match/app/mapping/examples).
OLD_STYLE = [
    {
        "name": "acme_fw",
        "regex": r"^ACME (?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<app>\w+)\[(?P<pid>\d+)\]: (?P<msg>.*)$",
        "timestamp_format": "%Y-%m-%d %H:%M:%S",
    },
    {
        "name": "grabby",
        "regex": r"^<(?P<pri>\d+)>GRAB (?P<ts>\d+) (?P<host>\S+) (?P<msg>.*)$",
        "timestamp_format": "epoch",
        "priority": "before",
    },
]

# Output produced by the converter before pattern captures existed.
OLD_STYLE_GOLDEN = [
    (
        "ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed tcp srcip=10.0.0.1 dstip=10.0.0.2",
        "CEF:0|Linux|Syslog|auto|linux.syslog|allowed tcp srcip=10.0.0.1 dstip=10.0.0.2|3|"
        "msg=allowed tcp srcip\\=10.0.0.1 dstip\\=10.0.0.2 shost=fw01 rt=1786431600000 sproc=nat "
        "dvcpid=42 cs1Label=rawEvent cs1=ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed tcp "
        "srcip\\=10.0.0.1 dstip\\=10.0.0.2",
    ),
    (
        "<13>GRAB 1786431600 box1 user=alice action=login",
        "CEF:0|Linux|Syslog|auto|linux.syslog|user=alice action=login|3|msg=user\\=alice "
        "action\\=login shost=box1 rt=1786431600000 cs1Label=rawEvent cs1=<13>GRAB 1786431600 "
        "box1 user\\=alice action\\=login",
    ),
    (
        SSHD_LINE,
        "CEF:0|Linux|Syslog|auto|linux.syslog|Failed password for root from 10.0.0.1 port 2222 ssh2|2|"
        "msg=Failed password for root from 10.0.0.1 port 2222 ssh2 shost=web01 rt=1767323045000 "
        "sproc=sshd dvcpid=123 cs1Label=rawEvent cs1=" + SSHD_LINE,
    ),
    (
        "<134>Aug 11 07:00:00 fw %ASA-6-302013: Built outbound TCP connection",
        "CEF:0|Cisco|ASA|auto|asa.ASA-6-302013|%ASA-6-302013: Built outbound TCP connection|2|"
        "msg=%ASA-6-302013: Built outbound TCP connection shost=fw rt=1786431600000 "
        "cs1Label=rawEvent cs1=<134>Aug 11 07:00:00 fw %ASA-6-302013: Built outbound TCP connection",
    ),
]


@pytest.mark.parametrize("line, expected", OLD_STYLE_GOLDEN)
def test_old_pattern_files_produce_identical_output(tmp_path: Path, line, expected):
    assert load_patterns(write_patterns(tmp_path, *OLD_STYLE)) == 2

    assert convert_line(line, now=NOW) == expected


def test_old_pattern_files_get_default_metadata(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, *OLD_STYLE))

    acme, grabby = custom.loaded_patterns()
    for pattern in (acme, grabby):
        assert pattern.match == "line"
        assert pattern.apps == ()
        assert pattern.mapping_ref is None
        assert pattern.examples == []
    assert acme.priority == "after" and grabby.priority == "before"

    event = parse_syslog(OLD_STYLE_GOLDEN[0][0])
    assert event.pattern == "acme_fw"
    assert event.fields == {}
    assert event.msg_pattern is None
    assert custom.mapping_for(event) is None
