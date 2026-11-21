"""Pattern examples and ``--check-patterns``."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

import syslogcef.custom
from syslogcef import custom
from syslogcef.cli import main
from syslogcef.pattern_check import ExampleResult, format_report, run_examples

@pytest.fixture(autouse=True)
def _clean_registry():
    custom.clear_registry()
    yield
    custom.clear_registry()


# ---- fakes ---------------------------------------------------------------


@dataclass
class FakePattern:
    name: str
    examples: List[dict]
    match: str = "line"
    warnings: List[str] = field(default_factory=list)


@dataclass
class FakeEvent:
    fields: Dict[str, Any] = field(default_factory=dict)
    pattern: Optional[str] = None
    msg_pattern: Optional[str] = None
    source_hint: str = "kv"

    def as_field_dict(self) -> Dict[str, Any]:
        return dict(self.fields)


def fixed(event: FakeEvent):
    return lambda line: event


# ---- run_examples ----------------------------------------------------------


def test_pass_when_pattern_and_fields_match():
    event = FakeEvent({"src": "10.0.0.1", "host": "fw1"}, pattern="acme")
    pattern = FakePattern("acme", [{"line": "x", "expect": {"src": "10.0.0.1", "host": "fw1"}}])

    [result] = run_examples([pattern], fixed(event))

    assert result == ExampleResult(pattern="acme", index=1, line="x", passed=True, problems=[])


def test_pattern_match_without_expect_passes():
    [result] = run_examples([FakePattern("acme", [{"line": "x"}])], fixed(FakeEvent(pattern="acme")))
    assert result.passed


def test_missing_field_fails():
    event = FakeEvent({"host": "fw1"}, pattern="acme")
    [result] = run_examples([FakePattern("acme", [{"line": "x", "expect": {"src": "10.0.0.1"}}])], fixed(event))

    assert not result.passed
    assert result.problems == ["field src: expected '10.0.0.1', but it is missing"]


def test_wrong_value_fails():
    event = FakeEvent({"src": "10.0.0.2"}, pattern="acme")
    [result] = run_examples([FakePattern("acme", [{"line": "x", "expect": {"src": "10.0.0.1"}}])], fixed(event))

    assert not result.passed
    assert result.problems == ["field src: expected '10.0.0.1', got '10.0.0.2'"]


def test_numbers_compared_as_strings():
    event = FakeEvent({"spt": "443", "cnt": 7}, pattern="acme")
    pattern = FakePattern("acme", [
        {"line": "a", "expect": {"spt": 443, "cnt": "7"}},
        {"line": "b", "expect": {"spt": 80}},
    ])

    ok, bad = run_examples([pattern], fixed(event))

    assert ok.passed
    assert not bad.passed
    assert bad.problems == ["field spt: expected '80', got '443'"]


def test_wrong_pattern_matched_fails():
    event = FakeEvent({"src": "10.0.0.1"}, pattern="other")
    [result] = run_examples([FakePattern("acme", [{"line": "x", "expect": {"src": "10.0.0.1"}}])], fixed(event))

    assert not result.passed
    assert result.problems == ["pattern 'acme' did not match (pattern 'other' matched instead)"]


def test_no_pattern_matched_names_the_parser():
    event = FakeEvent(source_hint="adaptive")
    [result] = run_examples([FakePattern("acme", [{"line": "x"}])], fixed(event))

    assert not result.passed
    assert result.problems == ["pattern 'acme' did not match (no pattern matched; parser: adaptive)"]


def test_matches_false_passes_when_pattern_does_not_match():
    for event in (FakeEvent(), FakeEvent(pattern="other")):
        [result] = run_examples([FakePattern("acme", [{"line": "x", "matches": False}])], fixed(event))
        assert result.passed, result.problems


def test_matches_false_fails_when_pattern_matches():
    event = FakeEvent(pattern="acme")
    [result] = run_examples([FakePattern("acme", [{"line": "x", "matches": False}])], fixed(event))

    assert not result.passed
    assert result.problems == ["expected no match, but pattern 'acme' matched"]


def test_msg_kind_uses_msg_pattern():
    # The line pattern name must not satisfy a msg pattern, and vice versa.
    event = FakeEvent({"user": "root"}, pattern="sshd_fail", msg_pattern="other")
    msg = FakePattern("sshd_fail", [{"line": "x", "expect": {"user": "root"}}], match="msg")
    [result] = run_examples([msg], fixed(event))
    assert not result.passed
    assert result.problems == ["msg pattern 'sshd_fail' did not match (msg pattern 'other' matched instead)"]

    event = FakeEvent({"user": "root"}, msg_pattern="sshd_fail")
    [result] = run_examples([msg], fixed(event))
    assert result.passed


def test_msg_kind_matches_false():
    msg = FakePattern("sshd_fail", [{"line": "x", "matches": False}], match="msg")
    [ok] = run_examples([msg], fixed(FakeEvent(pattern="sshd_fail")))
    [bad] = run_examples([msg], fixed(FakeEvent(msg_pattern="sshd_fail")))

    assert ok.passed
    assert bad.problems == ["expected no match, but msg pattern 'sshd_fail' matched"]


def test_convert_raising_is_a_failed_result():
    def boom(line):
        raise RuntimeError("bad line")

    pattern = FakePattern("acme", [{"line": "x"}, {"line": "y"}])
    results = run_examples([pattern], boom)

    assert [r.passed for r in results] == [False, False]
    assert results[0].problems == ["conversion error: RuntimeError: bad line"]


def test_indexes_are_per_pattern_and_one_based():
    patterns = [
        FakePattern("a", [{"line": "1"}, {"line": "2"}]),
        FakePattern("b", [{"line": "3"}]),
    ]
    results = run_examples(patterns, lambda line: FakeEvent(pattern="a"))

    assert [(r.pattern, r.index, r.line) for r in results] == [("a", 1, "1"), ("a", 2, "2"), ("b", 1, "3")]


def test_zero_examples():
    patterns = [FakePattern("a", []), FakePattern("b", [])]
    assert run_examples(patterns, fixed(FakeEvent())) == []
    assert run_examples([], fixed(FakeEvent())) == []


# ---- format_report ---------------------------------------------------------


def test_report_format_and_totals():
    results = [
        ExampleResult("acme", 1, "x", True, []),
        ExampleResult("acme", 2, "y", False, ["field src: expected '1', got '2'", "field dst: expected '3', but it is missing"]),
        ExampleResult("sshd", 1, "z", True, []),
    ]

    assert format_report(results) == (
        "PASS acme example 1\n"
        "FAIL acme example 2: field src: expected '1', got '2'; field dst: expected '3', but it is missing\n"
        "PASS sshd example 1\n"
        "2/3 examples passed"
    )


def test_report_zero_examples():
    assert format_report([]) == "no examples defined"


def test_config_warnings_become_failed_results_before_examples():
    patterns = [
        FakePattern("a", [{"line": "1"}], warnings=["unknown key 'exmaples'", "unknown key 'x' in example 1"]),
        FakePattern("b", [{"line": "2"}]),
    ]
    results = run_examples(patterns, lambda line: FakeEvent(pattern="a" if line == "1" else "b"))

    assert [(r.pattern, r.kind, r.index, r.passed, r.problems) for r in results] == [
        ("a", "config", 0, False, ["unknown key 'exmaples'"]),
        ("a", "config", 0, False, ["unknown key 'x' in example 1"]),
        ("a", "example", 1, True, []),
        ("b", "example", 1, True, []),
    ]


def test_report_config_problems():
    results = [
        ExampleResult("acme", 0, "", False, ["unknown key 'exmaples'"], kind="config"),
        ExampleResult("acme", 1, "x", True, []),
    ]
    assert format_report(results) == (
        "FAIL acme config: unknown key 'exmaples'\n"
        "PASS acme example 1\n"
        "1/1 examples passed; 1 config problem"
    )
    two = [results[0], results[0]]
    assert format_report(two) == (
        "FAIL acme config: unknown key 'exmaples'\n"
        "FAIL acme config: unknown key 'exmaples'\n"
        "no examples defined; 2 config problems"
    )


# ---- CLI -------------------------------------------------------------------


def _usage_error(argv, capsys) -> str:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == 2
    return capsys.readouterr().err


def write_patterns(tmp_path: Path, *entries) -> Path:
    path = tmp_path / "patterns.json"
    path.write_text(json.dumps({"patterns": list(entries)}), encoding="utf-8")
    return path


ACME = {
    "name": "acme_fw",
    "regex": r"^ACME (?P<host>\S+) (?P<app>\w+): (?P<msg>.*)$",
}


def test_check_patterns_requires_patterns(capsys):
    err = _usage_error(["--check-patterns"], capsys)
    assert "--check-patterns requires at least one --patterns" in err


def test_check_patterns_rejects_paths(tmp_path: Path, capsys):
    log = tmp_path / "in.log"
    log.write_text("hello\n", encoding="utf-8")
    err = _usage_error(["--check-patterns", "--patterns", str(write_patterns(tmp_path, ACME)), str(log)], capsys)
    assert "remove PATHS" in err


def test_check_patterns_rejects_listen(tmp_path: Path, capsys):
    err = _usage_error(["--check-patterns", "--patterns", str(write_patterns(tmp_path, ACME)), "--listen", "udp:5514"], capsys)
    assert "remove --listen" in err


def test_check_patterns_rejects_tail(tmp_path: Path, capsys):
    log = tmp_path / "in.log"
    log.write_text("hello\n", encoding="utf-8")
    err = _usage_error(["--check-patterns", "--patterns", str(write_patterns(tmp_path, ACME)), "--tail", str(log)], capsys)
    assert "--check-patterns reads no input" in err
    assert "--tail" in err


def test_check_patterns_wiring_with_stubbed_registry(tmp_path: Path, capsys, monkeypatch):
    # The loaded pattern list is stubbed, conversion is real.
    stub = [FakePattern("acme_fw", [{"line": "plain text", "matches": False}])]
    monkeypatch.setattr(syslogcef.custom, "loaded_patterns", lambda: stub, raising=False)

    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, ACME))]) == 0
    assert capsys.readouterr().out == "PASS acme_fw example 1\n1/1 examples passed\n"

    custom.clear_registry()
    stub[:] = [FakePattern("acme_fw", [{"line": "plain text", "expect": {"host": "nowhere"}}])]
    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, ACME))]) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL acme_fw example 1: pattern 'acme_fw' did not match")
    assert out.endswith("0/1 examples passed\n")


def test_cli_all_examples_pass(tmp_path: Path, capsys):
    entry = dict(ACME, examples=[
        {"line": "ACME fw1 filter: blocked", "expect": {"host": "fw1", "app": "filter"}},
        {"line": "something else entirely", "matches": False},
    ])

    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, entry))]) == 0
    assert capsys.readouterr().out == (
        "PASS acme_fw example 1\n"
        "PASS acme_fw example 2\n"
        "2/2 examples passed\n"
    )


def test_cli_failing_example_exits_1(tmp_path: Path, capsys):
    entry = dict(ACME, examples=[
        {"line": "ACME fw1 filter: blocked", "expect": {"host": "fw2"}},
        {"line": "ACME fw1 filter: blocked", "matches": False},
    ])

    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, entry))]) == 1
    out = capsys.readouterr().out
    assert "FAIL acme_fw example 1: field host: expected 'fw2', got 'fw1'" in out
    assert "FAIL acme_fw example 2: expected no match, but pattern 'acme_fw' matched" in out
    assert out.endswith("0/2 examples passed\n")


def test_cli_msg_pattern_example(tmp_path: Path, capsys):
    entry = {
        "name": "sshd_fail",
        "match": "msg",
        "regex": r"Failed password for (?P<duser>\S+) from (?P<src>\S+)",
        "examples": [{
            "line": "<38>Jan  1 12:00:00 host1 sshd[42]: Failed password for root from 10.0.0.9 port 22 ssh2",
            "expect": {"duser": "root", "src": "10.0.0.9"},
        }],
    }

    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, entry))]) == 0
    assert capsys.readouterr().out == "PASS sshd_fail example 1\n1/1 examples passed\n"


def test_cli_zero_examples_exits_0(tmp_path: Path, capsys):
    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, ACME))]) == 0
    assert capsys.readouterr().out == "no examples defined\n"


def test_cli_unknown_keys_fail_the_check(tmp_path: Path, capsys):
    entry = dict(
        ACME,
        description="Acme firewall",
        exmaples=[{"line": "ACME fw1 filter: blocked"}],
        examples=[{"line": "ACME fw1 filter: blocked", "expcet": {"host": "fw9"}}],
    )

    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, entry))]) == 1
    assert capsys.readouterr().out == (
        "FAIL acme_fw config: unknown key 'exmaples'\n"
        "FAIL acme_fw config: unknown key 'expcet' in example 1\n"
        "PASS acme_fw example 1\n"
        "1/1 examples passed; 2 config problems\n"
    )


def test_cli_description_alone_passes(tmp_path: Path, capsys):
    entry = dict(ACME, description="Acme firewall", examples=[{"line": "ACME fw1 filter: blocked"}])

    assert main(["--check-patterns", "--patterns", str(write_patterns(tmp_path, entry))]) == 0
    assert capsys.readouterr().out == "PASS acme_fw example 1\n1/1 examples passed\n"


def test_cli_conversion_with_unknown_key_warns_on_stderr(tmp_path: Path):
    import subprocess
    import sys

    patterns = write_patterns(tmp_path, dict(ACME, exmaples=[]))
    proc = subprocess.run(
        [sys.executable, "-m", "syslogcef", "--patterns", str(patterns)],
        input="ACME fw1 filter: blocked\n",
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
        timeout=30,
    )

    assert proc.returncode == 0
    assert proc.stdout.startswith("CEF:0|")
    assert "shost=fw1" in proc.stdout
    assert f"{patterns}: pattern 'acme_fw': unknown key 'exmaples' (ignored)" in proc.stderr
