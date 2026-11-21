"""Tests for the regex shorthands used in custom pattern files."""

import re
import time

import pytest

from syslogcef.shorthands import SHORTHANDS, expand

POSITIVE = {
    "IPV4": ["192.168.1.10", "0.0.0.0", "255.255.255.255"],
    "IPV6": ["2001:db8::1", "::1", "fe80::1ff:fe23:4567", "::ffff:192.168.1.1"],
    "IP": ["10.0.0.1", "2001:db8::1"],
    "INT": ["0", "-42", "+7"],
    "NUMBER": ["1.5", "-3", "+0.25"],
    "PORT": ["22", "65535"],
    "WORD": ["abc_1", "Zed"],
    "NOTSPACE": ["a/b:c", "x"],
    "DATA": ["anything at all", ""],
    "GREEDYDATA": ["anything at all", ""],
    "HOSTNAME": ["web-01.example.com", "web01.", "localhost"],
    "USER": ["svc.backup@corp", "root"],
    "MAC": ["00:1A:2b:3C:4d:5E", "00-1a-2b-3c-4d-5e"],
    "SYSLOGTIMESTAMP": ["Jan  5 01:02:03", "Dec 25 23:59:59"],
    "TIMESTAMP_ISO8601": [
        "2026-11-21T13:40:09.579Z",
        "2026-11-21 13:40:09+02:00",
        "2026-11-21T13:40:09",
    ],
    "QUOTEDSTRING": ['"a \\"b\\" c"', '""'],
    "PATH": ["/var/log/messages", "/"],
    "LOGLEVEL": ["WARNING", "crit", "Critical", "info"],
}

NEGATIVE = {
    "IPV4": ["256.1.1.1", "1.2.3", "10.0.0.1.5"],
    "IPV6": ["2001:db8", "192.168.1.1"],
    "IP": ["256.1.1.1", "hello"],
    "INT": ["1.5", "abc"],
    "NUMBER": ["1.", "abc"],
    "PORT": ["123456", "-1"],
    "WORD": ["a b", "a-b"],
    "NOTSPACE": ["a b"],
    "HOSTNAME": ["-web", "web_01", "web..example"],
    "USER": ["user name", "a!b"],
    "MAC": ["00:1A:2b:3C:4d", "00:1A:2b:3C:4d:5G"],
    "SYSLOGTIMESTAMP": ["jan  5 01:02:03", "Jan 5 1:02:03"],
    "TIMESTAMP_ISO8601": ["2026-11-21", "2026/11/21 13:40:09"],
    "QUOTEDSTRING": ['"unterminated', "no quotes"],
    "PATH": ["var/log", "/var log"],
    "LOGLEVEL": ["warnings", "verbose"],
}


def test_every_shorthand_compiles_without_capturing_groups():
    for name, value in SHORTHANDS.items():
        assert re.compile(value).groups == 0, name


@pytest.mark.parametrize(
    "name, text",
    [(name, text) for name, texts in POSITIVE.items() for text in texts],
)
def test_positive_matches(name, text):
    assert re.fullmatch(SHORTHANDS[name], text), (name, text)


@pytest.mark.parametrize(
    "name, text",
    [(name, text) for name, texts in NEGATIVE.items() for text in texts],
)
def test_negative_matches(name, text):
    assert re.fullmatch(SHORTHANDS[name], text) is None, (name, text)


def test_every_shorthand_has_positive_cases():
    assert set(POSITIVE) == set(SHORTHANDS)


def test_expand_named_fields_capture():
    pattern = re.compile(expand("from %{IP:src} port %{PORT:spt}"))
    match = pattern.fullmatch("from 10.0.0.1 port 22")
    assert match is not None
    assert match.groupdict() == {"src": "10.0.0.1", "spt": "22"}


def test_expand_unnamed_token_is_non_capturing():
    assert expand("%{WORD}") == "(?:" + SHORTHANDS["WORD"] + ")"
    assert re.compile(expand("%{WORD}")).groups == 0


def test_expand_named_token_is_one_group():
    assert re.compile(expand("%{WORD:w}")).groups == 1


def test_expand_unknown_name_raises_with_name_and_known_list():
    with pytest.raises(ValueError) as info:
        expand("x %{NOPE} y")
    message = str(info.value)
    assert "NOPE" in message
    expected_known = ", ".join(sorted(SHORTHANDS))
    assert message == "unknown shorthand %{NOPE}; known: " + expected_known


@pytest.mark.parametrize(
    "text",
    [
        "plain text with no tokens",
        "%d",
        "a{3}",
        "x{1,2}",
        "%{lowercase}",
        "%{}",
        "%{WORD",
    ],
)
def test_expand_leaves_non_tokens_unchanged(text):
    assert expand(text) == text


@pytest.mark.parametrize("name", sorted(SHORTHANDS))
def test_redos_smoke(name):
    pattern = re.compile(expand("%{" + name + "}"))
    for subject in ("a" * 5000 + "!", "1." * 3000):
        start = time.perf_counter()
        pattern.fullmatch(subject)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (name, elapsed)
