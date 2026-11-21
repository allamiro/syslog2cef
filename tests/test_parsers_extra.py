from __future__ import annotations

from datetime import datetime, timezone

import pytest

from syslogcef.parsers import ParserError, autodetect_and_parse


NOW = datetime(2023, 7, 2, tzinfo=timezone.utc)


def test_parse_rsyslog_json():
    line = '{"timestamp": "2023-07-01T12:00:00Z", "hostname": "web01", "programname": "nginx", "pid": 42, "msg": "GET /index.html", "pri": "14"}'
    result = autodetect_and_parse(line)
    assert result.source_hint in {"rsyslog", "journald"}
    assert result.host == "web01"
    assert result.msg == "GET /index.html"


def test_parse_rsyslog_file_format():
    line = "2023-07-01T12:00:00.123+00:00 web01 sshd[999]: Accepted publickey for root"
    result = autodetect_and_parse(line)
    assert result.host == "web01"
    assert result.app == "sshd"
    assert result.pid == "999"
    assert result.msg.startswith("Accepted publickey")


def test_parse_journald_iso():
    line = "2023-07-01 12:00:00 host1 systemd: Started Session 1 of user root."
    result = autodetect_and_parse(line)
    assert result.host == "host1"
    assert result.msg.startswith("Started Session")


def test_parse_journald_short():
    line = "Jul  1 12:00:00 host1 mytag with spaces: unit entered running state"
    result = autodetect_and_parse(line, now=NOW)
    assert result.host == "host1"
    assert result.msg == "unit entered running state"


def test_rfc5424_dash_fields_become_none():
    line = "<34>1 2023-07-01T12:00:00Z - - - - - message only"
    result = autodetect_and_parse(line)
    assert result.host is None
    assert result.app is None
    assert result.pid is None
    assert result.msgid is None


def test_unknown_format_falls_back_to_raw():
    line = "completely unstructured garbage without any format"
    result = autodetect_and_parse(line)
    assert result.source_hint == "unknown"
    assert result.msg == line
    assert result.host is not None


def test_explicit_mode_unknown_raises():
    with pytest.raises(ParserError):
        autodetect_and_parse("anything", mode="no_such_mode")


def test_explicit_mode_parse_failure_raises():
    with pytest.raises(ParserError):
        autodetect_and_parse("not valid rfc5424", mode="rfc5424")


def test_rfc3164_year_rollover_previous_year():
    # A December timestamp seen in January belongs to the previous year.
    line = "<14>Dec 31 23:59:59 host1 app: year rollover"
    result = autodetect_and_parse(line, now=datetime(2024, 1, 2, tzinfo=timezone.utc))
    assert result.ts.year == 2023


# Issue #112: a yearless timestamp describes an event that already
# happened, so it takes the most recent occurrence that is not later than
# now plus a small clock-skew/timezone tolerance — never a date months
# ahead just because it is nearer than last year's.

@pytest.mark.parametrize(
    "line, now, year",
    [
        # Jan 1 seen in late November: earlier this year, not next year.
        ("<14>Jan  1 12:34:56 h1 sshd[22]: x", datetime(2026, 11, 20, tzinfo=timezone.utc), 2026),
        # Year boundary: a line stamped just after midnight by a clock
        # slightly ahead lands in the year that is about to begin.
        ("<14>Jan  1 00:00:05 h1 app: x", datetime(2026, 12, 31, 23, 59, 58, tzinfo=timezone.utc), 2027),
        # Later today (sender in a timezone ahead of UTC) stays this year.
        ("<14>Nov 20 22:00:00 h1 app: x", datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc), 2026),
        # Several days in the future can only be last year's date.
        ("<14>Nov 25 10:00:00 h1 app: x", datetime(2026, 11, 20, tzinfo=timezone.utc), 2025),
        # Six-plus months back is still the past, not next year.
        ("<14>Mar  3 10:00:00 h1 app: x", datetime(2026, 11, 20, tzinfo=timezone.utc), 2026),
    ],
)
def test_yearless_timestamp_is_dated_in_the_past(line, now, year):
    assert autodetect_and_parse(line, now=now).ts.year == year


def test_yearless_feb29_takes_the_last_leap_day_in_the_past():
    from syslogcef.parsers import _infer_timestamp

    # 2028-02-29 is nearer to 2027-03-01 than 2024-02-29, but it has not
    # happened yet.
    ts = _infer_timestamp(2, 29, "12:00:00", now=datetime(2027, 3, 1, tzinfo=timezone.utc))
    assert ts.year == 2024


def test_adaptive_mon_day_is_dated_in_the_past():
    import re

    from syslogcef.adaptive import TIMESTAMP_LIB

    src, conv = next((s, c) for n, s, c in TIMESTAMP_LIB if n == "mon_day")
    ts = conv(re.compile(src).match("Jan  1 12:34:56"), datetime(2026, 11, 20, tzinfo=timezone.utc))
    assert ts.year == 2026
