"""macOS log formats: install.log compact offsets, tag/pid splitting,
continuation-line inheritance, and event time in the CEF output."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from syslogcef.adaptive import adaptive_parse, clear_cache
from syslogcef.api import StreamConverter
from syslogcef.parsers import autodetect_and_parse
from syslogcef.utils import parse_iso8601


class TestCompactUtcOffset:
    """macOS install.log stamps hour-only offsets: 2026-07-20 03:23:05+02."""

    def test_parse_iso8601_hour_only_offset(self):
        ts = parse_iso8601("2026-07-20 03:23:05+02")
        assert ts.utcoffset() == timedelta(hours=2)
        assert ts.replace(tzinfo=None) == datetime(2026, 7, 20, 3, 23, 5)

    def test_parse_iso8601_colonless_offset(self):
        ts = parse_iso8601("2026-07-20T03:23:05+0230")
        assert ts.utcoffset() == timedelta(hours=2, minutes=30)

    def test_parse_iso8601_negative_compact_offset(self):
        ts = parse_iso8601("2026-07-20 03:23:05-05")
        assert ts.utcoffset() == timedelta(hours=-5)

    def test_parse_iso8601_colon_offset_unchanged(self):
        ts = parse_iso8601("2026-07-20T03:23:05+02:00")
        assert ts.utcoffset() == timedelta(hours=2)

    def test_year_month_not_mistaken_for_offset(self):
        with pytest.raises(ValueError):
            parse_iso8601("2026-07")

    def test_install_log_line_fully_parsed(self):
        line = "2026-07-20 03:23:05+02 Tamirs-MBP system_installd[27234]: installd: Starting"
        event = autodetect_and_parse(line)
        assert event.host == "Tamirs-MBP"
        assert event.app == "system_installd"
        assert event.pid == "27234"
        assert event.ts is not None
        assert event.ts.utcoffset() == timedelta(hours=2)
        assert event.msg == "installd: Starting"


class TestTagPidSplit:
    def test_journald_short_splits_pid_from_tag(self):
        line = "May 28 16:04:52 MacBookPro opendirectoryd[69]: [session] node assigned UUID"
        event = autodetect_and_parse(line)
        assert event.host == "MacBookPro"
        assert event.app == "opendirectoryd"
        assert event.pid == "69"

    def test_journald_short_tag_without_pid(self):
        line = "May 28 16:04:52 MacBookPro kernel: something happened"
        event = autodetect_and_parse(line)
        assert event.app == "kernel"
        assert event.pid is None


class TestAdaptiveTagExtraction:
    """The adaptive learner recognizes timestamp, host, and app[pid]: tag."""

    def setup_method(self):
        clear_cache()

    def test_fresh_analysis_extracts_tag(self):
        event = adaptive_parse("2026/07/20 03:23:05 myhost myapp[123]: hello world")
        assert event.host == "myhost"
        assert event.app == "myapp"
        assert event.pid == "123"
        assert event.msg == "hello world"

    def test_cached_pattern_extracts_tag(self):
        adaptive_parse("2026/07/20 03:23:05 myhost myapp[123]: hello world")
        event = adaptive_parse("2026/07/20 03:23:06 myhost myapp[123]: second event")
        assert event.app == "myapp"
        assert event.pid == "123"
        assert event.msg == "second event"

    def test_timezone_remnant_not_taken_as_host(self):
        # If a stray non-hostname token follows the timestamp it must stay
        # in the message rather than become the host.
        event = adaptive_parse("2026/07/20 03:23:05 +bogus stays in message")
        assert event.host is None
        assert "+bogus" in event.msg


class TestContinuationLines:
    """Whitespace-indented lines inherit context from the previous event
    instead of getting the local (container) hostname and no timestamp."""

    def test_continuation_inherits_host_app_time(self):
        conv = StreamConverter()
        first = conv.convert(
            "May 28 16:04:52 MacBookPro opendirectoryd[69]: ODNodeCopyDetails request, Keys: ("
        )
        cont = conv.convert('\t    "dsAttrTypeStandard:OperatingSystemVersion"')
        closing = conv.convert("\t)")
        assert "shost=MacBookPro" in first
        for cef in (cont, closing):
            assert "shost=MacBookPro" in cef
            assert "sproc=opendirectoryd" in cef
            assert "dvcpid=69" in cef
        # Continuation lines carry the parent's event time.
        rt_first = first.split("rt=")[1].split()[0]
        rt_cont = cont.split("rt=")[1].split()[0]
        assert rt_first == rt_cont

    def test_continuation_without_context_keeps_fallback(self):
        conv = StreamConverter()
        cef = conv.convert("\tstray indented line with no parent")
        assert cef.startswith("CEF:0|")

    def test_non_indented_unknown_line_does_not_become_context(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent event")
        conv.convert("completely freeform line no structure !!")
        cont = conv.convert("\tindented continuation")
        # Context still comes from the last *parsed* event, not the
        # freeform fallback line.
        assert "shost=MacBookPro" in cont

    def test_indented_message_preserved(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent event")
        cef = conv.convert("\t    AllowBootstrapTokenOnFullSecurity = true;")
        assert "AllowBootstrapTokenOnFullSecurity" in cef


class TestEventTimeInOutput:
    def test_rt_matches_parsed_timestamp(self):
        conv = StreamConverter()
        cef = conv.convert("2026-07-20T03:23:05+02:00 host1 app[1]: hello")
        expected_ms = int(
            datetime(2026, 7, 20, 3, 23, 5, tzinfo=timezone(timedelta(hours=2))).timestamp() * 1000
        )
        assert f"rt={expected_ms}" in cef


class TestPerSourceContext:
    """Continuation context must not leak across input sources (files)."""

    def test_continuation_does_not_inherit_across_sources(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent", source="a.log")
        cef = conv.convert("\tindented start of another file", source="b.log")
        assert "shost=MacBookPro" not in cef

    def test_each_source_keeps_its_own_context(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 host-a appa[1]: parent A", source="a.log")
        conv.convert("May 28 16:04:53 host-b appb[2]: parent B", source="b.log")
        # Interleaved continuations inherit from their own file.
        cef_a = conv.convert("\tcontinuation for A", source="a.log")
        cef_b = conv.convert("\tcontinuation for B", source="b.log")
        assert "shost=host-a" in cef_a and "sproc=appa" in cef_a
        assert "shost=host-b" in cef_b and "sproc=appb" in cef_b

    def test_process_lines_tags_sources(self):
        from syslogcef.cli import process_lines

        items = [
            ("a.log", "May 28 16:04:52 host-a appa[1]: parent A"),
            ("b.log", "\tindented first line of file B"),
        ]
        out = list(
            process_lines(items, mode=None, mapping=None, use_multiprocessing=False, pool_size=None)
        )
        assert "shost=host-a" in out[0]
        assert "shost=host-a" not in out[1]


class TestForcedModeContinuation:
    """A forced --mode must inherit continuation lines, not abort on them."""

    def test_forced_mode_continuation_inherits(self):
        conv = StreamConverter(mode="journald_short")
        parent = conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent event")
        cont = conv.convert("\t    wrapped payload line")
        assert "shost=MacBookPro" in parent
        assert "shost=MacBookPro" in cont
        assert "sproc=opendirectoryd" in cont

    def test_forced_mode_still_rejects_non_continuations(self):
        from syslogcef.parsers import ParserError

        conv = StreamConverter(mode="journald_short")
        with pytest.raises(ParserError):
            conv.convert("not a journald line at all")

    def test_forced_mode_indented_without_context_still_raises(self):
        from syslogcef.parsers import ParserError

        conv = StreamConverter(mode="journald_short")
        with pytest.raises(ParserError):
            conv.convert("\tindented but no preceding event")


class TestDvcpidNumericOnly:
    """dvcpid is an integer CEF field; non-numeric PROCIDs must not land there."""

    def test_numeric_pid_emits_dvcpid(self):
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        cef = convert_line(
            "<34>1 2026-07-20T03:23:05Z host1 myapp 4711 ID47 - message", mapping=LINUX
        )
        assert "dvcpid=4711" in cef

    def test_nonnumeric_procid_omits_dvcpid(self):
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        cef = convert_line(
            "<34>1 2026-07-20T03:23:05Z host1 myapp worker-A ID47 - message", mapping=LINUX
        )
        assert "dvcpid=" not in cef

    def test_nonnumeric_procid_passes_strict_validation(self):
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        cef = convert_line(
            "<34>1 2026-07-20T03:23:05Z host1 myapp worker-A ID47 - message",
            mapping=LINUX,
            strict=True,
        )
        assert cef.startswith("CEF:0|")

    def test_kv_pid_emits_dvcpid_when_header_has_none(self):
        # A headerless line has no parsed PID; its pid= field is the
        # effective PID, which %(pid)s rendered before the alias existed.
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        assert "dvcpid=123" in convert_line("pid=123 action=test", mapping=LINUX)
        cef = convert_line("pid=worker-A action=test", mapping=LINUX, strict=True)
        assert "dvcpid=" not in cef

    def test_parsed_pid_wins_over_kv_pid(self):
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        cef = convert_line(
            "<34>1 2026-07-20T03:23:05Z host1 myapp 4711 ID47 - pid=99", mapping=LINUX
        )
        assert "dvcpid=4711" in cef


class TestSyslogHostIsSource:
    """The syslog HOSTNAME is the device that generated the event, so it
    maps to shost (source host), never dhost (destination). shost, not
    dvchost: RFC 5424 hostnames can exceed dvchost's 100-char limit."""

    def test_linux_mapping_host_is_shost_not_dhost(self):
        from syslogcef import convert_line

        cef = convert_line(
            "<13>Aug 10 13:39:25 clay-wks-linux-15 kernel: docker0: port 1 entered blocking state"
        )
        assert "shost=clay-wks-linux-15" in cef
        assert "dhost=" not in cef
        assert "dvchost=" not in cef

    def test_default_mapping_surfaces_host_as_source(self):
        # Exercise DEFAULT_MAPPING directly: a minimal custom mapping with
        # no extensions falls through to the default extension set, so the
        # default's shost is what surfaces (mapping=None would route via
        # _guess_mapping to the bundled LINUX mapping instead).
        from syslogcef import convert_line

        cef = convert_line(
            "<13>Aug 10 13:39:25 gw-01 weirdproc: payload zzz",
            mapping={"deviceVendor": "Acme", "deviceProduct": "Thing"},
        )
        assert "|Acme|Thing|" in cef  # confirms the custom (default-based) mapping ran
        assert "shost=gw-01" in cef
        assert "dhost=" not in cef

    def test_long_hostname_passes_strict(self):
        # A 200-char hostname (valid per RFC 5424, > dvchost's 100 limit)
        # must not fail --strict — which is why host maps to shost (1023).
        from syslogcef import convert_line

        host = "h" * 200
        cef = convert_line(f"<13>Aug 10 13:39:25 {host} app: msg", strict=True)
        assert f"shost={host}" in cef


class TestApplianceHostIsDevice:
    """On firewall/router/load-balancer logs the syslog sender is the
    reporting device; CEF's source entity is the endpoint in src."""

    @pytest.mark.parametrize(
        "line, product",
        [
            (
                "<166>Jan 12 10:00:00 fw1 %ASA-6-302013: Built inbound TCP connection 1 "
                "for outside:10.0.0.1/1234 (10.0.0.1/1234) to inside:10.0.0.2/80 (10.0.0.2/80)",
                "ASA",
            ),
            ("<189>Jan 12 10:00:00 fw1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", "IOS"),
            (
                "<134>Jan 12 10:00:00 fw1 tmm[1234]: 01010028:3: BIG-IP pool /Common/p "
                "member 10.0.0.5:80 down",
                "BIG-IP",
            ),
        ],
    )
    def test_cisco_and_f5_host_is_dvchost_not_shost(self, line, product):
        from syslogcef import convert_line

        cef = convert_line(line)
        assert cef.split("|")[2] == product
        assert "shost=" not in cef
        assert "dvchost=fw1" in cef

    @pytest.mark.parametrize(
        "line, product",
        [
            (
                'date=2020-01-01 time=10:00:00 devname="fgt1" devid="FGT" logid="0000000013" '
                'type="traffic" srcip=10.1.1.1 dstip=10.2.2.2',
                "FortiGate",
            ),
            (
                'device="SFW" date=2020-05-18 time=14:38:48 device_name="XG230" '
                'log_id=041101618035 log_type="Firewall" src_ip="10.9.9.9"',
                "XG Firewall",
            ),
        ],
    )
    def test_kv_firewall_host_is_not_shost(self, line, product):
        from syslogcef import convert_line

        cef = convert_line(line)
        assert cef.split("|")[2] == product
        assert "shost=" not in cef
        assert "dvchost=" in cef
