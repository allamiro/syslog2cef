"""Appliance mappings report the syslog host as the device (#135).

For Cisco ASA, Cisco IOS and F5 BIG-IP the syslog header host is the
reporting appliance, so it belongs in dvchost, not shost. dvchost is
limited to 100 characters while shost allows 1023: a longer, valid host
stays in shost so nothing is truncated and --strict never fails.
"""

from __future__ import annotations

import pytest

from syslogcef import convert_line
from syslogcef.dictionary import cef_keys
from syslogcef.mappings import load_mapping
from syslogcef.normalizer import normalize
from syslogcef.parsers import autodetect_and_parse

DVCHOST_MAX = cef_keys()["dvchost"][1]

ASA_LINE = (
    "<166>Jan 12 10:00:00 fw1 %ASA-6-302013: Built inbound TCP connection 1 "
    "for outside:10.0.0.1/1234 (10.0.0.1/1234) to inside:10.0.0.2/80 (10.0.0.2/80)"
)
IOS_LINE = (
    "<189>1 2026-01-12T10:00:00Z rtr1.example.net - - - - "
    "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down"
)
F5_LINE = (
    "<134>Jan 12 10:00:00 lb1 tmm[1234]: 01010028:3: BIG-IP pool /Common/p "
    "member 10.0.0.5:80 down"
)

# A valid RFC 5424 hostname (labels of at most 63 characters) longer than
# dvchost allows: 63 + 1 + 63 + 1 + 5 = 133 characters.
LONG_HOST = "a" * 63 + "." + "b" * 63 + ".corp1"


def extensions(cef: str) -> dict:
    """Extension key -> value for a CEF line whose values contain no '='."""
    ext = cef.split("|", 7)[7]
    out = {}
    for token in ext.split(" "):
        if "=" in token:
            key, _, value = token.partition("=")
            if key.isalnum():
                out[key] = value
    return out


def test_long_host_fixture_is_valid_and_too_long_for_dvchost():
    assert len(LONG_HOST) == 133
    assert all(len(label) <= 63 for label in LONG_HOST.split("."))
    assert DVCHOST_MAX == 100


@pytest.mark.parametrize(
    "line, product, host",
    [
        (ASA_LINE, "ASA", "fw1"),
        (IOS_LINE, "IOS", "rtr1.example.net"),
        (F5_LINE, "BIG-IP", "lb1"),
    ],
)
def test_appliance_host_is_dvchost_not_shost(line, product, host):
    cef = convert_line(line, strict=True)
    assert cef.split("|")[2] == product
    assert f"dvchost={host} " in cef
    assert " shost=" not in cef


@pytest.mark.parametrize(
    "template, product",
    [
        ("<166>1 2026-01-12T10:00:00Z {host} - - - - %ASA-6-302013: Built inbound TCP connection", "ASA"),
        ("<189>1 2026-01-12T10:00:00Z {host} - - - - %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", "IOS"),
        ("<134>1 2026-01-12T10:00:00Z {host} tmm 1234 - - 01010028:3: BIG-IP pool member down", "BIG-IP"),
    ],
)
def test_long_host_stays_in_shost_under_strict(template, product):
    cef = convert_line(template.format(host=LONG_HOST), strict=True)
    assert cef.split("|")[2] == product
    assert f"shost={LONG_HOST} " in cef
    assert "dvchost=" not in cef


@pytest.mark.parametrize("length, field", [(DVCHOST_MAX, "dvchost"), (DVCHOST_MAX + 1, "shost")])
def test_dvchost_limit_boundary(length, field):
    host = "h" * length
    cef = convert_line(f"<166>1 2026-01-12T10:00:00Z {host} - - - - %ASA-6-302013: Built", strict=True)
    ext = extensions(cef)
    assert ext[field] == host
    assert ("shost" if field == "dvchost" else "dvchost") not in ext


@pytest.mark.parametrize(
    "line, host, long_host",
    [
        ("<13>Jan 12 10:00:00 fw1 app: msg", "fw1", ""),
        (f"<13>1 2026-01-12T10:00:00Z {LONG_HOST} app - - - msg", "", LONG_HOST),
    ],
)
def test_device_host_fields_split_host(line, host, long_host):
    fields = normalize(autodetect_and_parse(line)).as_field_dict()
    assert fields["device_host"] == host
    assert fields["device_host_long"] == long_host
    assert fields["host"] == (host or long_host)


def test_device_host_mirrors_localhost_fallback():
    # A hostless RFC 3164 line gets "localhost" for %(host)s (the default
    # shost); device_host follows the same value.
    event = autodetect_and_parse("<13>Jan 12 10:00:00 app[1]: hello")
    fields = normalize(event).as_field_dict()
    assert fields["device_host"] == fields.get("host", "")


def test_device_host_cannot_be_injected_from_message():
    line = "<166>Jan 12 10:00:00 fw1 %ASA-6-302013: Built device_host=evil device_host_long=evil2"
    ext = extensions(convert_line(line))
    assert ext["dvchost"] == "fw1"
    assert "shost" not in ext


def test_bundled_appliance_mappings_use_the_pair():
    for name in ("cisco_asa", "cisco_ios", "f5"):
        ext = load_mapping(name)["extensions"]
        assert ext["dvchost"] == "%(device_host)s"
        assert ext["shost"] == "%(device_host_long)s"


def test_linux_mapping_still_reports_shost():
    cef = convert_line("<38>Jan 12 10:00:00 web01 sshd[2211]: Failed password for root", strict=True)
    assert cef.split("|")[1:3] == ["Linux", "Syslog"]
    ext = extensions(cef)
    assert ext["shost"] == "web01"
    assert "dvchost" not in ext


def test_linux_mapping_keeps_long_host_in_shost():
    cef = convert_line(f"<38>1 2026-01-12T10:00:00Z {LONG_HOST} sshd 2211 - - Failed password", strict=True)
    ext = extensions(cef)
    assert ext["shost"] == LONG_HOST
    assert "dvchost" not in ext


@pytest.mark.parametrize(
    "line, product, dvchost",
    [
        (
            '<189>Jan 12 10:00:00 fwhost date=2020-01-01 time=10:00:00 devname="fgt1" devid="FGT" '
            'logid="0000000013" type="traffic" srcip=10.1.1.1 dstip=10.2.2.2',
            "FortiGate",
            "fgt1",
        ),
        (
            '<30>Jan 12 10:00:00 fwhost device="SFW" date=2020-05-18 time=14:38:48 device_name="XG230" '
            'log_id=041101618035 log_type="Firewall" src_ip="10.9.9.9"',
            "XG Firewall",
            "XG230",
        ),
    ],
)
def test_fortinet_and_sophos_unchanged(line, product, dvchost):
    cef = convert_line(line)
    assert cef.split("|")[2] == product
    ext = extensions(cef)
    assert ext["dvchost"] == dvchost
    assert ext["shost"] == "fwhost"
