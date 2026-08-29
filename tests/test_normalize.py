import pytest

from iftriage.models import Platform
from iftriage.normalize import (
    InterfaceNameError,
    expand_interface,
    interface_matches_token,
    is_portchannel_name,
    line_references_interface,
)


@pytest.mark.parametrize(
    "platform,short,expected",
    [
        (Platform.IOS_XE, "Gi3/0/20", "GigabitEthernet3/0/20"),
        (Platform.IOS_XE, "Te1/1/3", "TenGigabitEthernet1/1/3"),
        (Platform.IOS_XE, "Twe1/0/1", "TwentyFiveGigE1/0/1"),
        (Platform.IOS_XE, "Po214", "Port-channel214"),
        (Platform.IOS_XE, "GigabitEthernet3/0/20", "GigabitEthernet3/0/20"),
        (Platform.NXOS, "Eth4/15", "Ethernet4/15"),
        (Platform.NXOS, "Et4/15", "Ethernet4/15"),
        (Platform.NXOS, "Po214", "port-channel214"),
        (Platform.EOS, "Et4/15", "Ethernet4/15"),
        (Platform.EOS, "Et3/25/3", "Ethernet3/25/3"),
        (Platform.EOS, "Po214", "Port-Channel214"),
        (Platform.EOS, "Ethernet4/15", "Ethernet4/15"),
        (Platform.NXOS, "Po21", "port-channel21"),
    ],
)
def test_expand_interface(platform, short, expected):
    assert expand_interface(platform, short) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "Gi3/0/20; reload",  # injection attempt
        "Gi3/0/20 | include x",
        "",
        "foo",
        "Xx1/1",
        "Gi",
        "3/0/20",
    ],
)
def test_expand_interface_rejects_unsafe_names(bad):
    with pytest.raises(InterfaceNameError):
        expand_interface(Platform.IOS_XE, bad)


@pytest.mark.parametrize(
    "token,canonical,expected",
    [
        ("Gi3/0/20", "GigabitEthernet3/0/20", True),
        ("Eth4/15", "Ethernet4/15", True),
        ("Et4/15", "Ethernet4/15", True),
        ("Po214", "Port-channel214", True),
        ("Po214", "Port-Channel214", True),
        ("Gi3/0/21", "GigabitEthernet3/0/20", False),
        ("Te3/0/20", "GigabitEthernet3/0/20", False),
        ("Port", "GigabitEthernet3/0/20", False),
    ],
)
def test_interface_matches_token(token, canonical, expected):
    assert interface_matches_token(token, canonical) is expected


# Device-side `| include <name>` is a substring match: filtered logging output
# for a low-numbered port also carries its higher-numbered siblings.
@pytest.mark.parametrize(
    "line,canonical,expected",
    [
        (
            "%LINK-3-UPDOWN: Interface GigabitEthernet3/0/2, changed state to down",
            "GigabitEthernet3/0/2",
            True,
        ),
        (
            "%LINK-3-UPDOWN: Interface GigabitEthernet3/0/20, changed state to down",
            "GigabitEthernet3/0/2",
            False,
        ),
        (
            "%LINEPROTO-5-UPDOWN: Line protocol on Interface Gi3/0/2, changed state",
            "GigabitEthernet3/0/2",
            True,
        ),
        (
            "%QUEUEMONITOR-6-LENGTH_OVER_THRESHOLD: ingress port-set "
            "Ethernet3/25/1,Ethernet3/25/3,Ethernet3/26/1 over high threshold",
            "Ethernet3/25/3",
            True,
        ),
        (
            "Aug 24 02:11:41.520: %SYS-5-CONFIG_I: configured from console",
            "Vlan3",
            False,
        ),
        (
            "%LINK-3-UPDOWN: Interface Vlan20, changed state to up",
            "GigabitEthernet3/0/20",
            False,
        ),
        ("", "GigabitEthernet3/0/2", False),
    ],
)
def test_line_references_interface(line, canonical, expected):
    assert line_references_interface(line, canonical) is expected


def test_is_portchannel_name_matches_every_platform_spelling():
    for name in ("Po1", "Po214", "Port-channel10", "port-channel10", "Port-Channel214"):
        assert is_portchannel_name(name)


def test_is_portchannel_name_rejects_everything_else():
    # "Pos1" matters: packet-over-SONET must not be mistaken for a bundle.
    for name in ("Gi3/0/23", "Ethernet4/15", "Vlan10", "Pos1", "", "po", "garbage"):
        assert not is_portchannel_name(name)


def test_malicious_member_tokens_never_reach_a_command_template():
    """Port-channel member names come from device output; anything not
    interface-shaped must be rejected before command substitution."""
    for token in (
        "foo; reload",
        "Gi3/0/23 && clear counters",
        "Gi3/0/23\nreload",
        "Unknown99",
    ):
        with pytest.raises(InterfaceNameError):
            expand_interface(Platform.IOS_XE, token)
