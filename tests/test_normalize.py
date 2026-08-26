import pytest

from iftriage.models import Platform
from iftriage.normalize import (
    InterfaceNameError,
    expand_interface,
    interface_matches_token,
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
        (Platform.EOS, "Po214", "Port-Channel214"),
        (Platform.EOS, "Ethernet4/15", "Ethernet4/15"),
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
