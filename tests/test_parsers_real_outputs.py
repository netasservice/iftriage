"""Phase 2: parsers validated against sanitized REAL fleet outputs.

Fixtures under tests/fixtures/<platform>/real_* are transcribed from captures
taken on the actual fleet (C9410R / Nexus / DCS-7808-CH), with hostnames,
IPs, serials, and MACs replaced by fictional values. They include the real
prompt/echo lines on purpose — parsers must tolerate them.
"""

from conftest import load_fixture
from test_rules import make_case

from iftriage.config import Thresholds
from iftriage.models import NormalizedInterfaceStats, Platform, VerdictCategory
from iftriage.platforms import get_profile
from iftriage.platforms.base import COMMAND_KEYS
from iftriage.rules import evaluate_case

IOS = get_profile(Platform.IOS_XE)
NX = get_profile(Platform.NXOS)
EOS = get_profile(Platform.EOS)


# ---- IOS-XE: C9410R access port in a real duplex mismatch ------------------


def test_real_ios_xe_version_c9410():
    parsed = IOS.parse(
        "version", load_fixture("ios_xe", "real_show_version_c9410.txt"), ""
    )
    assert parsed["os_version"] == "17.06.05"
    assert parsed["model"] == "C9410R"


def test_real_ios_xe_half_duplex_interface():
    parsed = IOS.parse(
        "interface",
        load_fixture("ios_xe", "real_show_interfaces_half_duplex.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed["link_status"] == "up"
    assert parsed["duplex"] == "half"
    assert parsed["speed"] == "100Mb/s"
    assert parsed["input_packets"] == 92971720
    assert parsed["input_errors"] == 0
    assert parsed["crc_errors"] == 0
    assert parsed["late_collisions"] == 38445916
    assert parsed["discards_out"] == 223462


def test_real_ios_xe_counters_late_col():
    parsed = IOS.parse(
        "counters",
        load_fixture("ios_xe", "real_counters_errors_late_col.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed["late_collisions"] == 38445927
    assert parsed["rcv_err"] == 0
    assert "input_errors" not in parsed  # Rcv-Err is its own series
    assert parsed["crc_errors"] == 0
    assert parsed["discards_out"] == 223462


def test_real_ios_xe_copper_transceiver_not_implemented():
    parsed = IOS.parse(
        "transceiver",
        load_fixture("ios_xe", "real_transceiver_not_implemented.txt"),
        "GigabitEthernet3/0/20",
    )
    assert "dom_rx_power_dbm" not in parsed  # stays None -> fail closed


def test_real_ios_xe_cdp_phone_with_mismatch_flag():
    parsed = IOS.parse(
        "neighbors",
        load_fixture("ios_xe", "real_cdp_neighbors_phone_mismatch.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed["neighbor_name"] == "SEP001122AABB99"
    assert parsed["neighbor_port"] == "Port 1"  # CDP port ids can have spaces
    assert parsed["neighbor_duplex"] == "full"
    assert parsed["neighbor_platform"] == "Cisco IP Phone 8841"


def test_real_ios_xe_empty_etherchannel_summary():
    parsed = IOS.parse(
        "portchannel",
        load_fixture("ios_xe", "real_etherchannel_summary_empty.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed == {}


def test_real_ios_xe_logging_flags_duplex_mismatch():
    parsed = IOS.parse(
        "logging",
        load_fixture("ios_xe", "real_logging_duplex_mismatch.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed["flap_count"] == 0
    assert parsed["duplex_mismatch_logged"] is True


def test_real_ios_xe_case_end_to_end_is_config_issue():
    """The full real case: Late-Col delta on a half-duplex port whose phone
    neighbor reports full duplex must come out as LINK_NEGOTIATION."""
    fixtures = {
        "interface": "real_show_interfaces_half_duplex.txt",
        "counters": "real_counters_errors_late_col.txt",
        "transceiver": "real_transceiver_not_implemented.txt",
        "neighbors": "real_cdp_neighbors_phone_mismatch.txt",
        "logging": "real_logging_duplex_mismatch.txt",
    }
    merged: dict = {}
    for key in COMMAND_KEYS:  # same merge order as the collector
        if key in fixtures:
            parsed = IOS.parse(
                key, load_fixture("ios_xe", fixtures[key]), "GigabitEthernet3/0/20"
            )
            merged.update(
                {name: value for name, value in parsed.items() if value is not None}
            )
    stats = NormalizedInterfaceStats(**merged)
    verdict = evaluate_case(make_case("Late-Col"), stats, None, None, Thresholds())
    assert verdict.category is VerdictCategory.LINK_NEGOTIATION
    assert "duplex_mismatch_confirmed" in verdict.reason


# ---- NX-OS: port-channel + fiber member, LLDP-only neighbor ----------------


def test_real_nxos_show_interface_po21():
    parsed = NX.parse(
        "interface",
        load_fixture("nxos", "real_show_interface_po21.txt"),
        "port-channel21",
    )
    assert parsed["link_status"] == "up"
    assert parsed["duplex"] == "full"
    assert parsed["input_packets"] == 17216303954170
    assert parsed["crc_errors"] == 0  # printed as 'CRC/FCS' on this NX-OS
    assert parsed["input_errors"] == 0
    assert parsed["discards_in"] == 177631552
    assert parsed["discards_out"] == 20655
    assert parsed["late_collisions"] == 0
    assert parsed["vpc_status"] == "Up"
    assert parsed["vpc_number"] == 21
    assert parsed["reliability"] == 255
    assert parsed["rxload"] == 87


def test_real_nxos_counters_po21_includes_indiscards_block():
    parsed = NX.parse(
        "counters",
        load_fixture("nxos", "real_counters_errors_po21.txt"),
        "port-channel21",
    )
    assert parsed["discards_out"] == 20655
    assert parsed["discards_in"] == 177631552  # fourth table block
    assert parsed["crc_errors"] == 0
    assert parsed["late_collisions"] == 0


def test_real_nxos_counters_eth4_15():
    parsed = NX.parse(
        "counters",
        load_fixture("nxos", "real_counters_errors_eth4_15.txt"),
        "Ethernet4/15",
    )
    assert parsed["discards_out"] == 8466
    assert parsed["discards_in"] == 44459877


def test_real_nxos_transceiver_sfp10gsr():
    parsed = NX.parse(
        "transceiver",
        load_fixture("nxos", "real_transceiver_details_sfp10gsr.txt"),
        "Ethernet4/15",
    )
    assert parsed["dom_tx_power_dbm"] == -2.18
    assert parsed["dom_rx_power_dbm"] == -2.94


def test_real_nxos_cdp_neighbor_not_found():
    parsed = NX.parse(
        "neighbors",
        load_fixture("nxos", "real_cdp_neighbors_not_found.txt"),
        "Ethernet4/15",
    )
    assert parsed == {}


def test_real_nxos_lldp_neighbor_detail():
    parsed = NX.parse(
        "neighbors_lldp",
        load_fixture("nxos", "real_lldp_neighbors_detail.txt"),
        "Ethernet4/15",
    )
    assert parsed["neighbor_name"] == "arista switch"
    assert parsed["neighbor_port"] == "Ethernet45"  # NX-OS prints 'Port id:'


def test_real_nxos_port_channel_summary_wrapped_members():
    parsed = NX.parse(
        "portchannel",
        load_fixture("nxos", "real_port_channel_summary_wrapped.txt"),
        "port-channel21",
    )
    members = parsed["port_channel_members"]
    # Po21's member list wraps onto a continuation line in the real output.
    assert members["Po21"] == ["Eth3/14", "Eth3/15", "Eth4/14", "Eth4/15"]
    assert members["Po1"] == ["Eth3/1", "Eth4/1"]


def test_real_nxos_empty_filtered_logging():
    parsed = NX.parse(
        "logging", load_fixture("nxos", "real_logging_empty.txt"), "Ethernet4/15"
    )
    assert parsed["flap_count"] == 0
    assert parsed["duplex_mismatch_logged"] is False


# ---- EOS: DCS-7808-CH breakout interface, down/down with CRC history -------


def test_real_eos_version_7808():
    parsed = EOS.parse("version", load_fixture("eos", "real_show_version_7808.txt"), "")
    assert parsed["os_version"] == "4.34.5M"
    assert parsed["model"] == "DCS-7808-CH"


def test_real_eos_down_breakout_interface():
    parsed = EOS.parse(
        "interface",
        load_fixture("eos", "real_show_interfaces_down_breakout.txt"),
        "Ethernet3/25/3",
    )
    assert parsed["link_status"] == "down"
    assert parsed["protocol_status"] == "down"
    assert parsed["duplex"] == "full"
    assert parsed["input_packets"] == 413685992377
    assert parsed["input_errors"] == 9874442
    assert parsed["crc_errors"] == 3736545
    assert parsed["discards_in"] == 199760
    assert parsed["discards_out"] == 221624
    assert parsed["late_collisions"] == 0
    assert parsed["member_of_portchannel"] == "Port-Channel195"


def test_real_eos_counters_breakout():
    parsed = EOS.parse(
        "counters",
        load_fixture("eos", "real_counters_errors_breakout.txt"),
        "Ethernet3/25/3",
    )
    assert parsed["crc_errors"] == 3736545
    assert parsed["input_errors"] == 9874442


def test_real_eos_transceiver_breakout_channel_column():
    # The port column holds the parent (Ethernet3/25) and the lane lives in a
    # separate Channel column — the parser must join them to match Et3/25/3.
    parsed = EOS.parse(
        "transceiver",
        load_fixture("eos", "real_transceiver_breakout_channel.txt"),
        "Ethernet3/25/3",
    )
    assert parsed["dom_tx_power_dbm"] == -1.50
    assert parsed["dom_rx_power_dbm"] == -6.66


def test_real_eos_lldp_no_neighbors():
    parsed = EOS.parse(
        "neighbors",
        load_fixture("eos", "real_lldp_neighbors_none.txt"),
        "Ethernet3/25/3",
    )
    assert parsed == {}


def test_real_nxos_member_port_names_its_bundle():
    """The `Belongs to Po21` line is what lets the collector skip the
    port-channel summary on devices where no case touches a bundle."""
    parsed = NX.parse(
        "interface",
        load_fixture("nxos", "real_show_interface_member_eth3_14.txt"),
        "Ethernet3/14",
    )
    assert parsed["member_of_portchannel"] == "Po21"
    assert parsed["link_status"] == "up"
    assert parsed["duplex"] == "full"
    assert parsed["crc_errors"] == 0
    assert parsed["discards_in"] == 45158036
    assert parsed["discards_out"] == 6240


def test_real_eos_port_channel_dense_flags():
    parsed = EOS.parse(
        "portchannel",
        load_fixture("eos", "real_port_channel_dense.txt"),
        "Ethernet3/25/3",
    )
    members = parsed["port_channel_members"]
    assert members["Po1"] == [
        "Et3/1/1",
        "Et3/36/1",
        "Et4/1/1",
        "Et4/36/1",
        "Et5/1/1",
        "Et5/36/1",
        "Et6/1/1",
        "Et6/36/1",
        "Et7/1/1",
        "Et7/36/1",
        "Et8/1/1",
        "Et8/36/1",
    ]
    # MLAG peer ports (PEt...) are captured verbatim; they can never match a
    # local canonical interface name, so they are harmless in dedup.
    assert members["Po101"] == ["Et4/10/2", "PEt4/10/2"]


def test_real_eos_logging_iso_timestamps_flaps():
    parsed = EOS.parse(
        "logging",
        load_fixture("eos", "real_logging_flaps_iso.txt"),
        "Ethernet3/25/3",
    )
    # Two LINEPROTO UPDOWN hits; the QUEUEMONITOR line must not count.
    assert parsed["flap_count"] == 2
    assert parsed["duplex_mismatch_logged"] is False
