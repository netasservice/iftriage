"""Platform parsers tested against raw fixture outputs. Zero device access."""

import pytest
from conftest import load_fixture

from iftriage.models import Platform
from iftriage.platforms import get_profile
from iftriage.platforms.base import parse_duration_minutes

IOS = get_profile(Platform.IOS_XE)
NX = get_profile(Platform.NXOS)
EOS = get_profile(Platform.EOS)


# ---- IOS-XE ----------------------------------------------------------------


def test_ios_xe_show_interfaces():
    parsed = IOS.parse(
        "interface",
        load_fixture("ios_xe", "show_interfaces.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed["link_status"] == "up"
    assert parsed["protocol_status"] == "up"
    assert parsed["duplex"] == "full"
    assert parsed["input_packets"] == 109443210
    assert parsed["input_errors"] == 3271
    assert parsed["crc_errors"] == 3271
    assert parsed["late_collisions"] == 0
    assert parsed["discards_in"] == 17
    assert parsed["discards_out"] == 42
    assert parsed["mtu"] == 1500
    assert parsed["media_type"] == "10/100/1000BaseTX"
    assert parsed["bytes_input"] == 2394664329
    assert parsed["bytes_output"] == 8873201991
    assert parsed["no_buffer"] == 0
    assert parsed["runts"] == 0
    assert parsed["giants"] == 0
    assert parsed["align_errors"] == 0
    assert parsed["overrun"] == 0
    assert parsed["ignored"] == 0
    assert parsed["output_errors"] == 0
    assert parsed["collisions"] == 0
    assert parsed["interface_resets"] == 2
    assert parsed["input_rate_pps"] == 267
    assert parsed["output_rate_pps"] == 341
    assert parsed["load_interval_seconds"] == 300
    assert parsed["counters_never_cleared"] is True
    assert "last_clearing_minutes" not in parsed
    assert parsed["last_input_minutes"] == pytest.approx(1 / 60)


def test_ios_xe_counters_errors():
    parsed = IOS.parse(
        "counters",
        load_fixture("ios_xe", "counters_errors.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed["crc_errors"] == 3271
    assert parsed["fcs_errors"] == 3271
    # Rcv-Err is its own series: it must never masquerade as input_errors.
    assert parsed["rcv_err"] == 3271
    assert "input_errors" not in parsed
    assert parsed["align_errors"] == 0
    assert parsed["undersize"] == 0
    assert parsed["output_errors"] == 0
    assert parsed["runts"] == 0
    assert parsed["giants"] == 0
    assert parsed["discards_out"] == 42
    assert parsed["late_collisions"] == 0


def test_ios_xe_golden_gi8_0_4_reference_case():
    """Reference case for the v2 engine: massive Rcv-Err with near-zero FCS
    on a copper port, no traffic. The two outputs must reconcile:
    input errors == runts + Rcv-Err."""
    interface = IOS.parse(
        "interface",
        load_fixture("ios_xe", "real_show_interfaces_gi8_0_4.txt"),
        "GigabitEthernet8/0/4",
    )
    assert interface["input_errors"] == 320792846
    assert interface["crc_errors"] == 185
    assert interface["runts"] == 4718847
    assert interface["giants"] == 0
    assert interface["overrun"] == 0
    assert interface["ignored"] == 0
    assert interface["no_buffer"] == 0
    assert interface["discards_in"] == 0
    assert interface["discards_out"] == 0
    assert interface["late_collisions"] == 0
    assert interface["input_packets"] == 561806
    assert interface["bytes_input"] == 87262523986
    assert interface["mtu"] == 9160
    assert interface["media_type"] == "10/100/1000BaseTX"
    assert interface["speed"] == "100Mb/s"
    assert interface["input_rate_pps"] == 0
    assert interface["load_interval_seconds"] == 30
    assert interface["interface_resets"] == 7
    assert interface["counters_never_cleared"] is True
    assert interface["last_input_minutes"] == pytest.approx(3 + 22 / 60)

    counters = IOS.parse(
        "counters",
        load_fixture("ios_xe", "real_counters_errors_gi8_0_4.txt"),
        "GigabitEthernet8/0/4",
    )
    assert counters["rcv_err"] == 316073999
    assert counters["fcs_errors"] == 185
    assert counters["align_errors"] == 0
    assert counters["undersize"] == 0
    assert counters["runts"] == 4718847
    assert counters["giants"] == 0
    assert counters["output_errors"] == 0
    assert counters["late_collisions"] == 0
    assert counters["discards_out"] == 0
    # The reconciliation identity the v2 engine verifies at runtime.
    assert interface["input_errors"] == counters["runts"] + counters["rcv_err"]


def test_ios_xe_transceiver_detail():
    parsed = IOS.parse(
        "transceiver",
        load_fixture("ios_xe", "transceiver_detail.txt"),
        "TenGigabitEthernet1/1/3",
    )
    assert parsed["dom_tx_power_dbm"] == -2.5
    assert parsed["dom_rx_power_dbm"] == -3.1


def test_ios_xe_cdp_neighbors():
    parsed = IOS.parse(
        "neighbors",
        load_fixture("ios_xe", "cdp_neighbors_detail.txt"),
        "GigabitEthernet3/0/20",
    )
    assert parsed["neighbor_name"] == "dist-sw-01.example.net"
    assert parsed["neighbor_port"] == "TenGigabitEthernet1/0/5"
    assert parsed["neighbor_duplex"] == "full"
    assert parsed["neighbor_platform"] == "cisco C9500-32C"


def test_ios_xe_etherchannel_summary():
    parsed = IOS.parse(
        "portchannel",
        load_fixture("ios_xe", "etherchannel_summary.txt"),
        "Port-channel214",
    )
    assert parsed["port_channel_members"] == {"Po214": ["Gi3/0/23", "Gi3/0/24"]}


def test_ios_xe_logging_flaps():
    parsed = IOS.parse(
        "logging", load_fixture("ios_xe", "logging.txt"), "GigabitEthernet3/0/20"
    )
    assert parsed["flap_count"] == 2
    assert IOS.parse("logging", "", "GigabitEthernet3/0/20")["flap_count"] == 0


def test_ios_xe_logging_ignores_neighbouring_ports():
    """`| include GigabitEthernet3/0/2` also matches /20, /21, /29 on the
    device; only the port under analysis may count."""
    raw = load_fixture("ios_xe", "logging_neighbor_ports.txt")
    parsed = IOS.parse("logging", raw, "GigabitEthernet3/0/2")
    assert parsed["flap_count"] == 1
    assert parsed["duplex_mismatch_logged"] is False

    sibling = IOS.parse("logging", raw, "GigabitEthernet3/0/21")
    assert sibling["flap_count"] == 0
    assert sibling["duplex_mismatch_logged"] is True


def test_ios_xe_version():
    parsed = IOS.parse(
        "version", load_fixture("ios_xe", "show_version.txt"), "GigabitEthernet3/0/20"
    )
    assert parsed["os_version"] == "17.06.05"
    assert parsed["model"] == "C9300-48P"
    # 41 weeks, 3 days, 2 hours, 11 minutes
    assert parsed["uptime_minutes"] == pytest.approx(41 * 10080 + 3 * 1440 + 131)


# ---- NX-OS -----------------------------------------------------------------


def test_nxos_show_interface():
    parsed = NX.parse(
        "interface", load_fixture("nxos", "show_interface.txt"), "Ethernet4/15"
    )
    assert parsed["link_status"] == "up"
    assert parsed["duplex"] == "full"
    assert parsed["input_packets"] == 89425035
    assert parsed["input_errors"] == 912
    assert parsed["crc_errors"] == 912
    assert parsed["discards_in"] == 388
    assert parsed["discards_out"] == 57
    assert parsed["late_collisions"] == 0
    assert parsed["mtu"] == 1500
    assert parsed["media_type"] == "10G"
    assert parsed["bytes_input"] == 71234567890
    assert parsed["bytes_output"] == 81234567890
    assert parsed["runts"] == 0
    assert parsed["giants"] == 0
    assert parsed["no_buffer"] == 0
    assert parsed["undersize"] == 0  # NX-OS "short frame"
    assert parsed["overrun"] == 0
    assert parsed["ignored"] == 0
    assert parsed["output_errors"] == 0
    assert parsed["collisions"] == 0
    assert parsed["interface_resets"] == 1
    assert parsed["input_rate_pps"] == 512
    assert parsed["output_rate_pps"] == 401
    assert parsed["load_interval_seconds"] == 30
    assert parsed["counters_never_cleared"] is True


def test_nxos_counters_errors():
    parsed = NX.parse(
        "counters", load_fixture("nxos", "counters_errors.txt"), "Ethernet4/15"
    )
    assert parsed["crc_errors"] == 912
    assert parsed["fcs_errors"] == 912
    assert parsed["rcv_err"] == 912
    assert "input_errors" not in parsed
    assert parsed["align_errors"] == 0
    assert parsed["undersize"] == 0
    assert parsed["output_errors"] == 0
    assert parsed["discards_out"] == 57


def test_nxos_transceiver_details():
    parsed = NX.parse(
        "transceiver", load_fixture("nxos", "transceiver_details.txt"), "Ethernet4/15"
    )
    assert parsed["dom_tx_power_dbm"] == -2.25
    assert parsed["dom_rx_power_dbm"] == -3.55


def test_nxos_cdp_neighbors():
    parsed = NX.parse(
        "neighbors", load_fixture("nxos", "cdp_neighbors_detail.txt"), "Ethernet4/15"
    )
    assert parsed["neighbor_name"].startswith("core-sw-01")
    assert parsed["neighbor_port"] == "Ethernet1/33"


def test_nxos_port_channel_summary():
    parsed = NX.parse(
        "portchannel",
        load_fixture("nxos", "port_channel_summary.txt"),
        "port-channel214",
    )
    assert parsed["port_channel_members"] == {"Po214": ["Eth4/16", "Eth4/17"]}


def test_nxos_version():
    parsed = NX.parse(
        "version", load_fixture("nxos", "show_version.txt"), "Ethernet4/15"
    )
    assert parsed["os_version"] == "9.3(10)"
    assert "Nexus9000" in parsed["model"]
    # Kernel uptime is 291 day(s), 4 hour(s), 22 minute(s), 1 second(s)
    assert parsed["uptime_minutes"] == pytest.approx(291 * 1440 + 262 + 1 / 60)


# ---- EOS -------------------------------------------------------------------


def test_eos_show_interfaces():
    parsed = EOS.parse(
        "interface", load_fixture("eos", "show_interfaces.txt"), "Ethernet4/15"
    )
    assert parsed["link_status"] == "up"
    assert parsed["duplex"] == "full"
    assert parsed["input_packets"] == 215883911
    assert parsed["input_errors"] == 21503
    assert parsed["crc_errors"] == 21503
    assert parsed["discards_in"] == 0
    assert parsed["late_collisions"] == 0
    assert parsed["mtu"] == 9214
    assert parsed["bytes_input"] == 198765432109
    assert parsed["bytes_output"] == 176543210987
    assert parsed["runts"] == 0
    assert parsed["giants"] == 0
    assert parsed["align_errors"] == 0
    assert parsed["symbol_errors"] == 0
    assert parsed["output_errors"] == 0
    assert parsed["collisions"] == 0
    assert parsed["input_rate_pps"] == 891
    assert parsed["output_rate_pps"] == 1021
    assert parsed["load_interval_seconds"] == 300
    assert parsed["counters_never_cleared"] is True


def test_eos_counters_errors():
    parsed = EOS.parse(
        "counters", load_fixture("eos", "counters_errors.txt"), "Ethernet4/15"
    )
    assert parsed["crc_errors"] == 21503
    assert parsed["fcs_errors"] == 21503
    assert parsed["input_errors"] == 21503
    assert parsed["align_errors"] == 0
    assert parsed["symbol_errors"] == 0
    assert parsed["runts"] == 0
    assert parsed["giants"] == 0
    # EOS 'Tx' counts transmit errors, not discards.
    assert parsed["output_errors"] == 0
    assert "discards_out" not in parsed


def test_eos_transceiver():
    parsed = EOS.parse(
        "transceiver", load_fixture("eos", "transceiver.txt"), "Ethernet4/15"
    )
    assert parsed["dom_tx_power_dbm"] == -2.63
    assert parsed["dom_rx_power_dbm"] == -15.21


def test_eos_lldp_neighbors():
    parsed = EOS.parse(
        "neighbors", load_fixture("eos", "lldp_neighbors_detail.txt"), "Ethernet4/15"
    )
    assert parsed["neighbor_name"] == "spine1.example.net"
    assert parsed["neighbor_port"] == "Ethernet21"


def test_eos_port_channel_summary():
    parsed = EOS.parse(
        "portchannel",
        load_fixture("eos", "port_channel_summary.txt"),
        "Port-Channel214",
    )
    assert parsed["port_channel_members"] == {"Po214": ["Ethernet4/16", "Ethernet4/17"]}


def test_eos_version():
    parsed = EOS.parse(
        "version", load_fixture("eos", "show_version.txt"), "Ethernet4/15"
    )
    assert parsed["os_version"] == "4.28.3M"
    assert parsed["model"] == "DCS-7808-CH"
    # Uptime: 41 weeks, 3 days, 2 hours and 11 minutes
    assert parsed["uptime_minutes"] == pytest.approx(41 * 10080 + 3 * 1440 + 131)


# ---- shared duration parsing (counter epochs, last input, uptime) ----------


def test_parse_duration_minutes_formats():
    assert parse_duration_minutes("00:03:22") == pytest.approx(3 + 22 / 60)
    assert parse_duration_minutes("1d02h") == pytest.approx(1440 + 120)
    assert parse_duration_minutes("2w3d") == pytest.approx(2 * 10080 + 3 * 1440)
    assert parse_duration_minutes("2 hours, 11 minutes") == pytest.approx(131)
    assert parse_duration_minutes("4 hour(s), 22 minute(s)") == pytest.approx(262)
    assert parse_duration_minutes("never") is None
    assert parse_duration_minutes("") is None
    assert parse_duration_minutes("garbage") is None


# ---- copper port through the transceiver command (empty/error response) ----


def test_transceiver_absent_yields_no_dom_fields():
    for profile, raw in (
        (IOS, "% Transceiver monitoring is not supported on this interface"),
        (NX, "Ethernet1/1\n    transceiver is not present\n"),
        (EOS, ""),
    ):
        parsed = profile.parse("transceiver", raw, "Ethernet1/1")
        assert "dom_rx_power_dbm" not in parsed  # stays None -> fail closed


# ---- CPU guard readings ----------------------------------------------------


def test_ios_xe_cpu_five_seconds():
    parsed = IOS.parse("cpu", load_fixture("ios_xe", "processes_cpu.txt"), "")
    assert parsed["cpu_percent"] == 12.0


def test_nxos_cpu_from_system_resources_idle():
    parsed = NX.parse("cpu", load_fixture("nxos", "system_resources.txt"), "")
    assert parsed["cpu_percent"] == 5.8  # 100 - 94.20% idle


def test_eos_cpu_from_top_idle():
    parsed = EOS.parse("cpu", load_fixture("eos", "processes_top_cpu.txt"), "")
    assert parsed["cpu_percent"] == 7.9  # 100 - 92.1 id


def test_unrecognized_cpu_output_parses_to_nothing():
    for profile in (IOS, NX, EOS):
        assert profile.parse("cpu", "% Invalid input detected", "") == {}
        assert profile.parse("cpu", "", "") == {}


def test_cpu_command_is_in_every_device_allow_list():
    for profile, interface in (
        (IOS, "GigabitEthernet3/0/20"),
        (NX, "Ethernet4/15"),
        (EOS, "Ethernet4/15"),
    ):
        allowed = profile.allowed_commands([interface])
        rendered = profile.templates["cpu"]
        assert rendered in allowed  # no {interface} placeholder: rendered as-is


# ---- port-channel member discovery (summary -> validated canonical names) --


def test_summary_members_expand_to_canonical_names_per_platform():
    for profile, fixture, po_canonical, expected in (
        (
            IOS,
            ("ios_xe", "etherchannel_summary.txt"),
            "Port-channel214",
            ["GigabitEthernet3/0/23", "GigabitEthernet3/0/24"],
        ),
        (
            NX,
            ("nxos", "port_channel_summary.txt"),
            "port-channel214",
            ["Ethernet4/16", "Ethernet4/17"],
        ),
        (
            EOS,
            ("eos", "port_channel_summary.txt"),
            "Port-Channel214",
            ["Ethernet4/16", "Ethernet4/17"],
        ),
    ):
        parsed = profile.parse("portchannel", load_fixture(*fixture), po_canonical)
        members = parsed["port_channel_members"]["Po214"]
        canonicals = [profile.canonical_interface(token) for token in members]
        assert canonicals == expected
