"""Arista EOS platform profile (LLDP; no CDP by default)."""

from __future__ import annotations

import re

from ..models import Platform
from ..normalize import interface_matches_token
from .base import (
    PlatformProfile,
    parse_cdp_neighbor_detail,
    parse_counters_table,
    parse_flap_count,
    parse_portchannel_summary,
    register,
)

_COUNTER_COLUMNS = {
    "fcs": "crc_errors",
    "rx": "input_errors",
    "tx": "discards_out",  # EOS 'Tx' column in counters errors = transmit errors
}


def _parse_show_interfaces(raw: str) -> dict:
    result: dict = {}
    m = re.search(r"^(\S+) is (.+?), line protocol is (\S+)", raw, re.MULTILINE)
    if m:
        admin = m.group(2).strip().lower()
        result["link_status"] = "up" if admin == "up" else admin
        result["protocol_status"] = m.group(3).strip().lower()
    m = re.search(r"(Full|Half|Auto)-duplex,\s*([^,\n]+)", raw)
    if m:
        result["duplex"] = m.group(1).lower()
        result["speed"] = m.group(2).strip()
    m = re.search(r"(\d+) packets input", raw)
    if m:
        result["input_packets"] = int(m.group(1))
    m = re.search(r"(\d+) packets output", raw)
    if m:
        result["output_packets"] = int(m.group(1))
    m = re.search(r"(\d+) input errors, (\d+) CRC", raw)
    if m:
        result["input_errors"] = int(m.group(1))
        result["crc_errors"] = int(m.group(2))
    m = re.search(r"(\d+) input discards", raw)
    if m:
        result["discards_in"] = int(m.group(1))
    m = re.search(r"(\d+) output discards", raw)
    if m:
        result["discards_out"] = int(m.group(1))
    m = re.search(r"(\d+) late collision", raw)
    if m:
        result["late_collisions"] = int(m.group(1))
    return result


def _parse_transceiver(raw: str, canonical: str) -> dict:
    """Parse the EOS transceiver table: Temp, Voltage, Bias, Tx dBm, Rx dBm."""
    result: dict = {}
    for line in raw.splitlines():
        tokens = line.split()
        if len(tokens) >= 6 and interface_matches_token(tokens[0], canonical):
            try:
                result["dom_tx_power_dbm"] = float(tokens[4])
                result["dom_rx_power_dbm"] = float(tokens[5])
            except ValueError:
                pass
            break
    return result


def _parse_version(raw: str) -> dict:
    result: dict = {}
    m = re.search(r"Software image version:\s+(\S+)", raw)
    if m:
        result["os_version"] = m.group(1)
    m = re.search(r"^Arista\s+(\S+)", raw, re.MULTILINE)
    if m:
        result["model"] = m.group(1)
    return result


class EosProfile(PlatformProfile):
    platform = Platform.EOS
    netmiko_device_type = "arista_eos"
    templates = {
        "version": "show version",
        "interface": "show interfaces {interface}",
        "counters": "show interfaces {interface} counters errors",
        "transceiver": "show interfaces {interface} transceiver",
        "neighbors": "show lldp neighbors {interface} detail",
        "portchannel": "show port-channel summary",
        "logging": "show logging | include {interface}",
    }

    def parse(self, key: str, raw: str, canonical_interface: str) -> dict:
        if key == "interface":
            return _parse_show_interfaces(raw)
        if key == "counters":
            return parse_counters_table(raw, canonical_interface, _COUNTER_COLUMNS)
        if key == "transceiver":
            return _parse_transceiver(raw, canonical_interface)
        if key == "neighbors":
            return parse_cdp_neighbor_detail(raw)  # also handles LLDP fields
        if key == "portchannel":
            return parse_portchannel_summary(raw)
        if key == "logging":
            return parse_flap_count(raw)
        if key == "version":
            return _parse_version(raw)
        return {}


register(EosProfile())
