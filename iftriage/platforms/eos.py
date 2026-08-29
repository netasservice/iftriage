"""Arista EOS platform profile (LLDP; no CDP by default)."""

from __future__ import annotations

import re

from ..models import Platform
from ..normalize import interface_matches_token
from .base import (
    PlatformProfile,
    parse_cdp_neighbor_detail,
    parse_counters_table,
    parse_cpu_from_idle,
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
    match = re.search(r"^(\S+) is (.+?), line protocol is (\S+)", raw, re.MULTILINE)
    if match:
        admin = match.group(2).strip().lower()
        result["link_status"] = "up" if admin == "up" else admin
        result["protocol_status"] = match.group(3).strip().lower()
    match = re.search(r"(Full|Half|Auto)-duplex,\s*([^,\n]+)", raw)
    if match:
        result["duplex"] = match.group(1).lower()
        result["speed"] = match.group(2).strip()
    match = re.search(r"(\d+) packets input", raw)
    if match:
        result["input_packets"] = int(match.group(1))
    match = re.search(r"(\d+) packets output", raw)
    if match:
        result["output_packets"] = int(match.group(1))
    match = re.search(r"(\d+) input errors, (\d+) CRC", raw)
    if match:
        result["input_errors"] = int(match.group(1))
        result["crc_errors"] = int(match.group(2))
    match = re.search(r"(\d+) input discards", raw)
    if match:
        result["discards_in"] = int(match.group(1))
    match = re.search(r"(\d+) output discards", raw)
    if match:
        result["discards_out"] = int(match.group(1))
    match = re.search(r"(\d+) late collision", raw)
    if match:
        result["late_collisions"] = int(match.group(1))
    return result


def _parse_transceiver(raw: str, canonical: str) -> dict:
    """Parse the EOS transceiver table: Temp, Voltage, Bias, Tx dBm, Rx dBm.

    Handles both row layouts seen in the fleet:
      Et4/15        31.42  3.28  7.06  -2.63  -3.27   0:00:03 ago
      Ethernet3/25  3      22.09 3.27  6.70  -1.50  -6.66  0:00:01 ago
    The second is the breakout form: the port column holds the parent
    interface and a separate Channel column holds the lane number.
    """
    result: dict = {}
    for line in raw.splitlines():
        tokens = line.split()
        if len(tokens) < 6:
            continue
        matched = interface_matches_token(tokens[0], canonical)
        if not matched and tokens[1].isdigit():
            matched = interface_matches_token(f"{tokens[0]}/{tokens[1]}", canonical)
        if not matched:
            continue
        numbers: list[float] = []
        for token in tokens[1:]:
            try:
                numbers.append(float(token))
            except ValueError:
                continue
        # Row carries temp, voltage, bias, tx, rx (plus the channel number in
        # the breakout form); tx/rx are always the last two numeric columns.
        if len(numbers) >= 5:
            result["dom_tx_power_dbm"] = numbers[-2]
            result["dom_rx_power_dbm"] = numbers[-1]
        break
    return result


def _parse_version(raw: str) -> dict:
    result: dict = {}
    match = re.search(r"Software image version:\s+(\S+)", raw)
    if match:
        result["os_version"] = match.group(1)
    match = re.search(r"^Arista\s+(\S+)", raw, re.MULTILINE)
    if match:
        result["model"] = match.group(1)
    return result


class EosProfile(PlatformProfile):
    platform = Platform.EOS
    netmiko_device_type = "arista_eos"
    templates = {
        "cpu": "show processes top once | include Cpu",
        "version": "show version",
        "interface": "show interfaces {interface}",
        "counters": "show interfaces {interface} counters errors",
        "transceiver": "show interfaces {interface} transceiver",
        "neighbors": "show lldp neighbors {interface} detail",
        "portchannel": "show port-channel summary",
        "logging": "show logging | include {interface}",
    }

    def parse(self, key: str, raw: str, canonical_interface: str) -> dict:
        if key == "cpu":
            return parse_cpu_from_idle(raw)
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
            return parse_flap_count(raw, canonical_interface)
        if key == "version":
            return _parse_version(raw)
        return {}


register(EosProfile())
