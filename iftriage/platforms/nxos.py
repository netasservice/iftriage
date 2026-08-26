"""Cisco Nexus (NX-OS) platform profile."""

from __future__ import annotations

import re

from ..models import Platform
from .base import (
    PlatformProfile,
    parse_cdp_neighbor_detail,
    parse_counters_table,
    parse_flap_count,
    parse_portchannel_summary,
    register,
)

_COUNTER_COLUMNS = {
    "fcs-err": "crc_errors",
    "rcv-err": "input_errors",
    "outdiscards": "discards_out",
    "late-col": "late_collisions",
}


def _parse_show_interface(raw: str) -> dict:
    result: dict = {}
    match = re.search(r"^(\S+) is (\S+)", raw, re.MULTILINE)
    if match:
        result["link_status"] = match.group(2).strip(" ,").lower()
    match = re.search(r"admin state is (\S+)", raw)
    if match:
        result["protocol_status"] = match.group(1).strip(",").lower()
    match = re.search(r"(full|half|auto)-duplex,\s*([^,\n]+)", raw, re.IGNORECASE)
    if match:
        result["duplex"] = match.group(1).lower()
        result["speed"] = match.group(2).strip()
    match = re.search(r"^\s*(\d+)\s+input packets", raw, re.MULTILINE)
    if match:
        result["input_packets"] = int(match.group(1))
    match = re.search(r"^\s*(\d+)\s+output packets", raw, re.MULTILINE)
    if match:
        result["output_packets"] = int(match.group(1))
    match = re.search(r"(\d+)\s+CRC", raw)
    if match:
        result["crc_errors"] = int(match.group(1))
    match = re.search(r"(\d+)\s+input error", raw)
    if match:
        result["input_errors"] = int(match.group(1))
    match = re.search(r"(\d+)\s+input discard", raw)
    if match:
        result["discards_in"] = int(match.group(1))
    match = re.search(r"(\d+)\s+output discard", raw)
    if match:
        result["discards_out"] = int(match.group(1))
    match = re.search(r"(\d+)\s+late collision", raw)
    if match:
        result["late_collisions"] = int(match.group(1))
    return result


def _parse_transceiver_details(raw: str) -> dict:
    result: dict = {}
    match = re.search(r"Tx Power\s+(-?[\d.]+)\s+dBm", raw)
    if match:
        result["dom_tx_power_dbm"] = float(match.group(1))
    match = re.search(r"Rx Power\s+(-?[\d.]+)\s+dBm", raw)
    if match:
        result["dom_rx_power_dbm"] = float(match.group(1))
    return result


def _parse_version(raw: str) -> dict:
    result: dict = {}
    match = re.search(r"NXOS: version\s+(\S+)", raw) or re.search(
        r"system:\s+version\s+(\S+)", raw
    )
    if match:
        result["os_version"] = match.group(1)
    match = re.search(r"cisco\s+(Nexus\S*(?:\s+\S+)?)\s+[Cc]hassis", raw)
    if match:
        result["model"] = match.group(1)
    return result


class NxosProfile(PlatformProfile):
    platform = Platform.NXOS
    netmiko_device_type = "cisco_nxos"
    templates = {
        "version": "show version",
        "interface": "show interface {interface}",
        "counters": "show interface {interface} counters errors",
        "transceiver": "show interface {interface} transceiver details",
        "neighbors": "show cdp neighbors interface {interface} detail",
        "portchannel": "show port-channel summary",
        "logging": "show logging logfile | include {interface}",
    }

    def parse(self, key: str, raw: str, canonical_interface: str) -> dict:
        if key == "interface":
            return _parse_show_interface(raw)
        if key == "counters":
            return parse_counters_table(raw, canonical_interface, _COUNTER_COLUMNS)
        if key == "transceiver":
            return _parse_transceiver_details(raw)
        if key == "neighbors":
            return parse_cdp_neighbor_detail(raw)
        if key == "portchannel":
            return parse_portchannel_summary(raw)
        if key == "logging":
            return parse_flap_count(raw)
        if key == "version":
            return _parse_version(raw)
        return {}


register(NxosProfile())
