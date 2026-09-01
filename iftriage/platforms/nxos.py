"""Cisco Nexus (NX-OS) platform profile."""

from __future__ import annotations

import re

from ..models import Platform
from .base import (
    PlatformProfile,
    parse_cdp_neighbor_detail,
    parse_counters_table,
    parse_cpu_from_idle,
    parse_flap_count,
    parse_last_clearing,
    parse_portchannel_summary,
    parse_uptime_minutes,
    register,
)

_COUNTER_COLUMNS: dict[str, str | tuple[str, ...]] = {
    "align-err": "align_errors",
    "fcs-err": ("crc_errors", "fcs_errors"),
    "xmit-err": "output_errors",
    "rcv-err": ("input_errors", "rcv_err"),
    "undersize": "undersize",
    "outdiscards": "discards_out",
    "late-col": "late_collisions",
    "runts": "runts",
    "giants": "giants",
    "indiscards": "discards_in",  # NX-OS prints a fourth InDiscards block
}


def _parse_show_interface(raw: str) -> dict:
    result: dict = {}
    match = re.search(r"^(\S+) is (\S+)", raw, re.MULTILINE)
    if match:
        result["link_status"] = match.group(2).strip(" ,").lower()
    match = re.search(r"admin state is (\S+)", raw)
    if match:
        result["protocol_status"] = match.group(1).strip(",").lower()
    match = re.search(r"^\s*Belongs to (\S+)", raw, re.MULTILINE)
    if match:
        result["member_of_portchannel"] = match.group(1)
    match = re.search(r"(full|half|auto)-duplex,\s*([^,\n]+)", raw, re.IGNORECASE)
    if match:
        result["duplex"] = match.group(1).lower()
        result["speed"] = match.group(2).strip()
    match = re.search(r"media type is (\S[^\n]*)", raw)
    if match:
        result["media_type"] = match.group(1).strip()
    match = re.search(r"MTU (\d+) bytes", raw)
    if match:
        result["mtu"] = int(match.group(1))
    match = re.search(r"^\s*(\d+)\s+input packets\s+(\d+)\s+bytes", raw, re.MULTILINE)
    if match:
        result["input_packets"] = int(match.group(1))
        result["bytes_input"] = int(match.group(2))
    else:
        match = re.search(r"^\s*(\d+)\s+input packets", raw, re.MULTILINE)
        if match:
            result["input_packets"] = int(match.group(1))
    match = re.search(r"^\s*(\d+)\s+output packets\s+(\d+)\s+bytes", raw, re.MULTILINE)
    if match:
        result["output_packets"] = int(match.group(1))
        result["bytes_output"] = int(match.group(2))
    else:
        match = re.search(r"^\s*(\d+)\s+output packets", raw, re.MULTILINE)
        if match:
            result["output_packets"] = int(match.group(1))
    match = re.search(
        r"(\d+)\s+runts\s+(\d+)\s+giants\s+(\d+)\s+CRC\s+(\d+)\s+no buffer", raw
    )
    if match:
        result["runts"] = int(match.group(1))
        result["giants"] = int(match.group(2))
        result["crc_errors"] = int(match.group(3))
        result["no_buffer"] = int(match.group(4))
    else:
        match = re.search(r"(\d+)\s+CRC", raw)
        if match:
            result["crc_errors"] = int(match.group(1))
    match = re.search(r"(\d+)\s+input error", raw)
    if match:
        result["input_errors"] = int(match.group(1))
    # NX-OS "short frame" is the undersized-frame bucket.
    match = re.search(r"(\d+)\s+short frame", raw)
    if match:
        result["undersize"] = int(match.group(1))
    match = re.search(r"(\d+)\s+overrun", raw)
    if match:
        result["overrun"] = int(match.group(1))
    match = re.search(r"(\d+)\s+ignored", raw)
    if match:
        result["ignored"] = int(match.group(1))
    match = re.search(r"(\d+)\s+input discard", raw)
    if match:
        result["discards_in"] = int(match.group(1))
    match = re.search(r"(\d+)\s+output discard", raw)
    if match:
        result["discards_out"] = int(match.group(1))
    match = re.search(r"(\d+)\s+output error", raw)
    if match:
        result["output_errors"] = int(match.group(1))
    match = re.search(r"(\d+)\s+collision", raw)
    if match:
        result["collisions"] = int(match.group(1))
    match = re.search(r"(\d+)\s+late collision", raw)
    if match:
        result["late_collisions"] = int(match.group(1))
    match = re.search(r"^\s*(\d+)\s+interface resets", raw, re.MULTILINE)
    if match:
        result["interface_resets"] = int(match.group(1))
    match = re.search(r"(\d+) seconds input rate \d+ bits/sec, (\d+) packets/sec", raw)
    if match:
        result["load_interval_seconds"] = int(match.group(1))
        result["input_rate_pps"] = int(match.group(2))
    match = re.search(r"(\d+) seconds output rate \d+ bits/sec, (\d+) packets/sec", raw)
    if match:
        result["output_rate_pps"] = int(match.group(2))
    result.update(parse_last_clearing(raw))
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
    result.update(parse_uptime_minutes(raw))
    return result


class NxosProfile(PlatformProfile):
    platform = Platform.NXOS
    netmiko_device_type = "cisco_nxos"
    templates = {
        "cpu": "show system resources",
        "version": "show version",
        "interface": "show interface {interface}",
        "counters": "show interface {interface} counters errors",
        "transceiver": "show interface {interface} transceiver details",
        # Non-Cisco neighbors (e.g. Arista uplinks) do not speak CDP; LLDP is
        # collected first and CDP overrides it in the merge when present.
        "neighbors_lldp": "show lldp neighbors interface {interface} detail",
        "neighbors": "show cdp neighbors interface {interface} detail",
        "portchannel": "show port-channel summary",
        "logging": "show logging logfile | include {interface}",
    }

    def parse(self, key: str, raw: str, canonical_interface: str) -> dict:
        if key == "cpu":
            return parse_cpu_from_idle(raw)
        if key == "interface":
            return _parse_show_interface(raw)
        if key == "counters":
            return parse_counters_table(raw, canonical_interface, _COUNTER_COLUMNS)
        if key == "transceiver":
            return _parse_transceiver_details(raw)
        if key in ("neighbors", "neighbors_lldp"):
            return parse_cdp_neighbor_detail(raw)
        if key == "portchannel":
            return parse_portchannel_summary(raw)
        if key == "logging":
            return parse_flap_count(raw, canonical_interface)
        if key == "version":
            return _parse_version(raw)
        return {}


register(NxosProfile())
