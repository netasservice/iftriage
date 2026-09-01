"""Cisco Catalyst (IOS-XE) platform profile."""

from __future__ import annotations

import re

from ..models import Platform
from .base import (
    PlatformProfile,
    parse_cdp_neighbor_detail,
    parse_counters_table,
    parse_cpu_five_seconds,
    parse_duration_minutes,
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
    match = re.search(r"media type is (\S[^\n]*)", raw)
    if match:
        result["media_type"] = match.group(1).strip()
    match = re.search(r"MTU (\d+) bytes", raw)
    if match:
        result["mtu"] = int(match.group(1))
    match = re.search(r"(\d+) packets input, (\d+) bytes, (\d+) no buffer", raw)
    if match:
        result["input_packets"] = int(match.group(1))
        result["bytes_input"] = int(match.group(2))
        result["no_buffer"] = int(match.group(3))
    else:
        match = re.search(r"(\d+) packets input", raw)
        if match:
            result["input_packets"] = int(match.group(1))
    match = re.search(r"(\d+) packets output, (\d+) bytes", raw)
    if match:
        result["output_packets"] = int(match.group(1))
        result["bytes_output"] = int(match.group(2))
    else:
        match = re.search(r"(\d+) packets output", raw)
        if match:
            result["output_packets"] = int(match.group(1))
    match = re.search(r"(\d+) runts, (\d+) giants", raw)
    if match:
        result["runts"] = int(match.group(1))
        result["giants"] = int(match.group(2))
    match = re.search(
        r"(\d+) input errors, (\d+) CRC, (\d+) frame, (\d+) overrun, (\d+) ignored",
        raw,
    )
    if match:
        result["input_errors"] = int(match.group(1))
        result["crc_errors"] = int(match.group(2))
        result["align_errors"] = int(match.group(3))
        result["overrun"] = int(match.group(4))
        result["ignored"] = int(match.group(5))
    else:
        match = re.search(r"(\d+) input errors, (\d+) CRC", raw)
        if match:
            result["input_errors"] = int(match.group(1))
            result["crc_errors"] = int(match.group(2))
    match = re.search(
        r"(\d+) output errors, (\d+) collisions, (\d+) interface resets", raw
    )
    if match:
        result["output_errors"] = int(match.group(1))
        result["collisions"] = int(match.group(2))
        result["interface_resets"] = int(match.group(3))
    match = re.search(r"(\d+) late collision", raw)
    if match:
        result["late_collisions"] = int(match.group(1))
    match = re.search(r"Input queue: \d+/\d+/(\d+)/\d+", raw)
    if match:
        result["discards_in"] = int(match.group(1))
    match = re.search(r"Total output drops: (\d+)", raw)
    if match:
        result["discards_out"] = int(match.group(1))
    match = re.search(
        r"(\d+) (?:minute|second) input rate \d+ bits/sec, (\d+) packets/sec", raw
    )
    if match:
        result["input_rate_pps"] = int(match.group(2))
    match = re.search(
        r"(\d+) (minute|second) output rate \d+ bits/sec, (\d+) packets/sec", raw
    )
    if match:
        result["output_rate_pps"] = int(match.group(3))
    match = re.search(r"(\d+) (minute|second)s? (?:input|output) rate", raw)
    if match:
        value, unit = int(match.group(1)), match.group(2)
        result["load_interval_seconds"] = value * 60 if unit == "minute" else value
    match = re.search(r"Last input ([^,\n]+),", raw)
    if match:
        token = match.group(1).strip()
        if token.lower() != "never":
            minutes = parse_duration_minutes(token)
            if minutes is not None:
                result["last_input_minutes"] = minutes
    result.update(parse_last_clearing(raw))
    return result


def _parse_transceiver_detail(raw: str, canonical: str) -> dict:
    from ..normalize import interface_matches_token

    result: dict = {}
    section: str | None = None
    for line in raw.splitlines():
        if "Transmit Power" in line:
            section = "dom_tx_power_dbm"
            continue
        if "Receive Power" in line:
            section = "dom_rx_power_dbm"
            continue
        if re.search(r"Temperature|Voltage|Current", line):
            if "Power" not in line:
                section = None
            continue
        tokens = line.split()
        if section and tokens and interface_matches_token(tokens[0], canonical):
            for token in tokens[1:]:
                try:
                    result[section] = float(token)
                    break
                except ValueError:
                    continue
    return result


def _parse_version(raw: str) -> dict:
    result: dict = {}
    match = re.search(r"Cisco IOS XE Software, Version\s+(\S+)", raw) or re.search(
        r"Version\s+([\w.():]+)", raw
    )
    if match:
        result["os_version"] = match.group(1).rstrip(",")
    match = re.search(r"Model Number\s+:\s+(\S+)", raw) or re.search(
        r"^cisco\s+(\S+)", raw, re.MULTILINE | re.IGNORECASE
    )
    if match:
        result["model"] = match.group(1)
    result.update(parse_uptime_minutes(raw))
    return result


class IosXeProfile(PlatformProfile):
    platform = Platform.IOS_XE
    netmiko_device_type = "cisco_xe"
    # `show interfaces` on IOS-XE never names the channel-group, so the
    # etherchannel summary is the only way to learn membership at all.
    reports_portchannel_membership = False
    templates = {
        "cpu": "show processes cpu | include CPU utilization",
        "version": "show version",
        "interface": "show interfaces {interface}",
        "counters": "show interfaces {interface} counters errors",
        "transceiver": "show interfaces {interface} transceiver detail",
        "neighbors": "show cdp neighbors {interface} detail",
        "portchannel": "show etherchannel summary",
        "logging": "show logging | include {interface}",
    }

    def parse(self, key: str, raw: str, canonical_interface: str) -> dict:
        if key == "cpu":
            return parse_cpu_five_seconds(raw)
        if key == "interface":
            return _parse_show_interfaces(raw)
        if key == "counters":
            return parse_counters_table(raw, canonical_interface, _COUNTER_COLUMNS)
        if key == "transceiver":
            return _parse_transceiver_detail(raw, canonical_interface)
        if key == "neighbors":
            return parse_cdp_neighbor_detail(raw)
        if key == "portchannel":
            return parse_portchannel_summary(raw)
        if key == "logging":
            return parse_flap_count(raw, canonical_interface)
        if key == "version":
            return _parse_version(raw)
        return {}


register(IosXeProfile())
