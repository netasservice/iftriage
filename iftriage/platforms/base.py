"""PlatformProfile ABC + registry.

Each profile declares its command templates (the closed allow-list is derived
from these), prompt expectations (delegated to Netmiko device_type), and a
parser per command key. Parsers map raw output to canonical
NormalizedInterfaceStats field names; rules.py never sees platform specifics.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from ..models import Platform
from ..normalize import (
    expand_interface,
    interface_matches_token,
    line_references_interface,
)

# Canonical command keys, in collection order. Profiles may omit keys.
# "neighbors_lldp" comes before "neighbors" so that when a platform runs both
# (NX-OS: LLDP fallback for non-Cisco neighbors), CDP data wins the merge
# whenever it found an entry. Two template keys are deliberately absent:
# "cpu" feeds the pre-collection CPU guard, not the per-interface stats, and
# "portchannel" is conditional (see PORTCHANNEL_KEY).
COMMAND_KEYS = (
    "version",
    "interface",
    "counters",
    "transceiver",
    "neighbors_lldp",
    "neighbors",
    "logging",
)

# Per-device commands (not per-interface): run once per device.
DEVICE_LEVEL_KEYS = ("version",)

# The port-channel summary is device-level AND conditional: it is sent only
# when a case on the device is a port-channel or a member of one, so it is
# driven by its own collector step rather than by the per-interface key loop.
PORTCHANNEL_KEY = "portchannel"

# Commands run for each discovered port-channel member: the full per-interface
# set. Device-level keys are excluded — already collected once per device.
MEMBER_KEYS = tuple(key for key in COMMAND_KEYS if key not in DEVICE_LEVEL_KEYS)

_REGISTRY: dict[Platform, PlatformProfile] = {}


def register(profile: PlatformProfile) -> PlatformProfile:
    _REGISTRY[profile.platform] = profile
    return profile


def get_profile(platform: Platform) -> PlatformProfile:
    return _REGISTRY[platform]


class PlatformProfile(ABC):
    platform: Platform
    netmiko_device_type: str
    # command key -> template with {interface} placeholder
    templates: dict[str, str]
    # True when `show interfaces` names the parent port-channel, so the
    # port-channel summary can be deferred until a case proves it relevant.
    # False (IOS-XE) means that summary is the only source of membership at
    # all, so it must be sent unconditionally.
    reports_portchannel_membership: bool = True

    def canonical_interface(self, name: str) -> str:
        return expand_interface(self.platform, name)

    def render_commands(self, canonical: str) -> dict[str, str]:
        """Render the full command set for one (already canonical) interface."""
        return {
            key: template.format(interface=canonical)
            for key, template in self.templates.items()
        }

    def allowed_commands(
        self,
        canonical_interfaces: list[str],
        keys: tuple[str, ...] | None = None,
    ) -> frozenset[str]:
        """The closed allow-list for a device, given its target interfaces.

        With `keys`, only those template keys are rendered, so a session built
        for a narrower pass allows exactly the commands it will send.
        """
        allowed: set[str] = set()
        for intf in canonical_interfaces:
            for key, command in self.render_commands(intf).items():
                if keys is None or key in keys:
                    allowed.add(command)
        return frozenset(allowed)

    @abstractmethod
    def parse(self, key: str, raw: str, canonical_interface: str) -> dict:
        """Parse one command's raw output into canonical stat fields.

        Returns a (possibly empty) dict of NormalizedInterfaceStats field
        names. Raises on structurally broken output; missing fields are
        simply absent (fail-closed handling happens in rules.py).
        """


# ---------------------------------------------------------------------------
# Shared parsing helpers
# ---------------------------------------------------------------------------


def _to_int(token: str) -> int | None:
    token = token.strip().replace(",", "")
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    return None


def parse_counters_table(
    raw: str, canonical_interface: str, column_map: dict[str, str | tuple[str, ...]]
) -> dict:
    """Parse whitespace-aligned counters tables (one or more blocks).

    column_map: lowercase header token -> canonical field name, or a tuple of
    them when one device column feeds several canonical fields (IOS-XE Rcv-Err
    is both the merged `input_errors` and the standalone `rcv_err`).
    Finds the row whose first token refers to the target interface.
    """
    result: dict = {}
    lines = raw.splitlines()
    header: list[str] | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", " "}:
            continue
        tokens = stripped.split()
        first = tokens[0]
        if first.lower() == "port" or (
            header is None
            and not interface_matches_token(first, canonical_interface)
            and any(t.lower() in column_map for t in tokens)
        ):
            header = tokens[1:] if first.lower() == "port" else tokens
            continue
        if header and interface_matches_token(first, canonical_interface):
            values = tokens[1:]
            for name, value in zip(header, values, strict=False):
                mapped = column_map.get(name.lower())
                if mapped:
                    parsed = _to_int(value)
                    if parsed is not None:
                        targets = (mapped,) if isinstance(mapped, str) else mapped
                        for field in targets:
                            result[field] = parsed
            header = None  # next block needs its own header
    return result


# Duration spellings across the three platforms: "41 weeks, 3 days, 2 hours,
# 11 minutes" (IOS-XE), "291 day(s), 4 hour(s), ..." (NX-OS), "41 weeks,
# 3 days, 2 hours and 11 minutes" (EOS).
_DURATION_UNIT_RE = re.compile(
    r"(\d+)\s*(year|week|day|hour|minute|second)", re.IGNORECASE
)
_DURATION_MINUTES = {
    "year": 365 * 24 * 60,
    "week": 7 * 24 * 60,
    "day": 24 * 60,
    "hour": 60,
    "minute": 1,
    "second": 1 / 60,
}
# Compact IOS tokens: "00:03:22" (H:MM:SS), "1d02h", "2w3d", "3y22w".
_DURATION_HMS_RE = re.compile(r"^(\d+):(\d\d):(\d\d)$")
_DURATION_COMPACT_RE = re.compile(r"(\d+)([ywdhms])")
_COMPACT_MINUTES = {
    "y": 365 * 24 * 60,
    "w": 7 * 24 * 60,
    "d": 24 * 60,
    "h": 60,
    "m": 1,
    "s": 1 / 60,
}


def parse_duration_minutes(token: str) -> float | None:
    """Parse a device-printed duration into minutes, None when unrecognized.

    Handles both the worded form ("2 hours, 11 minutes") and the compact IOS
    timestamp forms ("00:03:22", "1d02h", "2w3d"). "never" is NOT a duration;
    callers handle it explicitly.
    """
    token = token.strip().rstrip(".,")
    if not token:
        return None
    match = _DURATION_HMS_RE.match(token)
    if match:
        hours, minutes, seconds = (int(group) for group in match.groups())
        return hours * 60 + minutes + seconds / 60
    units = _DURATION_UNIT_RE.findall(token)
    if units:
        return sum(
            int(value) * _DURATION_MINUTES[unit.lower()] for value, unit in units
        )
    compact = _DURATION_COMPACT_RE.findall(token)
    if compact and re.fullmatch(r"(?:\d+[ywdhms])+", token):
        return sum(int(value) * _COMPACT_MINUTES[unit] for value, unit in compact)
    return None


_LAST_CLEARING_RE = re.compile(
    r"Last clearing of \"show interface\" counters\s+(\S.*)$", re.MULTILINE
)


def parse_last_clearing(raw: str) -> dict:
    """The counter epoch line, shared verbatim by all three platforms.

    "never" and a parsed age are distinct facts; a missing line yields {} so
    both fields stay None (unknown), never a fake "never".
    """
    match = _LAST_CLEARING_RE.search(raw)
    if not match:
        return {}
    token = match.group(1).strip()
    if token.lower() == "never":
        return {"counters_never_cleared": True}
    minutes = parse_duration_minutes(token)
    if minutes is None:
        return {}
    return {"counters_never_cleared": False, "last_clearing_minutes": minutes}


_UPTIME_LINE_RE = re.compile(r"^.*uptime\s+is\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_UPTIME_COLON_RE = re.compile(r"^Uptime:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def parse_uptime_minutes(raw: str) -> dict:
    """Device uptime from `show version` output, as {'uptime_minutes': float}.

    Matches "<host> uptime is ..." (IOS-XE), "Kernel uptime is ..." (NX-OS)
    and "Uptime: ..." (EOS). Returns {} when no uptime line parses.
    """
    match = _UPTIME_LINE_RE.search(raw) or _UPTIME_COLON_RE.search(raw)
    if not match:
        return {}
    minutes = parse_duration_minutes(match.group(1))
    if minutes is None:
        return {}
    return {"uptime_minutes": minutes}


# Member/flag tokens like Gi3/0/20(P), Eth4/15(P), Et3/1/1(PG+), Po21(SU).
# The flag class must accept EOS dense flags (+, ^, *).
_PC_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z-]*\d+(?:/\d+)*)\(([\w+^*-]+)\)")


def parse_portchannel_summary(raw: str) -> dict:
    """Map port-channel names to member interfaces.

    Handles the token style shared by IOS-XE/NX-OS/EOS summaries
    (Po214(SU) ... Gi3/0/20(P)) and the EOS 'Active Ports:' style.
    """
    members: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw.splitlines():
        header = re.match(r"\s*Port Channel (\S+?):", line)
        if header:
            current = header.group(1)
            members.setdefault(current, [])
            continue
        active = re.match(r"\s*Active Ports:\s*(.+)", line)
        if active and current:
            members[current].extend(active.group(1).split())
            continue
        for name, _flags in _PC_TOKEN_RE.findall(line):
            if name.lower().startswith(("po", "port-channel")):
                current = name
                members.setdefault(current, [])
            elif current is not None:
                members[current].append(name)
    if not members:
        return {}
    return {"port_channel_members": members}


_CPU_FIVE_SECONDS_RE = re.compile(
    r"CPU utilization for five seconds:\s*(\d+(?:\.\d+)?)%"
)
_CPU_IDLE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%?\s*id(?:le)?\b")


def parse_cpu_five_seconds(raw: str) -> dict:
    """IOS-style current CPU: 'CPU utilization for five seconds: 12%/4%; ...'.

    Returns {} when the line is absent — the CPU guard fails closed on that.
    """
    match = _CPU_FIVE_SECONDS_RE.search(raw)
    if match:
        return {"cpu_percent": float(match.group(1))}
    return {}


def parse_cpu_from_idle(raw: str) -> dict:
    """Idle-based current CPU (NX-OS 'CPU states: ... 94.2% idle', EOS
    top-style '%Cpu(s): ... 92.1 id'): utilization is 100 minus idle."""
    match = _CPU_IDLE_RE.search(raw)
    if match:
        return {"cpu_percent": round(100.0 - float(match.group(1)), 1)}
    return {}


def parse_cdp_neighbor_detail(raw: str) -> dict:
    """Extract neighbor identity from CDP/LLDP detail output."""
    result: dict = {}
    match = re.search(r"Device ID:\s*(\S+)", raw) or re.search(
        r'System Name:\s*"?([^"\n]+)"?', raw
    )
    if match:
        result["neighbor_name"] = match.group(1).strip()
    # CDP port ids can contain spaces ("Port 1" on IP phones); NX-OS LLDP
    # prints "Port id:" in lowercase.
    match = re.search(r"Port ID \(outgoing port\):\s*([^\n]+)", raw) or re.search(
        r'Port [Ii][Dd]\s*:\s*"?([^"\n]+)"?', raw
    )
    if match:
        result["neighbor_port"] = match.group(1).strip().strip('"')
    match = re.search(r"Duplex(?: Mode)?:\s*(\S+)", raw, re.IGNORECASE)
    if match:
        result["neighbor_duplex"] = match.group(1).strip().lower()
    return result


def parse_flap_count(raw: str, canonical_interface: str) -> dict:
    """Count link up/down transitions in filtered logging output, and flag
    logged duplex-mismatch events (%CDP-4-DUPLEX_MISMATCH).

    Every line is re-scoped to the interface under analysis: the device-side
    `| include <name>` filter matches substrings, so output collected for
    GigabitEthernet3/0/2 also carries GigabitEthernet3/0/20 events, and a
    neighbouring port's mismatch must never corroborate this port's verdict.
    """
    count = 0
    mismatch_logged = False
    for line in raw.splitlines():
        if not line_references_interface(line, canonical_interface):
            continue
        if re.search(r"(UPDOWN|changed state to|LINEPROTO|IF_DOWN|IF_UP)", line):
            count += 1
        if "DUPLEX_MISMATCH" in line:
            mismatch_logged = True
    return {"flap_count": count, "duplex_mismatch_logged": mismatch_logged}
