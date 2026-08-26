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
from ..normalize import expand_interface, interface_matches_token

# Canonical command keys, in collection order.
COMMAND_KEYS = (
    "version",
    "interface",
    "counters",
    "transceiver",
    "neighbors",
    "portchannel",
    "logging",
)

# Commands re-run during the optional re-poll pass.
REPOLL_KEYS = ("interface", "counters")

# Per-device commands (not per-interface): run once per device.
DEVICE_LEVEL_KEYS = ("version", "portchannel")

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

    def canonical_interface(self, name: str) -> str:
        return expand_interface(self.platform, name)

    def render_commands(self, canonical: str) -> dict[str, str]:
        """Render the full command set for one (already canonical) interface."""
        return {
            key: template.format(interface=canonical)
            for key, template in self.templates.items()
        }

    def allowed_commands(self, canonical_interfaces: list[str]) -> frozenset[str]:
        """The closed allow-list for a device, given its target interfaces."""
        allowed: set[str] = set()
        for intf in canonical_interfaces:
            allowed.update(self.render_commands(intf).values())
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
    raw: str, canonical_interface: str, column_map: dict[str, str]
) -> dict:
    """Parse whitespace-aligned counters tables (one or more blocks).

    column_map: lowercase header token -> canonical field name.
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
                field = column_map.get(name.lower())
                if field:
                    parsed = _to_int(value)
                    if parsed is not None:
                        result[field] = parsed
            header = None  # next block needs its own header
    return result


_PC_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z-]*\d+(?:/\d+)*)\(([\w-]+)\)")


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


def parse_cdp_neighbor_detail(raw: str) -> dict:
    """Extract neighbor identity from CDP/LLDP detail output."""
    result: dict = {}
    m = re.search(r"Device ID:\s*(\S+)", raw) or re.search(
        r'System Name:\s*"?([^"\n]+)"?', raw
    )
    if m:
        result["neighbor_name"] = m.group(1).strip()
    m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", raw) or re.search(
        r'Port ID\s*:\s*"?([^"\n]+)"?', raw
    )
    if m:
        result["neighbor_port"] = m.group(1).strip()
    m = re.search(r"Duplex(?: Mode)?:\s*(\S+)", raw, re.IGNORECASE)
    if m:
        result["neighbor_duplex"] = m.group(1).strip().lower()
    return result


def parse_flap_count(raw: str) -> dict:
    """Count link up/down transitions in filtered logging output."""
    if not raw.strip():
        return {"flap_count": 0}
    count = 0
    for line in raw.splitlines():
        if re.search(r"(UPDOWN|changed state to|LINEPROTO|IF_DOWN|IF_UP)", line):
            count += 1
    return {"flap_count": count}
