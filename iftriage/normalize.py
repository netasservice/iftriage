"""Interface-name normalization.

CSV short names (Gi3/0/20, Et4/15, Po214) must expand to each platform's
canonical form before being substituted into command templates. Unknown
prefixes raise — a wrong interface name would make shows fail silently.
"""

from __future__ import annotations

import re

from .models import Platform


class InterfaceNameError(ValueError):
    """Raised when an interface name cannot be safely normalized."""


# Numeric part of an interface name: digits with / and . separators
# (e.g. 3/0/20, 4/15.100, 214)
_NUMBER_RE = re.compile(r"^\d+(?:/\d+){0,3}(?:\.\d+)?$")
_NAME_RE = re.compile(r"^([A-Za-z][A-Za-z-]*)\s*([0-9][0-9/.]*)$")

# Canonical long names per platform, keyed by canonical lowercase.
# Short-name resolution: the alpha prefix must be a case-insensitive prefix of
# exactly one canonical name (longest-match on the prefix table below).
_CANONICAL: dict[Platform, list[str]] = {
    Platform.IOS_XE: [
        "GigabitEthernet",
        "TwoGigabitEthernet",
        "FiveGigabitEthernet",
        "TenGigabitEthernet",
        "TwentyFiveGigE",
        "FortyGigabitEthernet",
        "HundredGigE",
        "FastEthernet",
        "Port-channel",
        "Vlan",
        "Loopback",
        "AppGigabitEthernet",
    ],
    Platform.NXOS: [
        "Ethernet",
        "port-channel",
        "Vlan",
        "loopback",
        "mgmt",
    ],
    Platform.EOS: [
        "Ethernet",
        "Port-Channel",
        "Vlan",
        "Loopback",
        "Management",
    ],
}

# Common CSV/abbreviated prefixes mapped explicitly (checked before generic
# prefix matching, longest first). This disambiguates e.g. Tw vs Twe vs Two.
_SHORT_PREFIXES: dict[Platform, dict[str, str]] = {
    Platform.IOS_XE: {
        "twe": "TwentyFiveGigE",
        "two": "TwoGigabitEthernet",
        "tw": "TwoGigabitEthernet",
        "te": "TenGigabitEthernet",
        "fo": "FortyGigabitEthernet",
        "hu": "HundredGigE",
        "fi": "FiveGigabitEthernet",
        "gi": "GigabitEthernet",
        "fa": "FastEthernet",
        "po": "Port-channel",
        "vl": "Vlan",
        "lo": "Loopback",
        "ap": "AppGigabitEthernet",
    },
    Platform.NXOS: {
        "eth": "Ethernet",
        "et": "Ethernet",
        "po": "port-channel",
        "vl": "Vlan",
        "lo": "loopback",
        "mgmt": "mgmt",
        "ma": "mgmt",
    },
    Platform.EOS: {
        "eth": "Ethernet",
        "et": "Ethernet",
        "po": "Port-Channel",
        "vl": "Vlan",
        "lo": "Loopback",
        "ma": "Management",
    },
}


def expand_interface(platform: Platform, name: str) -> str:
    """Expand a short interface name to the platform's canonical form.

    Raises InterfaceNameError on anything that does not look like a valid,
    safely-substitutable interface name (fail closed).
    """
    name = (name or "").strip()
    match = _NAME_RE.match(name)
    if not match:
        raise InterfaceNameError(f"invalid interface name: {name!r}")
    prefix, number = match.group(1), match.group(2)
    if not _NUMBER_RE.match(number):
        raise InterfaceNameError(f"invalid interface number in {name!r}")

    prefix_lower = prefix.lower()

    # Exact canonical name already?
    for canonical in _CANONICAL[platform]:
        if prefix_lower == canonical.lower():
            return f"{canonical}{number}"

    # Known short prefix (exact match on the abbreviation table).
    shorts = _SHORT_PREFIXES[platform]
    if prefix_lower in shorts:
        return f"{shorts[prefix_lower]}{number}"

    # Generic: unique canonical name starting with the given prefix
    # (handles longer abbreviations like 'Gig', 'Ether', 'Hun').
    candidates = [
        name for name in _CANONICAL[platform] if name.lower().startswith(prefix_lower)
    ]
    if len(candidates) == 1:
        return f"{candidates[0]}{number}"

    raise InterfaceNameError(
        f"unknown interface prefix {prefix!r} for platform {platform.value} in {name!r}"
    )


def interface_matches_token(token: str, canonical: str) -> bool:
    """True when a table-row token (e.g. 'Gi3/0/20', 'Eth4/15') refers to
    the canonical interface name (e.g. 'GigabitEthernet3/0/20')."""
    tok = _NAME_RE.match(token.strip())
    can = _NAME_RE.match(canonical.strip())
    if not tok or not can:
        return False
    if tok.group(2) != can.group(2):
        return False
    tok_prefix = tok.group(1).lower().replace("-", "")
    can_prefix = can.group(1).lower().replace("-", "")
    return can_prefix.startswith(tok_prefix) or tok_prefix.startswith(can_prefix)
