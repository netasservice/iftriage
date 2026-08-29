"""Core dataclasses shared across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Platform(StrEnum):
    IOS_XE = "ios_xe"
    NXOS = "nxos"
    EOS = "eos"


class VerdictCategory(StrEnum):
    PHYSICAL_MEDIA = "PHYSICAL_MEDIA"
    CONFIG_ISSUE = "CONFIG_ISSUE"
    CAPACITY = "CAPACITY"
    IGNORE = "IGNORE"
    UNVERIFIED = "UNVERIFIED"
    PARSE_ERROR = "PARSE_ERROR"


# Report ordering: most actionable first.
VERDICT_ORDER = [
    VerdictCategory.PHYSICAL_MEDIA,
    VerdictCategory.CONFIG_ISSUE,
    VerdictCategory.CAPACITY,
    VerdictCategory.PARSE_ERROR,
    VerdictCategory.UNVERIFIED,
    VerdictCategory.IGNORE,
]


@dataclass(frozen=True)
class Credentials:
    """Device credentials. Never logged, never persisted."""

    username: str
    password: str
    enable_secret: str | None = None

    def __repr__(self) -> str:  # defensive: keep secrets out of tracebacks/logs
        return (
            f"Credentials(username={self.username!r}, "
            "password=<hidden>, enable_secret=<hidden>)"
        )


@dataclass
class InterfaceCase:
    """One row of the Splunk top-N CSV."""

    poll_time: str
    switch: str
    mgmt_ip: str
    interface: str
    description: str
    status: str
    protocol: str
    counter: str
    prev_count: int | None
    count: int | None
    change: int | None
    row_index: int
    dq_flags: list[str] = field(default_factory=list)
    excluded: bool = False  # excluded from live analysis (data-quality artifact)
    # Verbatim echo of the input row for the enriched CSV report, keyed in the
    # original header order — including columns this model does not parse.
    raw_row: dict[str, str] = field(default_factory=dict)


@dataclass
class NormalizedInterfaceStats:
    """Canonical, platform-independent view of one interface.

    Every field is Optional; None means "unknown / not parsed" and is treated
    fail-closed by the rules engine — it is never coerced to zero.
    """

    link_status: str | None = None  # "up" / "down" / ...
    protocol_status: str | None = None
    duplex: str | None = None  # "full" / "half" / "auto"
    speed: str | None = None
    input_packets: int | None = None
    output_packets: int | None = None
    input_errors: int | None = None
    crc_errors: int | None = None
    late_collisions: int | None = None
    discards_in: int | None = None
    discards_out: int | None = None
    dom_rx_power_dbm: float | None = None
    dom_tx_power_dbm: float | None = None
    neighbor_name: str | None = None
    neighbor_port: str | None = None
    neighbor_duplex: str | None = None
    port_channel_members: dict[str, list[str]] | None = (
        None  # Po name -> member interfaces
    )
    flap_count: int | None = None
    # Corroborative only (e.g. %CDP-4-DUPLEX_MISMATCH in logging); never a
    # required field, so its absence cannot cause PARSE_ERROR.
    duplex_mismatch_logged: bool | None = None
    model: str | None = None
    os_version: str | None = None
    collected_at: datetime | None = None


@dataclass
class Verdict:
    category: VerdictCategory
    reason: str  # one-line justification in decision language
    details: list[str] = field(default_factory=list)


@dataclass
class DataQualityFinding:
    kind: str  # e.g. "cross_device_identical", "negative_delta", ...
    detail: str
    rows: list[int] = field(default_factory=list)


@dataclass
class CaseResult:
    case: InterfaceCase
    platform: Platform | None = None
    canonical_interface: str | None = None
    stats: NormalizedInterfaceStats | None = None
    repoll_stats: NormalizedInterfaceStats | None = None
    repoll_minutes: float | None = None
    raw_outputs: dict[str, str] = field(default_factory=dict)
    collection_error: str | None = None  # unreachable / auth failed / timeout / aborted
    # Set when the re-poll pass deliberately left the device alone (CPU guard);
    # the first sample stays valid, only the delta answer is missing.
    repoll_skip_reason: str | None = None
    parse_errors: list[str] = field(default_factory=list)
    verdict: Verdict | None = None
    duplicate_of: str | None = None  # set when this is a member of a Po also in the CSV
    recurrence: int = 0  # prior runs in which this switch+interface appeared
