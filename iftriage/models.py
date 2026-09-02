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
    """v2 vocabulary. PHYSICAL_MEDIA/LINK_NEGOTIATION/CONGESTION_BUFFER say
    what kind of fault is active; HISTORIC_NOT_ACTIVE says the lifetime
    counters are old news; INSUFFICIENT_DATA says the data parsed fine but
    cannot support a judgement (distinct from PARSE_ERROR, which is a failed
    parse, and UNVERIFIED, which is a failed collection — both fail-closed
    guarantees that predate v2 and stay untouched)."""

    PHYSICAL_MEDIA = "PHYSICAL_MEDIA"
    LINK_NEGOTIATION = "LINK_NEGOTIATION"
    CONGESTION_BUFFER = "CONGESTION_BUFFER"
    HISTORIC_NOT_ACTIVE = "HISTORIC_NOT_ACTIVE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    IGNORE = "IGNORE"
    UNVERIFIED = "UNVERIFIED"
    PARSE_ERROR = "PARSE_ERROR"


class Confidence(StrEnum):
    """How much a verdict may claim. Caps are hard limits applied by the
    rules layer (no second observation, stale poll, reconciliation residual,
    None among a rule's inputs), never suggestions."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SignalKind(StrEnum):
    """Closed vocabulary of evidence the engine can emit. Rules produce kinds
    plus named counter values — zero prose; the sentences live in the report
    templates, keyed on the kind, so a new report language is a new template
    file with no code change."""

    ZERO_TRAFFIC_ERRORS = "zero_traffic_errors"
    UNATTRIBUTED_RX_DOMINANT = "unattributed_rx_dominant"
    RUNTS_DOMINANT_NO_COLLISIONS = "runts_dominant_no_collisions"
    FCS_FRACTION_ACTIVE = "fcs_fraction_active"
    BUFFER_GROUP_DOMINANT = "buffer_group_dominant"
    DISCARDS_WITHOUT_CONGESTION_SIGNATURE = "discards_without_congestion_signature"
    LATE_COLLISIONS_FULL_DUPLEX = "late_collisions_full_duplex"
    GIANTS_WITH_MTU_MISMATCH = "giants_with_mtu_mismatch"
    SPEED_BELOW_CAPABILITY = "speed_below_capability"
    RELIABILITY_DEGRADED = "reliability_degraded"
    BYTES_PER_FRAME_ABOVE_MTU = "bytes_per_frame_above_mtu"
    DOM_RX_OUT_OF_RANGE = "dom_rx_out_of_range"
    ZERO_DELTA_NONZERO_LIFETIME = "zero_delta_nonzero_lifetime"
    LOW_FCS_DOES_NOT_CLEAR_MEDIA = "low_fcs_does_not_clear_media"
    INTERFACE_RESETS = "interface_resets"
    ERRORS_STOPPED_AFTER_CLEAR = "errors_stopped_after_clear"
    ERRORS_RESUMED = "errors_resumed"


class DataQualityKind(StrEnum):
    """Closed vocabulary of reasons the data itself limits the verdict."""

    RATIO_OUT_OF_RANGE = "ratio_out_of_range"
    COUNTER_RECONCILIATION_FAILED = "counter_reconciliation_failed"
    DELTA_SOURCE_DISAGREEMENT = "delta_source_disagreement"
    STALE_POLL_TIMESTAMP = "stale_poll_timestamp"
    INTERVAL_FROM_INGEST_TIME = "interval_from_ingest_time"
    NULL_RULE_INPUT = "null_rule_input"
    NO_SECOND_OBSERVATION = "no_second_observation"
    POLL_TIMEZONE_ASSUMED_UTC = "poll_timezone_assumed_utc"


# Report ordering: most actionable first.
VERDICT_ORDER = [
    VerdictCategory.PHYSICAL_MEDIA,
    VerdictCategory.LINK_NEGOTIATION,
    VerdictCategory.CONGESTION_BUFFER,
    VerdictCategory.PARSE_ERROR,
    VerdictCategory.UNVERIFIED,
    VerdictCategory.INSUFFICIENT_DATA,
    VerdictCategory.HISTORIC_NOT_ACTIVE,
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

    All counter fields are LIFETIME values: read from the device as-is, since
    the last counter clear. Deltas between two observations are computed by the
    rules layer from two of these snapshots; the two populations must never be
    mixed in a ratio.
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
    bytes_input: int | None = None
    bytes_output: int | None = None
    mtu: int | None = None
    # Free text from the device ("10/100/1000BaseTX", "10G"); remediation and
    # DOM expectations are derived from it, so a copper port is never told to
    # check a transceiver.
    media_type: str | None = None
    # Receive-error decomposition. `rcv_err` is the platform's aggregate
    # receive-error column (IOS-XE/NX-OS Rcv-Err) kept separate from
    # `input_errors` so the rules layer can reconcile the two and compute the
    # unattributed residual instead of trusting the total alone.
    runts: int | None = None
    giants: int | None = None
    undersize: int | None = None
    fcs_errors: int | None = None
    align_errors: int | None = None
    symbol_errors: int | None = None
    rcv_err: int | None = None
    overrun: int | None = None
    ignored: int | None = None
    no_buffer: int | None = None
    collisions: int | None = None
    output_errors: int | None = None
    interface_resets: int | None = None
    # Device-computed health/load averages ("reliability 132/255,
    # txload 1/255, rxload 6/255"). Reliability is the device's own
    # error-weighted exponential average: 255/255 is healthy, anything lower
    # is the device itself reporting degradation.
    reliability: int | None = None
    txload: int | None = None
    rxload: int | None = None
    # Device-reported load-interval rates. The interval length matters as much
    # as the value ("30 seconds" vs "5 minute"), so it travels alongside.
    input_rate_pps: int | None = None
    output_rate_pps: int | None = None
    load_interval_seconds: int | None = None
    # Counter epoch. `counters_never_cleared` is True for the literal `never`;
    # `last_clearing_minutes` carries a parsed age otherwise. Both None means
    # the line was not seen — distinct from a known "never".
    last_clearing_minutes: float | None = None
    counters_never_cleared: bool | None = None
    last_input_minutes: float | None = None
    # Device uptime from `show version` — the device-side time anchor used to
    # bound lifetime counters without any extra command.
    uptime_minutes: float | None = None
    dom_rx_power_dbm: float | None = None
    dom_tx_power_dbm: float | None = None
    neighbor_name: str | None = None
    neighbor_port: str | None = None
    neighbor_duplex: str | None = None
    # CDP "Platform:" string ("Cisco IP Phone 8841", "cisco C9500-32C") —
    # remediation language depends on WHAT is at the far end: a managed
    # phone's duplex is fixed in the call manager, not at the jack.
    neighbor_platform: str | None = None
    # NX-OS vPC membership ("vPC Status: Up, vPC number: 214"): a healthy
    # peer leg means member-level remediation can be hitless.
    vpc_status: str | None = None
    vpc_number: int | None = None
    port_channel_members: dict[str, list[str]] | None = (
        None  # Po name -> member interfaces
    )
    # Parent port-channel as the device names it, when `show interfaces` says
    # so (EOS "Member of Port-Channel195", NX-OS "Belongs to Po21"). Optional:
    # its absence only means "not known from this output", never an error.
    member_of_portchannel: str | None = None
    flap_count: int | None = None
    # Corroborative only (e.g. %CDP-4-DUPLEX_MISMATCH in logging); never a
    # required field, so its absence cannot cause PARSE_ERROR.
    duplex_mismatch_logged: bool | None = None
    model: str | None = None
    os_version: str | None = None
    collected_at: datetime | None = None


@dataclass(frozen=True)
class Signal:
    """One piece of evidence: a kind, its weight, and the NAMED counter
    values that produced it. `contradicts=True` marks evidence that points
    away from the chosen verdict — rendered under "Evidence against" with the
    reason it did not change the outcome, never silently dropped."""

    kind: SignalKind
    weight: Confidence
    values: dict[str, int | float | str] = field(default_factory=dict)
    supports: VerdictCategory | None = None
    contradicts: bool = False


@dataclass(frozen=True)
class DataQualityFlag:
    kind: DataQualityKind
    values: dict[str, int | float | str] = field(default_factory=dict)


@dataclass(frozen=True)
class VerdictMetrics:
    """The numbers the report prints next to a verdict, with their
    provenance. Both delta sources appear labeled; the interval always names
    where its length came from."""

    errors_per_second: float | None = None
    errors_per_hour: float | None = None
    error_ratio: float | None = None  # only ever a value inside [0, 1]
    ratio_basis: str | None = None  # the denominator population, for the label
    delta_tool: int | None = None  # the CSV-flagged counter, run-to-run
    delta_csv: int | None = None  # the CSV `change` column, as supplied
    interval_minutes: float | None = None
    interval_source: str | None = None
    staleness_minutes: float | None = None


@dataclass
class Verdict:
    category: VerdictCategory
    reason: str  # one-line justification in decision language
    details: list[str] = field(default_factory=list)
    # Port-channel cases only: one-line finding per member interface.
    member_findings: dict[str, str] = field(default_factory=dict)
    # v2 engine fields; all default so existing constructor calls stay valid.
    confidence: Confidence | None = None
    signals: list[Signal] = field(default_factory=list)
    data_quality: list[DataQualityFlag] = field(default_factory=list)
    metrics: VerdictMetrics | None = None
    # One line of falsifiability: the observation that would flip the
    # verdict, as a signal kind plus named values (prose lives in templates).
    what_would_change: Signal | None = None


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
    # The EARLIER sample, taken by a previous run and read back from history.
    # The delta runs baseline_stats -> stats, never the other way around.
    baseline_stats: NormalizedInterfaceStats | None = None
    baseline_minutes: float | None = None  # elapsed between the two samples
    baseline_taken_at: datetime | None = None
    baseline_run_id: int | None = None
    raw_outputs: dict[str, str] = field(default_factory=dict)
    collection_error: str | None = None  # unreachable / auth failed / timeout / aborted
    # Why this case has no delta: nothing stored, too recent, too old, or the
    # stored sample was discarded. Reported per case so an un-compared
    # interface can never be mistaken for a compared one.
    baseline_note: str | None = None
    parse_errors: list[str] = field(default_factory=list)
    # Set when the case interface is itself a member of a port-channel; then
    # member_stats holds its sibling members as context, not the case's own
    # members, and the verdict stays about the reported interface.
    parent_portchannel: str | None = None
    # Port-channel cases: per-member samples keyed by canonical member name,
    # and the reason any discovered member has no sample (fail closed).
    member_stats: dict[str, NormalizedInterfaceStats] = field(default_factory=dict)
    member_baseline_stats: dict[str, NormalizedInterfaceStats] = field(
        default_factory=dict
    )
    member_errors: dict[str, str] = field(default_factory=dict)
    verdict: Verdict | None = None
    duplicate_of: str | None = None  # set when this is a member of a Po also in the CSV
    recurrence: int = 0  # prior runs in which this switch+interface appeared
