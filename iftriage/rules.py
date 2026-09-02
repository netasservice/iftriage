"""Verdict engine — pure functions, no I/O.

Consumes ONLY the canonical NormalizedInterfaceStats model; never knows the
platform. Fail-closed rule: a failed parse or missing critical field NEVER
yields a clean verdict — missing data => PARSE_ERROR / UNVERIFIED, always.

v2 engine: classification is driven by WHICH error bucket is incrementing,
never by the total alone, and every verdict carries a confidence level plus
typed evidence signals (enum kinds + named counter values, zero prose — the
sentences live in the report templates). Population discipline (lifetime vs
tool-delta vs CSV-delta) is enforced by `metrics.py`; interval provenance by
`timebase.py`. Confidence caps are hard limits: no second observation, a
stale poll, an unbalanced reconciliation, or a None among a fired rule's
inputs each cap what the verdict may claim.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from enum import Enum

from .config import Thresholds
from .metrics import (
    DeltaWindow,
    LifetimeView,
    RatioResult,
    buffer_group_delta,
    bytes_per_frame,
    bytes_per_frame_exceeds_mtu,
    compute_delta_window,
    delta_sources_disagree,
    reconcile_input_errors,
    unattributed_rx,
    zero_traffic_test,
)
from .models import (
    VERDICT_ORDER,
    Confidence,
    DataQualityFlag,
    DataQualityKind,
    InterfaceCase,
    NormalizedInterfaceStats,
    Signal,
    SignalKind,
    Verdict,
    VerdictCategory,
    VerdictMetrics,
)
from .timebase import (
    STALENESS_HEADLINE_MINUTES as _STALE_HEADLINE_MINUTES,
)
from .timebase import (
    IntervalEstimate,
    IntervalSource,
    lifetime_window,
    observation_window,
    parse_poll_time,
    staleness_minutes,
)

# Spec-fixed semantics, not operator tunables: these constants define what
# the verdicts MEAN. The operator-facing floors stay in config.yaml.
DOMINANT_SHARE = 0.5  # a bucket "dominates" above half of the error total
FCS_FRACTION_MIN = 0.10  # FCS share that reads as marginal-signal corruption
FCS_NEGLIGIBLE_FRACTION = 0.01  # below this, FCS neither confirms nor clears
RECONCILIATION_LOW_CAP_FRACTION = 0.01  # residual above 1% caps LOW

_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

# The falsifiability line for HISTORIC_NOT_ACTIVE: movement on a future run
# reopens the case and the ladder reclassifies it.
_WHAT_HISTORIC = Signal(kind=SignalKind.ERRORS_RESUMED, weight=Confidence.HIGH)


class CounterClass(Enum):
    LATE_COLLISIONS = "late_collisions"
    RECEIVE_ERRORS = "receive_errors"
    IN_DISCARDS = "in_discards"
    OUT_DISCARDS = "out_discards"
    TOTAL_TRAFFIC = "total_traffic"
    GENERIC_ERRORS = "generic_errors"


def classify_counter(name: str) -> CounterClass:
    key = (name or "").lower().replace("-", "").replace("_", "").replace(" ", "")
    if key in {"latecol", "latecollision", "latecollisions"}:
        return CounterClass.LATE_COLLISIONS
    if key in {
        "rcverr",
        "rcverrors",
        "crc",
        "fcserr",
        "fcs",
        "inerrors",
        "inputerrors",
        "alignerr",
        "symbolerr",
    }:
        return CounterClass.RECEIVE_ERRORS
    if key in {"indiscards", "inputdiscards", "indiscard"}:
        return CounterClass.IN_DISCARDS
    if key in {"outdiscards", "outputdiscards", "outdiscard"}:
        return CounterClass.OUT_DISCARDS
    if key in {
        "rx",
        "tx",
        "inoctets",
        "outoctets",
        "inucastpkts",
        "outucastpkts",
        "rxtotal",
        "txtotal",
    }:
        return CounterClass.TOTAL_TRAFFIC
    return CounterClass.GENERIC_ERRORS


# Critical fields per counter class: any None among these => PARSE_ERROR.
_REQUIRED_FIELDS: dict[CounterClass, tuple[str, ...]] = {
    CounterClass.LATE_COLLISIONS: ("late_collisions", "duplex", "link_status"),
    CounterClass.RECEIVE_ERRORS: (
        "input_errors",
        "crc_errors",
        "input_packets",
        "link_status",
    ),
    CounterClass.IN_DISCARDS: ("discards_in", "input_packets", "link_status"),
    CounterClass.OUT_DISCARDS: ("discards_out", "input_packets", "link_status"),
    CounterClass.TOTAL_TRAFFIC: (),
    CounterClass.GENERIC_ERRORS: ("input_errors", "input_packets", "link_status"),
}

# Which stats field carries the counter value for each class.
_VALUE_FIELD: dict[CounterClass, str] = {
    CounterClass.LATE_COLLISIONS: "late_collisions",
    CounterClass.RECEIVE_ERRORS: "input_errors",
    CounterClass.IN_DISCARDS: "discards_in",
    CounterClass.OUT_DISCARDS: "discards_out",
    CounterClass.TOTAL_TRAFFIC: "input_packets",
    CounterClass.GENERIC_ERRORS: "input_errors",
}


def _fmt_threshold(percent: float) -> str:
    """The configured floor, without the trailing zeros of a fixed format."""
    return f"{percent:g}%"


def format_window(minutes: float | None) -> str:
    """A comparison window in the largest unit that stays readable.

    Returns only digits and a unit symbol, so report language stays in the
    templates.
    """
    if minutes is None:
        return "?"
    if minutes < 90:
        return f"{minutes:.0f} min"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} h"
    return f"{hours / 24:.1f} d"


def _cap(confidence: Confidence, ceiling: Confidence) -> Confidence:
    if _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[ceiling]:
        return ceiling
    return confidence


def apply_caps(confidence: Confidence, flags: Sequence[DataQualityFlag]) -> Confidence:
    """Hard confidence ceilings from data-quality conditions. Applied after
    the verdict is chosen; each cap's flag is already in the verdict, so the
    report can explain why confidence is what it is.

    Only conditions that limited the EVIDENCE cap the verdict: a single
    observation, an unknown rule input, an unbalanced reconciliation. A stale
    CSV poll or a host-side interval label stay headline data-quality items —
    verdicts here rest on the tool's own two observations, which the CSV's
    age does not touch, and the tool's collection interval is measured (by
    the host's clock) rather than inferred.
    """
    for flag in flags:
        if flag.kind is DataQualityKind.COUNTER_RECONCILIATION_FAILED:
            fraction = flag.values.get("residual_fraction", 0)
            if isinstance(fraction, int | float) and (
                fraction > RECONCILIATION_LOW_CAP_FRACTION
            ):
                confidence = _cap(confidence, Confidence.LOW)
            else:
                confidence = _cap(confidence, Confidence.MEDIUM)
        elif flag.kind in (
            DataQualityKind.NO_SECOND_OBSERVATION,
            DataQualityKind.NULL_RULE_INPUT,
        ):
            confidence = _cap(confidence, Confidence.MEDIUM)
    return confidence


def _share(part: int | None, whole: int | None) -> float | None:
    if part is None or whole is None or whole <= 0:
        return None
    return part / whole


def _speed_below_capability(stats: NormalizedInterfaceStats) -> bool:
    """100M negotiated on a gigabit-capable copper port. Real signal (cable
    pair damage forces the fallback) but equally consistent with a genuinely
    100M endpoint — corroborating only, never a verdict on its own."""
    speed = (stats.speed or "").replace(" ", "").lower()
    media = (stats.media_type or "").lower()
    return bool(
        re.match(r"100mb?", speed)
        and not speed.startswith("1000")
        and "1000base" in media
    )


def _corroborating_signals(stats: NormalizedInterfaceStats) -> list[Signal]:
    signals: list[Signal] = []
    if _speed_below_capability(stats):
        signals.append(
            Signal(
                kind=SignalKind.SPEED_BELOW_CAPABILITY,
                weight=Confidence.LOW,
                values={
                    "speed": stats.speed or "?",
                    "media_type": stats.media_type or "?",
                },
                supports=VerdictCategory.PHYSICAL_MEDIA,
            )
        )
    if bytes_per_frame_exceeds_mtu(stats):
        average = bytes_per_frame(stats)
        signals.append(
            Signal(
                kind=SignalKind.BYTES_PER_FRAME_ABOVE_MTU,
                weight=Confidence.LOW,
                values={
                    "bytes_per_frame": round(average or 0),
                    "mtu": stats.mtu or 0,
                    "bytes_input": stats.bytes_input or 0,
                    "input_packets": stats.input_packets or 0,
                },
                supports=VerdictCategory.PHYSICAL_MEDIA,
            )
        )
    if stats.interface_resets:
        signals.append(
            Signal(
                kind=SignalKind.INTERFACE_RESETS,
                weight=Confidence.LOW,
                values={"interface_resets": stats.interface_resets},
                supports=VerdictCategory.PHYSICAL_MEDIA,
            )
        )
    return signals


def _fcs_contradiction(stats: NormalizedInterfaceStats) -> Signal | None:
    """A near-zero FCS count on a port drowning in receive errors. It points
    away from the media verdict at first sight, but does not clear it: symbol
    corruption and short frames are discarded before the FCS check, so severe
    link damage can present with near-zero FCS. Rendered under "Evidence
    against" with that explanation."""
    fcs = stats.fcs_errors if stats.fcs_errors is not None else stats.crc_errors
    fraction = _share(fcs, stats.input_errors)
    if fcs is None or fraction is None or fraction >= FCS_NEGLIGIBLE_FRACTION:
        return None
    return Signal(
        kind=SignalKind.LOW_FCS_DOES_NOT_CLEAR_MEDIA,
        weight=Confidence.LOW,
        values={"fcs_errors": fcs, "input_errors": stats.input_errors or 0},
        contradicts=True,
    )


def _build_metrics(
    window: DeltaWindow | None,
    value_delta: int | None,
    csv_change: int | None,
    ratio: RatioResult | None,
    stale_minutes: float | None,
) -> VerdictMetrics:
    interval = window.interval if window is not None else None
    return VerdictMetrics(
        errors_per_second=window.errors_per_second() if window else None,
        errors_per_hour=window.errors_per_hour() if window else None,
        error_ratio=ratio.value if ratio else None,
        delta_tool=value_delta,
        delta_csv=csv_change,
        interval_minutes=interval.minutes if interval else None,
        interval_source=interval.source.value if interval else None,
        staleness_minutes=stale_minutes,
    )


def evaluate_case(
    case: InterfaceCase,
    stats: NormalizedInterfaceStats | None,
    baseline_stats: NormalizedInterfaceStats | None,
    baseline_minutes: float | None,
    thresholds: Thresholds,
    collection_error: str | None = None,
    parse_errors: Sequence[str] = (),
    member_stats: dict[str, NormalizedInterfaceStats] | None = None,
    member_baseline_stats: dict[str, NormalizedInterfaceStats] | None = None,
    member_errors: dict[str, str] | None = None,
    parent_portchannel: str | None = None,
    report_time: datetime | None = None,
) -> Verdict:
    """Produce the verdict for one case. Pure function.

    A port-channel with sampled members is judged member by member. A case that
    is itself a member of a bundle (parent_portchannel set) keeps its own
    single-interface verdict and carries its siblings as context. Every other
    case takes the plain single-interface path.
    """

    if collection_error:
        return Verdict(
            VerdictCategory.UNVERIFIED,
            f"UNVERIFIED — device could not be checked ({collection_error}). "
            "CSV data only; treat as unconfirmed.",
        )

    if stats is None:
        return Verdict(
            VerdictCategory.PARSE_ERROR,
            "PARSE_ERROR — no diagnostic data was collected/parsed for this "
            "interface. No verdict is possible (fail closed).",
            details=list(parse_errors),
        )

    if (member_stats or member_errors) and classify_counter(
        case.counter
    ) is not CounterClass.TOTAL_TRAFFIC:
        if parent_portchannel:
            return _member_case_verdict(
                case,
                stats,
                baseline_stats,
                baseline_minutes,
                thresholds,
                list(parse_errors),
                parent_portchannel,
                member_stats or {},
                member_baseline_stats or {},
                member_errors or {},
                report_time,
            )
        return _portchannel_verdict(
            case,
            stats,
            baseline_stats,
            baseline_minutes,
            thresholds,
            list(parse_errors),
            member_stats or {},
            member_baseline_stats or {},
            member_errors or {},
            report_time,
        )

    return _evaluate_stats(
        case.counter,
        stats,
        baseline_stats,
        baseline_minutes,
        thresholds,
        list(parse_errors),
        csv_change=case.change,
        poll_time=case.poll_time,
        report_time=report_time,
    )


def _evaluate_stats(
    counter_name: str,
    stats: NormalizedInterfaceStats,
    baseline_stats: NormalizedInterfaceStats | None,
    baseline_minutes: float | None,
    thresholds: Thresholds,
    base_details: list[str],
    csv_change: int | None = None,
    poll_time: str | None = None,
    report_time: datetime | None = None,
) -> Verdict:
    """Single-interface verdict logic, shared by plain cases, the bundle-level
    view of a port-channel, and each of its members.

    Deterministic ladder, first match wins:
    INSUFFICIENT_DATA -> HISTORIC_NOT_ACTIVE -> CONGESTION_BUFFER ->
    PHYSICAL_MEDIA -> LINK_NEGOTIATION -> IGNORE.
    """

    cls = classify_counter(counter_name)

    if cls is CounterClass.TOTAL_TRAFFIC:
        return Verdict(
            VerdictCategory.IGNORE,
            f"IGNORE — '{counter_name}' is a total traffic counter, not an "
            "error counter; a 24h increase is normal operation. No action.",
        )

    missing = [
        field_name
        for field_name in _REQUIRED_FIELDS[cls]
        if getattr(stats, field_name) is None
    ]
    if missing:
        return Verdict(
            VerdictCategory.PARSE_ERROR,
            f"PARSE_ERROR — critical field(s) {', '.join(missing)} could not "
            "be parsed from device output. Refusing to guess (fail closed).",
            details=list(base_details),
        )

    details: list[str] = list(base_details)
    flags: list[DataQualityFlag] = []
    signals: list[Signal] = []
    value_field = _VALUE_FIELD[cls]

    # --- populations and provenance ------------------------------------------
    interval: IntervalEstimate | None = None
    window: DeltaWindow | None = None
    if baseline_stats is not None:
        interval = observation_window(baseline_stats, stats, baseline_minutes)
        window = compute_delta_window(baseline_stats, stats, interval)
    value_delta = getattr(window, value_field) if window is not None else None
    flat = value_delta == 0 if value_delta is not None else None
    life = LifetimeView(stats)
    life_window = lifetime_window(stats)

    if value_delta is None:
        flags.append(DataQualityFlag(DataQualityKind.NO_SECOND_OBSERVATION))
        if baseline_stats is not None:
            details.append(
                "earlier sample discarded: its counters cannot be subtracted "
                "from the current ones (counter reset, device reload, or a "
                "field it does not carry)"
            )
    if interval is not None and interval.source is IntervalSource.HOST_INGEST_TIME:
        flags.append(
            DataQualityFlag(
                DataQualityKind.INTERVAL_FROM_INGEST_TIME,
                {"interval_minutes": round(interval.minutes, 1)},
            )
        )

    stale_minutes: float | None = None
    if report_time is not None and poll_time:
        poll = parse_poll_time(poll_time)
        stale_minutes = staleness_minutes(report_time, poll)
        if stale_minutes is not None and stale_minutes > _STALE_HEADLINE_MINUTES:
            flags.append(
                DataQualityFlag(
                    DataQualityKind.STALE_POLL_TIMESTAMP,
                    {"staleness_minutes": round(stale_minutes)},
                )
            )

    if (
        value_delta is not None
        and csv_change is not None
        and csv_change >= 0
        and delta_sources_disagree(value_delta, csv_change)
    ):
        flags.append(
            DataQualityFlag(
                DataQualityKind.DELTA_SOURCE_DISAGREEMENT,
                {"delta_tool": value_delta, "delta_csv": csv_change},
            )
        )

    if cls in (CounterClass.RECEIVE_ERRORS, CounterClass.GENERIC_ERRORS):
        reconciliation = reconcile_input_errors(stats)
        if reconciliation is not None and not reconciliation.balanced:
            flags.append(
                DataQualityFlag(
                    DataQualityKind.COUNTER_RECONCILIATION_FAILED,
                    {
                        "residual": reconciliation.residual,
                        "residual_fraction": round(reconciliation.residual_fraction, 4),
                    },
                )
            )

    ratio = window.ratio_of(value_field) if window is not None else None
    if ratio is not None and ratio.flag is not None:
        flags.append(
            DataQualityFlag(
                DataQualityKind.RATIO_OUT_OF_RANGE, {"detail": ratio.detail or ""}
            )
        )
    metrics = _build_metrics(window, value_delta, csv_change, ratio, stale_minutes)

    link_down = (stats.link_status or "").lower() != "up"
    if link_down:
        details.append(
            f"interface is currently {stats.link_status}/{stats.protocol_status or '?'}"
        )

    def verdict(
        category: VerdictCategory,
        base_confidence: Confidence | None,
        reason_tag: str,
        extra_signals: Sequence[Signal] = (),
        what: Signal | None = None,
    ) -> Verdict:
        all_signals = [*signals, *extra_signals]
        confidence = apply_caps(base_confidence, flags) if base_confidence else None
        headline = f"{category.value}"
        if confidence:
            headline += f" — confidence {confidence.value}"
        if reason_tag:
            headline += f" ({reason_tag})"
        return Verdict(
            category,
            headline + ".",
            details=details,
            confidence=confidence,
            signals=all_signals,
            data_quality=flags,
            metrics=metrics,
            what_would_change=what,
        )

    # ---- late collisions ---------------------------------------------------
    if cls is CounterClass.LATE_COLLISIONS:
        return _late_collisions_verdict(stats, flat, verdict)

    # ---- discards: congestion/buffer, not physical --------------------------
    if cls in (CounterClass.IN_DISCARDS, CounterClass.OUT_DISCARDS):
        return _discards_verdict(
            cls, stats, window, value_delta, flat, life_window, thresholds, verdict
        )

    # ---- receive errors: the core ladder ------------------------------------
    return _receive_errors_verdict(
        stats,
        window,
        value_delta,
        flat,
        life,
        life_window,
        thresholds,
        signals,
        flags,
        verdict,
    )


def _late_collisions_verdict(
    stats: NormalizedInterfaceStats,
    flat: bool | None,
    verdict,
) -> Verdict:
    lc = stats.late_collisions or 0
    if lc == 0:
        return verdict(VerdictCategory.IGNORE, Confidence.HIGH, "no_late_collisions")
    if flat is True:
        return verdict(
            VerdictCategory.HISTORIC_NOT_ACTIVE,
            Confidence.HIGH,
            "zero_delta_nonzero_lifetime",
            extra_signals=[
                Signal(
                    kind=SignalKind.ZERO_DELTA_NONZERO_LIFETIME,
                    weight=Confidence.HIGH,
                    values={"late_collisions": lc},
                )
            ],
            what=_WHAT_HISTORIC,
        )
    duplex = (stats.duplex or "").lower()
    neighbor_duplex = (stats.neighbor_duplex or "").lower()
    mismatch_logged = bool(stats.duplex_mismatch_logged)
    mismatch_signal = Signal(
        kind=SignalKind.LATE_COLLISIONS_FULL_DUPLEX,
        weight=Confidence.HIGH,
        values={
            "late_collisions": lc,
            "duplex": stats.duplex or "?",
            "neighbor_duplex": stats.neighbor_duplex or "?",
            "neighbor_name": stats.neighbor_name or "?",
            "mismatch_logged": str(mismatch_logged),
        },
        supports=VerdictCategory.LINK_NEGOTIATION,
    )
    if duplex.startswith("full"):
        # Late collisions cannot happen on a true full-duplex link: the far
        # end is running half duplex. A negotiation problem, fixed via CLI.
        return verdict(
            VerdictCategory.LINK_NEGOTIATION,
            Confidence.HIGH,
            "late_collisions_full_duplex",
            extra_signals=[mismatch_signal],
        )
    if neighbor_duplex.startswith("full") or mismatch_logged:
        return verdict(
            VerdictCategory.LINK_NEGOTIATION,
            Confidence.HIGH,
            "duplex_mismatch_confirmed",
            extra_signals=[mismatch_signal],
        )
    # Genuine half-duplex on both ends: late collisions mean the segment is
    # out of spec (cable too long, failing NIC) — a physical problem.
    return verdict(
        VerdictCategory.PHYSICAL_MEDIA,
        Confidence.MEDIUM,
        "late_collisions_legacy_half_duplex",
        extra_signals=[
            Signal(
                kind=SignalKind.LATE_COLLISIONS_FULL_DUPLEX,
                weight=Confidence.MEDIUM,
                values={"late_collisions": lc, "duplex": stats.duplex or "?"},
                supports=VerdictCategory.PHYSICAL_MEDIA,
            )
        ],
    )


def _discards_verdict(
    cls: CounterClass,
    stats: NormalizedInterfaceStats,
    window: DeltaWindow | None,
    value_delta: int | None,
    flat: bool | None,
    life_window: IntervalEstimate | None,
    thresholds: Thresholds,
    verdict,
) -> Verdict:
    direction_in = cls is CounterClass.IN_DISCARDS
    lifetime_value = stats.discards_in if direction_in else stats.discards_out
    congestion_signal = Signal(
        kind=SignalKind.BUFFER_GROUP_DOMINANT,
        weight=Confidence.HIGH,
        values={
            "discards": value_delta
            if value_delta is not None
            else (lifetime_value or 0),
            "direction": "input" if direction_in else "output",
        },
        supports=VerdictCategory.CONGESTION_BUFFER,
    )

    rate: float | None = None
    if window is not None and value_delta is not None:
        # Same-population denominators: input discards against received
        # frames, output discards against delta output packets.
        if direction_in:
            rate = window.ratio_of("discards_in").value
        else:
            # Discarded frames are not in `packets output`, so they are added
            # back — the quotient is bounded to [0, 1] by construction.
            delivered = window.output_packets
            if delivered is not None and delivered + value_delta > 0:
                rate = value_delta / (delivered + value_delta)
    elif lifetime_value is not None and life_window is not None:
        packets = stats.input_packets if direction_in else stats.output_packets
        if packets and packets > 0:
            rate = lifetime_value / (packets + lifetime_value)

    if flat is True and (lifetime_value or 0) > 0:
        return verdict(
            VerdictCategory.HISTORIC_NOT_ACTIVE,
            Confidence.HIGH,
            "zero_delta_nonzero_lifetime",
            extra_signals=[
                Signal(
                    kind=SignalKind.ZERO_DELTA_NONZERO_LIFETIME,
                    weight=Confidence.HIGH,
                    values={"discards": lifetime_value or 0},
                )
            ],
            what=_WHAT_HISTORIC,
        )
    if rate is not None and rate >= thresholds.discard_rate:
        return verdict(
            VerdictCategory.CONGESTION_BUFFER,
            Confidence.HIGH,
            "discards_at_rate",
            extra_signals=[congestion_signal],
        )
    if (lifetime_value or 0) == 0:
        return verdict(VerdictCategory.IGNORE, Confidence.HIGH, "no_discards")
    if rate is None and window is None and life_window is None:
        # A lifetime figure with no epoch and no second observation supports
        # no rate at all.
        return verdict(VerdictCategory.INSUFFICIENT_DATA, None, "no_usable_window")
    return verdict(VerdictCategory.IGNORE, Confidence.HIGH, "below_threshold")


def _receive_errors_verdict(
    stats: NormalizedInterfaceStats,
    window: DeltaWindow | None,
    value_delta: int | None,
    flat: bool | None,
    life: LifetimeView,
    life_window: IntervalEstimate | None,
    thresholds: Thresholds,
    signals: list[Signal],
    flags: list[DataQualityFlag],
    verdict,
) -> Verdict:
    what_media = Signal(
        kind=SignalKind.ERRORS_STOPPED_AFTER_CLEAR, weight=Confidence.HIGH
    )

    # DOM out of range is a direct physical-layer measurement: it needs no
    # delta and dominates the counter analysis.
    rx_dbm = stats.dom_rx_power_dbm
    if rx_dbm is not None and not (
        thresholds.dom_rx_low_dbm <= rx_dbm <= thresholds.dom_rx_high_dbm
    ):
        return verdict(
            VerdictCategory.PHYSICAL_MEDIA,
            Confidence.HIGH,
            "dom_rx_out_of_range",
            extra_signals=[
                Signal(
                    kind=SignalKind.DOM_RX_OUT_OF_RANGE,
                    weight=Confidence.HIGH,
                    values={
                        "dom_rx_power_dbm": rx_dbm,
                        "dom_rx_low_dbm": thresholds.dom_rx_low_dbm,
                        "dom_rx_high_dbm": thresholds.dom_rx_high_dbm,
                    },
                    supports=VerdictCategory.PHYSICAL_MEDIA,
                ),
                *_corroborating_signals(stats),
            ],
            what=what_media,
        )

    lifetime_errors = stats.input_errors or 0

    # ---- with a usable tool delta -------------------------------------------
    if value_delta is not None:
        if flat is True:
            if lifetime_errors > 0:
                # A never-cleared counter with millions of errors and zero
                # movement is not an incident, regardless of its size.
                return verdict(
                    VerdictCategory.HISTORIC_NOT_ACTIVE,
                    Confidence.HIGH,
                    "zero_delta_nonzero_lifetime",
                    extra_signals=[
                        Signal(
                            kind=SignalKind.ZERO_DELTA_NONZERO_LIFETIME,
                            weight=Confidence.HIGH,
                            values={"input_errors": lifetime_errors},
                        )
                    ],
                    what=_WHAT_HISTORIC,
                )
            return verdict(VerdictCategory.IGNORE, Confidence.HIGH, "clean")

        # Active delta. Magnitude first (rate is the primary metric): below
        # the floor nothing else fires; above it, WHICH bucket is moving
        # decides the class — never the total alone.
        assert window is not None
        zero_traffic = zero_traffic_test(window, stats)
        error_ratio = window.error_ratio()
        significant = zero_traffic or (
            error_ratio.value is not None and error_ratio.value >= thresholds.error_rate
        )
        if not significant:
            return verdict(VerdictCategory.IGNORE, Confidence.HIGH, "below_threshold")

        if zero_traffic:
            zero_traffic_values: dict[str, int | float | str] = {
                "delta_input_errors": window.input_errors or 0,
                "errors_per_second": round(window.errors_per_second() or 0, 2),
                "input_rate_pps": stats.input_rate_pps
                if stats.input_rate_pps is not None
                else -1,
                "last_input_minutes": round(
                    stats.last_input_minutes
                    if stats.last_input_minutes is not None
                    else -1,
                    1,
                ),
                "duplex": stats.duplex or "?",
            }
            # Errors without traffic place the fault at the link, but the link
            # includes its negotiation: collision activity means the port is
            # fighting its peer, and the collision-aware rungs below must
            # decide between media and duplex — same guard as
            # _media_dominance_verdict.
            collision_activity = bool(stats.collisions) or bool(stats.late_collisions)
            if not collision_activity:
                if stats.collisions is None or stats.late_collisions is None:
                    flags.append(
                        DataQualityFlag(
                            DataQualityKind.NULL_RULE_INPUT,
                            {"fields": "collisions/late_collisions"},
                        )
                    )
                return verdict(
                    VerdictCategory.PHYSICAL_MEDIA,
                    Confidence.HIGH,
                    "zero_traffic_errors",
                    extra_signals=[
                        Signal(
                            kind=SignalKind.ZERO_TRAFFIC_ERRORS,
                            weight=Confidence.HIGH,
                            values=zero_traffic_values,
                            supports=VerdictCategory.PHYSICAL_MEDIA,
                        ),
                        *_unattributed_signals(stats),
                        *_corroborating_signals(stats),
                    ],
                    what=what_media,
                )
            # Keep the observation as evidence for whichever rung wins, but
            # without pre-judging the category.
            signals.append(
                Signal(
                    kind=SignalKind.ZERO_TRAFFIC_ERRORS,
                    weight=Confidence.MEDIUM,
                    values={
                        **zero_traffic_values,
                        "collisions": stats.collisions or 0,
                        "late_collisions": stats.late_collisions or 0,
                    },
                )
            )

        buffer_delta = buffer_group_delta(window)
        buffer_share = _share(buffer_delta, window.input_errors)
        if buffer_share is not None and buffer_share > DOMINANT_SHARE:
            return verdict(
                VerdictCategory.CONGESTION_BUFFER,
                Confidence.HIGH,
                "buffer_group_dominant",
                extra_signals=[
                    Signal(
                        kind=SignalKind.BUFFER_GROUP_DOMINANT,
                        weight=Confidence.HIGH,
                        values={
                            "buffer_group": buffer_delta or 0,
                            "input_errors": window.input_errors or 0,
                        },
                        supports=VerdictCategory.CONGESTION_BUFFER,
                    )
                ],
            )

        media = _media_dominance_verdict(
            stats, flags, verdict, _corroborating_signals(stats), what_media
        )
        if media is not None:
            return media

        negotiation = _link_negotiation_verdict(stats, window, verdict)
        if negotiation is not None:
            return negotiation

        fcs_verdict = _fcs_fraction_verdict(
            stats, window, verdict, what_media, active=True
        )
        if fcs_verdict is not None:
            return fcs_verdict

        return verdict(
            VerdictCategory.PHYSICAL_MEDIA,
            Confidence.MEDIUM,
            "error_rate_above_threshold",
            extra_signals=_corroborating_signals(stats),
            what=what_media,
        )

    # ---- no usable delta: lifetime-only path --------------------------------
    if lifetime_errors == 0:
        return verdict(VerdictCategory.IGNORE, Confidence.HIGH, "clean")

    if stats.counters_never_cleared and life_window is None:
        # Only a never-cleared lifetime figure and no second observation:
        # nothing here says whether a single error happened this month.
        return verdict(VerdictCategory.INSUFFICIENT_DATA, None, "no_usable_window")

    if life_window is None:
        return verdict(VerdictCategory.INSUFFICIENT_DATA, None, "unknown_epoch")

    if stats.counters_never_cleared:
        # The lifetime window spans the whole uptime; an average over months
        # says nothing about NOW without a second observation.
        return verdict(
            VerdictCategory.INSUFFICIENT_DATA, None, "never_cleared_single_sample"
        )

    lifetime_ratio = life.error_ratio()
    if lifetime_ratio.value is None or lifetime_ratio.value < thresholds.error_rate:
        return verdict(VerdictCategory.IGNORE, Confidence.HIGH, "below_threshold")
    media = _media_dominance_verdict(
        stats, flags, verdict, _corroborating_signals(stats), what_media
    )
    if media is not None:
        return media
    negotiation = _link_negotiation_verdict(stats, None, verdict)
    if negotiation is not None:
        return negotiation
    fcs_verdict = _fcs_fraction_verdict(stats, None, verdict, what_media, active=False)
    if fcs_verdict is not None:
        return fcs_verdict
    return verdict(
        VerdictCategory.PHYSICAL_MEDIA,
        Confidence.HIGH,  # capped MEDIUM by NO_SECOND_OBSERVATION
        "error_rate_above_threshold",
        extra_signals=_corroborating_signals(stats),
        what=what_media,
    )


def _unattributed_signals(stats: NormalizedInterfaceStats) -> list[Signal]:
    """The decomposition evidence: where the errors fall, and the FCS
    contradiction when it applies."""
    signals: list[Signal] = []
    residual = unattributed_rx(stats)
    if residual is not None and stats.input_errors:
        signals.append(
            Signal(
                kind=SignalKind.UNATTRIBUTED_RX_DOMINANT,
                weight=Confidence.HIGH,
                values={
                    "unattributed_rx": residual,
                    "input_errors": stats.input_errors,
                    "runts": stats.runts if stats.runts is not None else -1,
                },
                supports=VerdictCategory.PHYSICAL_MEDIA,
            )
        )
    contradiction = _fcs_contradiction(stats)
    if contradiction is not None:
        signals.append(contradiction)
    return signals


def _media_dominance_verdict(
    stats: NormalizedInterfaceStats,
    flags: list[DataQualityFlag],
    verdict,
    corroborating: list[Signal],
    what_media: Signal,
) -> Verdict | None:
    """PHYSICAL_MEDIA on a dominant unattributed/symbol/runts profile with no
    collision activity. The buckets accumulate together, so dominance is
    measured on the lifetime decomposition; activity was already established
    by the caller's delta (or capped by its absence)."""
    symbol_or_unattributed = (
        stats.symbol_errors
        if stats.symbol_errors is not None
        else unattributed_rx(stats)
    )
    dominant_share = max(
        _share(symbol_or_unattributed, stats.input_errors) or 0,
        _share(stats.runts, stats.input_errors) or 0,
    )
    if dominant_share <= DOMINANT_SHARE:
        return None
    if stats.collisions not in (0, None) or stats.late_collisions not in (0, None):
        return None  # collision activity points at negotiation, not media
    if stats.collisions is None or stats.late_collisions is None:
        flags.append(
            DataQualityFlag(
                DataQualityKind.NULL_RULE_INPUT,
                {"fields": "collisions/late_collisions"},
            )
        )
    kind = (
        SignalKind.RUNTS_DOMINANT_NO_COLLISIONS
        if (_share(stats.runts, stats.input_errors) or 0) > DOMINANT_SHARE
        and (_share(symbol_or_unattributed, stats.input_errors) or 0) <= DOMINANT_SHARE
        else SignalKind.UNATTRIBUTED_RX_DOMINANT
    )
    return verdict(
        VerdictCategory.PHYSICAL_MEDIA,
        Confidence.HIGH,
        kind.value,
        extra_signals=[
            *_unattributed_signals(stats),
            *corroborating,
        ],
        what=what_media,
    )


def _fcs_fraction_verdict(
    stats: NormalizedInterfaceStats,
    window: DeltaWindow | None,
    verdict,
    what_media: Signal,
    active: bool,
) -> Verdict | None:
    """High FCS share with errors moving: frames are arriving but corrupted —
    marginal signal rather than link-level corruption."""
    if window is not None:
        fcs_delta = (
            window.fcs_errors if window.fcs_errors is not None else window.crc_errors
        )
        fraction = _share(fcs_delta, window.input_errors)
    else:
        fcs = stats.fcs_errors if stats.fcs_errors is not None else stats.crc_errors
        fraction = _share(fcs, stats.input_errors)
    if fraction is None or fraction <= FCS_FRACTION_MIN:
        return None
    return verdict(
        VerdictCategory.PHYSICAL_MEDIA,
        Confidence.MEDIUM if active else Confidence.HIGH,
        "fcs_fraction_active",
        extra_signals=[
            Signal(
                kind=SignalKind.FCS_FRACTION_ACTIVE,
                weight=Confidence.MEDIUM,
                values={
                    "fcs_fraction": round(fraction, 4),
                    "input_errors": stats.input_errors or 0,
                },
                supports=VerdictCategory.PHYSICAL_MEDIA,
            ),
            *_corroborating_signals(stats),
        ],
        what=what_media,
    )


def _link_negotiation_verdict(
    stats: NormalizedInterfaceStats,
    window: DeltaWindow | None,
    verdict,
) -> Verdict | None:
    """Within a receive-error case: collision activity on full duplex, or a
    dominant giants profile, points at negotiation/MTU rather than media."""
    duplex = (stats.duplex or "").lower()
    late = window.late_collisions if window is not None else stats.late_collisions
    if late and duplex.startswith("full"):
        return verdict(
            VerdictCategory.LINK_NEGOTIATION,
            Confidence.HIGH,
            "late_collisions_full_duplex",
            extra_signals=[
                Signal(
                    kind=SignalKind.LATE_COLLISIONS_FULL_DUPLEX,
                    weight=Confidence.HIGH,
                    values={"late_collisions": late, "duplex": stats.duplex or "?"},
                    supports=VerdictCategory.LINK_NEGOTIATION,
                )
            ],
        )
    neighbor_duplex = (stats.neighbor_duplex or "").lower()
    if late and (neighbor_duplex.startswith("full") or stats.duplex_mismatch_logged):
        # Half duplex here, full duplex reported by the peer (or the device
        # logged the mismatch itself): the same confirmation the dedicated
        # Late-Col rule uses, reachable from a receive-error case.
        return verdict(
            VerdictCategory.LINK_NEGOTIATION,
            Confidence.HIGH,
            "duplex_mismatch_confirmed",
            extra_signals=[
                Signal(
                    kind=SignalKind.LATE_COLLISIONS_FULL_DUPLEX,
                    weight=Confidence.HIGH,
                    values={
                        "late_collisions": late,
                        "duplex": stats.duplex or "?",
                        "neighbor_duplex": stats.neighbor_duplex or "?",
                        "neighbor_name": stats.neighbor_name or "?",
                        "mismatch_logged": str(bool(stats.duplex_mismatch_logged)),
                    },
                    supports=VerdictCategory.LINK_NEGOTIATION,
                )
            ],
        )
    giants = window.giants if window is not None else stats.giants
    total = window.input_errors if window is not None else stats.input_errors
    giants_share = _share(giants, total)
    if giants_share is not None and giants_share > DOMINANT_SHARE:
        # The far end's MTU is unknown, so this is a giants profile, not a
        # confirmed mismatch — MEDIUM, and the narrative keeps the ambiguity.
        return verdict(
            VerdictCategory.LINK_NEGOTIATION,
            Confidence.MEDIUM,
            "giants_with_mtu_mismatch",
            extra_signals=[
                Signal(
                    kind=SignalKind.GIANTS_WITH_MTU_MISMATCH,
                    weight=Confidence.MEDIUM,
                    values={"giants": giants or 0, "mtu": stats.mtu or 0},
                    supports=VerdictCategory.LINK_NEGOTIATION,
                )
            ],
        )
    return None


# Verdicts that demand action; a member showing one is the bundle's culprit.
_ACTIONABLE = (
    VerdictCategory.PHYSICAL_MEDIA,
    VerdictCategory.LINK_NEGOTIATION,
    VerdictCategory.CONGESTION_BUFFER,
)


def _member_findings(
    counter_name: str,
    baseline_minutes: float | None,
    thresholds: Thresholds,
    member_stats: dict[str, NormalizedInterfaceStats],
    member_baseline_stats: dict[str, NormalizedInterfaceStats],
    member_errors: dict[str, str],
    report_time: datetime | None,
) -> tuple[dict[str, Verdict], dict[str, str]]:
    """Evaluate every sampled member; return their verdicts and one-line
    findings, with uncollectable members spelled out rather than omitted."""
    verdicts = {
        name: _evaluate_stats(
            counter_name,
            stats,
            member_baseline_stats.get(name),
            baseline_minutes,
            thresholds,
            [],
            report_time=report_time,
        )
        for name, stats in member_stats.items()
    }
    findings = {name: verdict.reason for name, verdict in verdicts.items()}
    for name, error in member_errors.items():
        findings[name] = f"not evaluated: {error}"
    return verdicts, findings


def _member_case_verdict(
    case: InterfaceCase,
    stats: NormalizedInterfaceStats,
    baseline_stats: NormalizedInterfaceStats | None,
    baseline_minutes: float | None,
    thresholds: Thresholds,
    parse_errors: list[str],
    parent_portchannel: str,
    member_stats: dict[str, NormalizedInterfaceStats],
    member_baseline_stats: dict[str, NormalizedInterfaceStats],
    member_errors: dict[str, str],
    report_time: datetime | None,
) -> Verdict:
    """Judge a case that is a member of a port-channel.

    The CSV asked about this interface, so the verdict is this interface's own
    — identical to the plain single-interface path. Its sibling members were
    sampled because a LAG fault often sits on a neighbouring link, but they are
    context only: a dirty or uncollectable sibling never changes the category
    of the port that was actually reported.
    """
    verdict = _evaluate_stats(
        case.counter,
        stats,
        baseline_stats,
        baseline_minutes,
        thresholds,
        parse_errors,
        csv_change=case.change,
        poll_time=case.poll_time,
        report_time=report_time,
    )
    _, findings = _member_findings(
        case.counter,
        baseline_minutes,
        thresholds,
        member_stats,
        member_baseline_stats,
        member_errors,
        report_time,
    )
    verdict.details.append(
        f"member of port-channel {parent_portchannel}: the members listed are "
        f"context; the verdict is for {case.interface} itself"
    )
    verdict.member_findings = findings
    return verdict


def _min_member_confidence(
    bundle_confidence: Confidence | None,
    member_verdicts: dict[str, Verdict],
) -> Confidence | None:
    """A bundle may not claim more confidence than its least confident
    evaluated member: the fault sits on a physical member, and that member's
    data-quality caps bound what the bundle knows."""
    confidences = [
        verdict.confidence
        for verdict in member_verdicts.values()
        if verdict.confidence is not None
    ]
    if bundle_confidence is not None:
        confidences.append(bundle_confidence)
    if not confidences:
        return None
    return min(confidences, key=lambda item: _CONFIDENCE_RANK[item])


def _portchannel_verdict(
    case: InterfaceCase,
    stats: NormalizedInterfaceStats,
    baseline_stats: NormalizedInterfaceStats | None,
    baseline_minutes: float | None,
    thresholds: Thresholds,
    parse_errors: list[str],
    member_stats: dict[str, NormalizedInterfaceStats],
    member_baseline_stats: dict[str, NormalizedInterfaceStats],
    member_errors: dict[str, str],
    report_time: datetime | None,
) -> Verdict:
    """Judge a port-channel through its members.

    Bundle counters are sums across members, so a single bad member's rate is
    diluted by its healthy peers — and cable/transceiver language is
    meaningless for a logical bundle. Each member is evaluated with the
    single-interface logic; the verdict names the culpable member, and any
    member that could not be evaluated fails the bundle closed.
    """
    member_verdicts, findings = _member_findings(
        case.counter,
        baseline_minutes,
        thresholds,
        member_stats,
        member_baseline_stats,
        member_errors,
        report_time,
    )

    bundle = _evaluate_stats(
        case.counter,
        stats,
        baseline_stats,
        baseline_minutes,
        thresholds,
        list(parse_errors),
        csv_change=case.change,
        poll_time=case.poll_time,
        report_time=report_time,
    )

    culpable = {
        name: verdict
        for name, verdict in member_verdicts.items()
        if verdict.category in _ACTIONABLE
    }
    if culpable:
        primary_name, primary = min(
            culpable.items(), key=lambda item: VERDICT_ORDER.index(item[1].category)
        )
        details = list(parse_errors)
        others = [name for name in culpable if name != primary_name]
        if others:
            details.append("other affected members: " + ", ".join(others))
        details.append(f"bundle-level analysis: {bundle.reason}")
        return Verdict(
            primary.category,
            f"{primary.category.value} — port-channel {case.interface}: fault "
            f"isolated to member {primary_name} — {primary.reason}",
            details=details,
            member_findings=findings,
            confidence=_min_member_confidence(primary.confidence, member_verdicts),
            signals=primary.signals,
            data_quality=primary.data_quality,
            metrics=primary.metrics,
            what_would_change=primary.what_would_change,
        )

    unevaluable = dict(member_errors)
    unevaluable.update(
        {
            name: verdict.reason
            for name, verdict in member_verdicts.items()
            if verdict.category is VerdictCategory.PARSE_ERROR
        }
    )
    if unevaluable:
        names = ", ".join(sorted(unevaluable))
        return Verdict(
            VerdictCategory.PARSE_ERROR,
            f"PARSE_ERROR — port-channel {case.interface}: member(s) {names} "
            "could not be collected/parsed; a clean verdict for the bundle "
            "would be a guess (fail closed).",
            details=[f"bundle-level analysis: {bundle.reason}", *parse_errors],
            member_findings=findings,
        )

    if bundle.category in _ACTIONABLE:
        return Verdict(
            bundle.category,
            f"{bundle.category.value} — port-channel {case.interface}: bundle "
            "counters show the reported errors but no current member does "
            "(possibly historical, or from a since-removed member). "
            f"Bundle-level analysis: {bundle.reason}",
            details=bundle.details,
            member_findings=findings,
            confidence=_min_member_confidence(bundle.confidence, member_verdicts),
            signals=bundle.signals,
            data_quality=bundle.data_quality,
            metrics=bundle.metrics,
        )

    # No culpable member, every member evaluable: the bundle-level verdict
    # stands (IGNORE when clean; PARSE_ERROR keeps failing closed).
    bundle.member_findings = findings
    return bundle
