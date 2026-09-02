"""Population-safe counter math for the diagnostic engine.

Three populations exist and must never meet in one ratio:

- lifetime values — `NormalizedInterfaceStats` fields, read from the device
  since its last counter clear;
- tool deltas — the difference between two observations of the same lifetime
  counter, held in `DeltaWindow` (built only by `compute_delta_window`);
- the CSV delta — Splunk's `change` column, held in `CsvDelta`.

The discipline is structural: division lives only in methods of the classes
above, so both operands always come from the same population. `CsvDelta`
deliberately has no rate methods at all — its interval is a claim, not a
measurement — it can only be displayed and compared against the tool's own
delta. A ratio that falls outside [0, 1] is never returned as a value; it
comes back as a `RATIO_OUT_OF_RANGE` data-quality flag naming both operands.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from .models import NormalizedInterfaceStats
from .timebase import IntervalEstimate

# The zero-traffic test (the strongest physical-media discriminator): errors
# advancing at this rate or faster while effectively no valid frames arrive
# cannot originate from the traffic — they originate from the link.
ZERO_TRAFFIC_MIN_ERRORS_PER_SEC = 1.0
ZERO_TRAFFIC_MAX_PACKETS_PER_SEC = 1.0

# Two delta sources that disagree by more than this factor are flagged; the
# tool's own observation is preferred because its interval is measured.
DELTA_DISAGREEMENT_FACTOR = 3.0

RATIO_OUT_OF_RANGE = "RATIO_OUT_OF_RANGE"


@dataclass(frozen=True)
class RatioResult:
    """A ratio, or the reason it could not honestly be one.

    `value` is set only when the ratio is defined and inside [0, 1]. `flag`
    carries RATIO_OUT_OF_RANGE with the offending operands when it is not;
    both None means the inputs were missing and no division was attempted.
    """

    value: float | None = None
    flag: str | None = None
    detail: str | None = None


def _ratio(numerator: int | None, denominator: int | None, label: str) -> RatioResult:
    if numerator is None or denominator is None or denominator <= 0:
        return RatioResult()
    value = numerator / denominator
    if 0 <= value <= 1:
        return RatioResult(value=value)
    return RatioResult(
        flag=RATIO_OUT_OF_RANGE,
        detail=f"{label}: {numerator} / {denominator} = {value:.4f}",
    )


# Lifetime counter fields that get a per-field delta. Each delta is None when
# either sample lacks the field or the counter went backwards (clear/reload
# between the samples) — never coerced to zero, so a discarded baseline can
# never fake a flat counter.
_DELTA_FIELDS = (
    "input_packets",
    "output_packets",
    "input_errors",
    "crc_errors",
    "fcs_errors",
    "align_errors",
    "symbol_errors",
    "rcv_err",
    "runts",
    "giants",
    "undersize",
    "overrun",
    "ignored",
    "no_buffer",
    "discards_in",
    "discards_out",
    "collisions",
    "late_collisions",
    "output_errors",
    "bytes_input",
    "bytes_output",
)


@dataclass(frozen=True)
class DeltaWindow:
    """Tool-observed deltas: later lifetime sample minus earlier one.

    Built only by `compute_delta_window`. Every field is the delta of the
    same-named lifetime counter, or None when it could not be formed.
    """

    interval: IntervalEstimate | None
    input_packets: int | None = None
    output_packets: int | None = None
    input_errors: int | None = None
    crc_errors: int | None = None
    fcs_errors: int | None = None
    align_errors: int | None = None
    symbol_errors: int | None = None
    rcv_err: int | None = None
    runts: int | None = None
    giants: int | None = None
    undersize: int | None = None
    overrun: int | None = None
    ignored: int | None = None
    no_buffer: int | None = None
    discards_in: int | None = None
    discards_out: int | None = None
    collisions: int | None = None
    late_collisions: int | None = None
    output_errors: int | None = None
    bytes_input: int | None = None
    bytes_output: int | None = None

    def received_frames(self) -> int | None:
        """Frames that arrived in the window, errored or not: `packets input`
        counts only successfully received frames, so the errored ones must be
        added back before it can serve as a denominator."""
        if self.input_packets is None or self.input_errors is None:
            return None
        return self.input_packets + self.input_errors

    def errors_per_second(self) -> float | None:
        if self.input_errors is None or self.interval is None:
            return None
        if self.interval.seconds <= 0:
            return None
        return self.input_errors / self.interval.seconds

    def errors_per_hour(self) -> float | None:
        per_second = self.errors_per_second()
        if per_second is None:
            return None
        return per_second * 3600

    def packets_per_second(self) -> float | None:
        if self.input_packets is None or self.interval is None:
            return None
        if self.interval.seconds <= 0:
            return None
        return self.input_packets / self.interval.seconds

    def error_ratio(self) -> RatioResult:
        """Secondary metric: delta input errors over delta received frames."""
        return _ratio(
            self.input_errors,
            self.received_frames(),
            "delta_input_errors / delta_received_frames",
        )

    def ratio_of(self, field_name: str) -> RatioResult:
        """Share of one delta bucket within delta received frames."""
        return _ratio(
            getattr(self, field_name),
            self.received_frames(),
            f"delta_{field_name} / delta_received_frames",
        )

    def rate_of(self, field_name: str) -> float | None:
        """Per-second rate of one delta bucket over the window."""
        value = getattr(self, field_name)
        if value is None or self.interval is None or self.interval.seconds <= 0:
            return None
        return value / self.interval.seconds

    def ratio_against_transmitted(self, field_name: str) -> RatioResult:
        """Share of one delta bucket within attempted transmissions.

        Frames lost to output discards or late collisions are absent from
        `packets output`, so the bucket is added back — the quotient is
        bounded to [0, 1] by construction.
        """
        value = getattr(self, field_name)
        attempted = (
            self.output_packets + value
            if value is not None and self.output_packets is not None
            else None
        )
        return _ratio(
            value, attempted, f"delta_{field_name} / delta_attempted_tx_frames"
        )


def compute_delta_window(
    earlier: NormalizedInterfaceStats,
    later: NormalizedInterfaceStats,
    interval: IntervalEstimate | None,
) -> DeltaWindow:
    """The only constructor of tool deltas.

    Per field: None when either sample lacks it or the counter decreased
    (cleared / reloaded between samples); the remaining fields still delta,
    so one reset counter does not discard the whole window.
    """
    deltas: dict[str, int | None] = {}
    for name in _DELTA_FIELDS:
        before = getattr(earlier, name)
        after = getattr(later, name)
        if before is None or after is None or after < before:
            deltas[name] = None
        else:
            deltas[name] = after - before
    return DeltaWindow(interval=interval, **deltas)


@dataclass(frozen=True)
class LifetimeView:
    """Lifetime-population ratios, the fallback when no delta exists.

    Wraps one snapshot; division only ever pairs its own fields.
    """

    stats: NormalizedInterfaceStats

    def received_frames(self) -> int | None:
        if self.stats.input_packets is None or self.stats.input_errors is None:
            return None
        return self.stats.input_packets + self.stats.input_errors

    def error_ratio(self) -> RatioResult:
        return _ratio(
            self.stats.input_errors,
            self.received_frames(),
            "lifetime_input_errors / lifetime_received_frames",
        )

    def ratio_of(self, field_name: str) -> RatioResult:
        """Share of one lifetime bucket within lifetime received frames."""
        return _ratio(
            getattr(self.stats, field_name),
            self.received_frames(),
            f"lifetime_{field_name} / lifetime_received_frames",
        )

    def ratio_against_transmitted(self, field_name: str) -> RatioResult:
        """Share of one lifetime bucket within attempted transmissions —
        same add-back as the delta variant, on lifetime fields."""
        value = getattr(self.stats, field_name)
        attempted = (
            self.stats.output_packets + value
            if value is not None and self.stats.output_packets is not None
            else None
        )
        return _ratio(
            value, attempted, f"lifetime_{field_name} / lifetime_attempted_tx_frames"
        )

    def errors_per_second(self, window: IntervalEstimate | None) -> float | None:
        """Lifetime rate over the lifetime accumulation window (uptime or
        counter-clear age) — never over an observation window."""
        if self.stats.input_errors is None or window is None:
            return None
        if window.seconds <= 0:
            return None
        return self.stats.input_errors / window.seconds


@dataclass(frozen=True)
class CsvDelta:
    """The upstream CSV's own delta claim. Display and comparison only: it
    has no interval the tool measured, so it earns no rate methods."""

    counter: str
    change: int | None


def delta_sources_disagree(tool_delta: int, csv_delta: int) -> bool:
    """More-than-3x disagreement between the tool's delta and the CSV's.

    Both must be positive for a factor to mean anything; a zero on either
    side with a nonzero other side is also a disagreement.
    """
    if tool_delta < 0 or csv_delta < 0:
        return True
    if tool_delta == 0 or csv_delta == 0:
        return tool_delta != csv_delta
    factor = max(tool_delta, csv_delta) / min(tool_delta, csv_delta)
    return factor > DELTA_DISAGREEMENT_FACTOR


@dataclass(frozen=True)
class Reconciliation:
    """Result of verifying `input_errors == runts + Rcv-Err` on a platform
    with an aggregate receive-error column."""

    balanced: bool
    residual: int  # input_errors - (runts + rcv_err); 0 when balanced
    residual_fraction: float  # |residual| / input_errors


def reconcile_input_errors(
    stats: NormalizedInterfaceStats,
) -> Reconciliation | None:
    """Verify — never assume — the platform's error-total identity.

    None when any operand is missing (no reconciliation is possible, which
    the rules layer treats as its own data-quality condition).
    """
    if stats.input_errors is None or stats.runts is None or stats.rcv_err is None:
        return None
    expected = stats.runts + stats.rcv_err
    residual = stats.input_errors - expected
    if stats.input_errors > 0:
        fraction = abs(residual) / stats.input_errors
    else:
        fraction = 0.0 if residual == 0 else 1.0
    return Reconciliation(
        balanced=residual == 0, residual=residual, residual_fraction=fraction
    )


def unattributed_rx(stats: NormalizedInterfaceStats) -> int | None:
    """The aggregate receive-error column minus its named buckets — the
    symbol-error proxy on platforms without a symbol counter.

    Requires `rcv_err`, `fcs_errors`, and `align_errors`; `symbol_errors` is
    subtracted when the platform exposes it. Negative results mean the
    buckets overlap differently than assumed and are returned as-is for the
    reconciliation flag to catch.
    """
    if stats.rcv_err is None or stats.fcs_errors is None or stats.align_errors is None:
        return None
    residual = stats.rcv_err - stats.fcs_errors - stats.align_errors
    if stats.symbol_errors is not None:
        residual -= stats.symbol_errors
    return residual


def bytes_per_frame(stats: NormalizedInterfaceStats) -> float | None:
    """Lifetime bytes over lifetime packets — same population by design."""
    if not stats.input_packets or stats.bytes_input is None:
        return None
    return stats.bytes_input / stats.input_packets


def bytes_per_frame_exceeds_mtu(stats: NormalizedInterfaceStats) -> bool | None:
    """Average frame size above the MTU means the byte counter includes
    octets from errored frames — weak corroborating evidence of PHY-level
    errors, surfaced rather than silently ignored."""
    average = bytes_per_frame(stats)
    if average is None or stats.mtu is None or stats.mtu <= 0:
        return None
    return average > stats.mtu


def buffer_group_delta(window: DeltaWindow) -> int | None:
    """The congestion-side buckets: overrun + ignored + no buffer + input
    queue drops (`discards_in` on IOS-XE). None when all are unknown; known
    buckets sum even when others are missing, since each is a lower bound."""
    parts = [window.overrun, window.ignored, window.no_buffer, window.discards_in]
    known = [part for part in parts if part is not None]
    if not known:
        return None
    return sum(known)


def zero_traffic_test(window: DeltaWindow, later: NormalizedInterfaceStats) -> bool:
    """Errors advancing while effectively no valid frames arrive.

    True only when the error rate clears the floor AND traffic is absent by
    either measure: the device's own load-interval rate reads 0 pps, or the
    window's packet delta amounts to (almost) nothing. Missing inputs make
    the test False, never True — it may only ever add evidence.
    """
    errors_per_second = window.errors_per_second()
    if errors_per_second is None:
        return False
    if errors_per_second < ZERO_TRAFFIC_MIN_ERRORS_PER_SEC:
        return False
    if later.input_rate_pps == 0:
        return True
    packets_per_second = window.packets_per_second()
    return (
        packets_per_second is not None
        and packets_per_second < ZERO_TRAFFIC_MAX_PACKETS_PER_SEC
    )


def delta_field_names() -> tuple[str, ...]:
    """The lifetime fields `compute_delta_window` deltas, for callers that
    need to iterate them (reports, tests)."""
    return _DELTA_FIELDS


# Keep the dataclass field list and _DELTA_FIELDS in lockstep.
assert set(_DELTA_FIELDS) <= {f.name for f in fields(DeltaWindow)}
