"""Verdict engine — pure functions, no I/O.

Consumes ONLY the canonical NormalizedInterfaceStats model; never knows the
platform. Fail-closed rule: a failed parse or missing critical field NEVER
yields a clean verdict — missing data => PARSE_ERROR / UNVERIFIED, always.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from .config import Thresholds
from .models import (
    VERDICT_ORDER,
    InterfaceCase,
    NormalizedInterfaceStats,
    Verdict,
    VerdictCategory,
)


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

# Which stats field carries the counter value for each class (repoll deltas).
_VALUE_FIELD: dict[CounterClass, str] = {
    CounterClass.LATE_COLLISIONS: "late_collisions",
    CounterClass.RECEIVE_ERRORS: "input_errors",
    CounterClass.IN_DISCARDS: "discards_in",
    CounterClass.OUT_DISCARDS: "discards_out",
    CounterClass.TOTAL_TRAFFIC: "input_packets",
    CounterClass.GENERIC_ERRORS: "input_errors",
}


def _fmt_rate(rate: float) -> str:
    per_million = rate * 1_000_000
    return f"{rate * 100:.4f}% ({per_million:,.0f} per million frames)"


def _lifetime_rate(errors: int, packets: int) -> float | None:
    if packets and packets > 0:
        return errors / packets
    return None


def _repoll_delta(
    stats: NormalizedInterfaceStats, repoll: NormalizedInterfaceStats | None, field: str
) -> tuple[int, int] | None:
    """(counter_delta, packet_delta) between the two samples, or None."""
    if repoll is None:
        return None
    first_value, second_value = getattr(stats, field), getattr(repoll, field)
    first_packets, second_packets = stats.input_packets, repoll.input_packets
    if (
        first_value is None
        or second_value is None
        or first_packets is None
        or second_packets is None
    ):
        return None
    if second_value < first_value or second_packets < first_packets:
        return None  # counter reset between samples
    return (second_value - first_value, second_packets - first_packets)


def evaluate_case(
    case: InterfaceCase,
    stats: NormalizedInterfaceStats | None,
    repoll_stats: NormalizedInterfaceStats | None,
    repoll_minutes: float | None,
    thresholds: Thresholds,
    collection_error: str | None = None,
    parse_errors: Sequence[str] = (),
    member_stats: dict[str, NormalizedInterfaceStats] | None = None,
    member_repoll_stats: dict[str, NormalizedInterfaceStats] | None = None,
    member_errors: dict[str, str] | None = None,
    parent_portchannel: str | None = None,
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
                repoll_stats,
                repoll_minutes,
                thresholds,
                list(parse_errors),
                parent_portchannel,
                member_stats or {},
                member_repoll_stats or {},
                member_errors or {},
            )
        return _portchannel_verdict(
            case,
            stats,
            repoll_stats,
            repoll_minutes,
            thresholds,
            list(parse_errors),
            member_stats or {},
            member_repoll_stats or {},
            member_errors or {},
        )

    return _evaluate_stats(
        case.counter,
        stats,
        repoll_stats,
        repoll_minutes,
        thresholds,
        list(parse_errors),
    )


def _evaluate_stats(
    counter_name: str,
    stats: NormalizedInterfaceStats,
    repoll_stats: NormalizedInterfaceStats | None,
    repoll_minutes: float | None,
    thresholds: Thresholds,
    base_details: list[str],
) -> Verdict:
    """Single-interface verdict logic, shared by plain cases, the bundle-level
    view of a port-channel, and each of its members."""

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
    repoll_note = ""
    value_field = _VALUE_FIELD[cls]
    delta = _repoll_delta(stats, repoll_stats, value_field)
    flat = None
    rate = None
    rate_basis = ""

    if delta is not None:
        counter_delta, packet_delta = delta
        flat = counter_delta == 0
        mins = f"{repoll_minutes:g}" if repoll_minutes else "?"
        if flat:
            repoll_note = f"counter flat across {mins}-min re-poll"
        else:
            repoll_note = (
                f"counter still incrementing (+{counter_delta:,} in {mins} min)"
            )
        if packet_delta > 0 and counter_delta > 0:
            rate = counter_delta / packet_delta
            rate_basis = "live re-poll window"

    if rate is None:
        value = getattr(stats, value_field)
        lifetime = _lifetime_rate(value, stats.input_packets or 0)
        if lifetime is not None:
            rate = lifetime
            rate_basis = "lifetime counters"

    link_down = (stats.link_status or "").lower() != "up"
    if link_down:
        details.append(
            f"interface is currently {stats.link_status}/{stats.protocol_status or '?'}"
        )

    # ---- late collisions ---------------------------------------------------
    if cls is CounterClass.LATE_COLLISIONS:
        lc = stats.late_collisions
        if lc == 0 and (flat is None or flat):
            return Verdict(
                VerdictCategory.IGNORE,
                "IGNORE — device shows zero late collisions now (counter was "
                "likely reset since the Splunk sample). Re-flag if it "
                "reappears in next week's top-20.",
                details=details,
            )
        duplex = (stats.duplex or "").lower()
        neighbor_duplex = (stats.neighbor_duplex or "").lower()
        mismatch_logged = bool(stats.duplex_mismatch_logged)
        if duplex.startswith("full"):
            corroboration = ""
            if neighbor_duplex.startswith("half"):
                corroboration = (
                    f" Neighbor {stats.neighbor_name or '?'} reports "
                    "half-duplex — mismatch confirmed on both ends."
                )
            elif mismatch_logged:
                corroboration = " Device log confirms a CDP duplex-mismatch event."
            return Verdict(
                VerdictCategory.CONFIG_ISSUE,
                f"CONFIG_ISSUE — {lc:,} late collisions on a full-duplex link "
                "(impossible under CSMA/CD-free operation): duplex mismatch. "
                f"Fix via CLI, not by touching media.{corroboration}"
                + (f" {repoll_note.capitalize()}." if repoll_note else ""),
                details=details,
            )
        # Local half-duplex with the far end on full duplex (or the device
        # logging a duplex-mismatch event) is a confirmed mismatch, not a
        # legacy half-duplex segment.
        if neighbor_duplex.startswith("full") or mismatch_logged:
            evidence = (
                f"neighbor {stats.neighbor_name or '?'} reports full duplex"
                if neighbor_duplex.startswith("full")
                else "the device log records a CDP duplex-mismatch event"
            )
            return Verdict(
                VerdictCategory.CONFIG_ISSUE,
                f"CONFIG_ISSUE — {lc:,} late collisions on a half-duplex link "
                f"while {evidence}: duplex mismatch confirmed. Fix via CLI "
                "(align both ends), not by touching media."
                + (f" {repoll_note.capitalize()}." if repoll_note else ""),
                details=details,
            )
        return Verdict(
            VerdictCategory.PHYSICAL_MEDIA,
            f"PHYSICAL_MEDIA — {lc:,} late collisions on a "
            f"{stats.duplex}-duplex link: cable out of spec or failing NIC "
            "on a legacy segment. Inspect the physical path."
            + (f" {repoll_note.capitalize()}." if repoll_note else ""),
            details=details,
        )

    # ---- DOM out of range dominates receive-error analysis -----------------
    if cls in (CounterClass.RECEIVE_ERRORS, CounterClass.GENERIC_ERRORS):
        rx_dbm = stats.dom_rx_power_dbm
        if rx_dbm is not None and not (
            thresholds.dom_rx_low_dbm <= rx_dbm <= thresholds.dom_rx_high_dbm
        ):
            return Verdict(
                VerdictCategory.PHYSICAL_MEDIA,
                f"PHYSICAL_MEDIA — DOM receive power {rx_dbm:.1f} dBm is out "
                f"of range ({thresholds.dom_rx_low_dbm:g}.."
                f"{thresholds.dom_rx_high_dbm:g} dBm): degraded optical path "
                "(fiber, connector, or transceiver). Inspect the optical "
                "path." + (f" {repoll_note.capitalize()}." if repoll_note else ""),
                details=details,
            )

    # ---- rate-driven classes ----------------------------------------------
    if cls in (CounterClass.RECEIVE_ERRORS, CounterClass.GENERIC_ERRORS):
        crc = stats.crc_errors
        crc_note = (
            f" CRC/FCS accounts for {crc:,} of {stats.input_errors:,} input errors."
            if crc is not None and stats.input_errors
            else ""
        )
        dom_note = (
            f" DOM rx power {stats.dom_rx_power_dbm:.1f} dBm within range."
            if stats.dom_rx_power_dbm is not None
            else ""
        )
        if rate is None:
            return Verdict(
                VerdictCategory.IGNORE,
                "IGNORE — zero errors relative to traffic on the live device "
                "(counter likely reset or historical event)."
                + (f" {repoll_note.capitalize()}." if repoll_note else "")
                + dom_note,
                details=details,
            )
        if rate >= thresholds.rate_high and flat is not True:
            return Verdict(
                VerdictCategory.PHYSICAL_MEDIA,
                f"PHYSICAL_MEDIA — error rate {_fmt_rate(rate)} over "
                f"{rate_basis}: real receive errors at meaningful rate."
                f"{crc_note} Inspect cable/transceiver/path."
                + (f" {repoll_note.capitalize()}." if repoll_note else ""),
                details=details,
            )
        # Only reachable when the operator configures rate_warn below
        # rate_high: the shipped default puts rate_warn at 1% because
        # discards are its real consumer, which leaves this branch dormant.
        if rate >= thresholds.rate_warn and flat is False:
            return Verdict(
                VerdictCategory.PHYSICAL_MEDIA,
                f"PHYSICAL_MEDIA — moderate error rate {_fmt_rate(rate)} and "
                f"the counter is still incrementing now.{crc_note} "
                "Inspect cable/transceiver/path."
                + (f" {repoll_note.capitalize()}." if repoll_note else ""),
                details=details,
            )
        reason_bits = [
            f"error rate {_fmt_rate(rate)} over {rate_basis} is "
            "below the noise threshold"
        ]
        if repoll_note:
            reason_bits.append(repoll_note)
        return Verdict(
            VerdictCategory.IGNORE,
            "IGNORE — " + ", ".join(reason_bits) + f".{dom_note} No action.",
            details=details,
        )

    # ---- discards: capacity, not physical ----------------------------------
    if cls in (CounterClass.IN_DISCARDS, CounterClass.OUT_DISCARDS):
        direction = "input" if cls is CounterClass.IN_DISCARDS else "output"
        value = getattr(stats, value_field)
        if rate is not None and rate >= thresholds.rate_warn and flat is not True:
            return Verdict(
                VerdictCategory.CAPACITY,
                f"CAPACITY — {value:,} {direction} discards at "
                f"{_fmt_rate(rate)}: frames arrived intact and were dropped "
                "(buffer congestion, VLAN not allowed on trunk, or ACL). Not "
                "a physical error — escalate as capacity/config, not media."
                + (f" {repoll_note.capitalize()}." if repoll_note else ""),
                details=details,
            )
        return Verdict(
            VerdictCategory.IGNORE,
            f"IGNORE — {direction} discards at negligible rate"
            + (f" ({_fmt_rate(rate)})" if rate is not None else "")
            + (f", {repoll_note}" if repoll_note else "")
            + ". No action.",
            details=details,
        )

    # Unreachable, but keep fail-closed semantics.
    return Verdict(
        VerdictCategory.PARSE_ERROR,
        f"PARSE_ERROR — counter {counter_name!r} could not be classified. "
        "Refusing to guess (fail closed).",
        details=details,
    )


# Verdicts that demand action; a member showing one is the bundle's culprit.
_ACTIONABLE = (
    VerdictCategory.PHYSICAL_MEDIA,
    VerdictCategory.CONFIG_ISSUE,
    VerdictCategory.CAPACITY,
)


def _member_findings(
    counter_name: str,
    repoll_minutes: float | None,
    thresholds: Thresholds,
    member_stats: dict[str, NormalizedInterfaceStats],
    member_repoll_stats: dict[str, NormalizedInterfaceStats],
    member_errors: dict[str, str],
) -> tuple[dict[str, Verdict], dict[str, str]]:
    """Evaluate every sampled member; return their verdicts and one-line
    findings, with uncollectable members spelled out rather than omitted."""
    verdicts = {
        name: _evaluate_stats(
            counter_name,
            stats,
            member_repoll_stats.get(name),
            repoll_minutes,
            thresholds,
            [],
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
    repoll_stats: NormalizedInterfaceStats | None,
    repoll_minutes: float | None,
    thresholds: Thresholds,
    parse_errors: list[str],
    parent_portchannel: str,
    member_stats: dict[str, NormalizedInterfaceStats],
    member_repoll_stats: dict[str, NormalizedInterfaceStats],
    member_errors: dict[str, str],
) -> Verdict:
    """Judge a case that is a member of a port-channel.

    The CSV asked about this interface, so the verdict is this interface's own
    — identical to the plain single-interface path. Its sibling members were
    sampled because a LAG fault often sits on a neighbouring link, but they are
    context only: a dirty or uncollectable sibling never changes the category
    of the port that was actually reported.
    """
    verdict = _evaluate_stats(
        case.counter, stats, repoll_stats, repoll_minutes, thresholds, parse_errors
    )
    _, findings = _member_findings(
        case.counter,
        repoll_minutes,
        thresholds,
        member_stats,
        member_repoll_stats,
        member_errors,
    )
    verdict.details.append(
        f"member of port-channel {parent_portchannel}: the members listed are "
        f"context; the verdict is for {case.interface} itself"
    )
    verdict.member_findings = findings
    return verdict


def _portchannel_verdict(
    case: InterfaceCase,
    stats: NormalizedInterfaceStats,
    repoll_stats: NormalizedInterfaceStats | None,
    repoll_minutes: float | None,
    thresholds: Thresholds,
    parse_errors: list[str],
    member_stats: dict[str, NormalizedInterfaceStats],
    member_repoll_stats: dict[str, NormalizedInterfaceStats],
    member_errors: dict[str, str],
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
        repoll_minutes,
        thresholds,
        member_stats,
        member_repoll_stats,
        member_errors,
    )

    bundle = _evaluate_stats(
        case.counter,
        stats,
        repoll_stats,
        repoll_minutes,
        thresholds,
        list(parse_errors),
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
        )

    # No culpable member, every member evaluable: the bundle-level verdict
    # stands (IGNORE when clean; PARSE_ERROR keeps failing closed).
    bundle.member_findings = findings
    return bundle
