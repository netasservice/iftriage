"""Verdict engine tests — including the fail-closed PARSE_ERROR behavior and
the v2 ladder (verdict + confidence + signals)."""

from datetime import UTC, datetime

from iftriage.config import Thresholds
from iftriage.models import (
    Confidence,
    DataQualityKind,
    InterfaceCase,
    NormalizedInterfaceStats,
    SignalKind,
    VerdictCategory,
)
from iftriage.rules import (
    CounterClass,
    apply_caps,
    classify_counter,
    evaluate_case,
    format_window,
)

T = Thresholds()
REPORT_TIME = datetime(2026, 9, 1, 17, 53, tzinfo=UTC)


def make_case(counter="Rcv-Err", change=1000):
    return InterfaceCase(
        poll_time="2026-08-24T03:12:00",
        switch="sw-a",
        mgmt_ip="10.0.0.1",
        interface="Gi3/0/20",
        description="",
        status="up",
        protocol="up",
        counter=counter,
        prev_count=0,
        count=change,
        change=change,
        row_index=0,
    )


def make_stats(**kwargs):
    defaults = dict(
        link_status="up",
        protocol_status="up",
        duplex="full",
        input_packets=1_000_000,
        input_errors=0,
        crc_errors=0,
        late_collisions=0,
        discards_in=0,
        discards_out=0,
        collisions=0,
        runts=0,
        giants=0,
        # A known epoch: cleared a day ago, so a single sample still supports
        # a lifetime rate (capped MEDIUM by the missing second observation).
        counters_never_cleared=False,
        last_clearing_minutes=1440.0,
    )
    defaults.update(kwargs)
    return NormalizedInterfaceStats(**defaults)


def run(case, stats, baseline=None, minutes=None, error=None, parse_errors=()):
    """`stats` is the fresh sample; `baseline` is the EARLIER one, from a
    previous run. The delta runs baseline -> stats, so the larger counter is
    always the one passed as `stats`."""
    return evaluate_case(
        case,
        stats,
        baseline,
        minutes,
        T,
        collection_error=error,
        parse_errors=parse_errors,
    )


def signal_kinds(verdict):
    return {signal.kind for signal in verdict.signals}


def flag_kinds(verdict):
    return {flag.kind for flag in verdict.data_quality}


# ---- classification --------------------------------------------------------


def test_counter_classification():
    assert classify_counter("Rcv-Err") is CounterClass.RECEIVE_ERRORS
    assert classify_counter("late-col") is CounterClass.LATE_COLLISIONS
    assert classify_counter("InDiscards") is CounterClass.IN_DISCARDS
    assert classify_counter("OutDiscards") is CounterClass.OUT_DISCARDS
    assert classify_counter("Rx") is CounterClass.TOTAL_TRAFFIC
    assert classify_counter("weird-new-counter") is CounterClass.GENERIC_ERRORS


# ---- fail-closed guarantees (unchanged by v2) ------------------------------


def test_unreachable_device_is_unverified():
    verdict = run(make_case(), None, error="connection timed out")
    assert verdict.category is VerdictCategory.UNVERIFIED


def test_missing_crc_is_parse_error_never_ignore():
    stats = make_stats(crc_errors=None)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.PARSE_ERROR
    assert "crc_errors" in verdict.reason


def test_missing_duplex_on_late_col_is_parse_error():
    stats = make_stats(duplex=None, late_collisions=5)
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.PARSE_ERROR


def test_no_stats_at_all_is_parse_error():
    verdict = run(make_case(), None, parse_errors=["interface: no match"])
    assert verdict.category is VerdictCategory.PARSE_ERROR
    assert verdict.details == ["interface: no match"]


# ---- late collisions / negotiation -----------------------------------------


def test_late_col_on_full_duplex_is_link_negotiation():
    stats = make_stats(late_collisions=773)
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.LINK_NEGOTIATION
    assert verdict.confidence is Confidence.MEDIUM  # single observation
    assert SignalKind.LATE_COLLISIONS_FULL_DUPLEX in signal_kinds(verdict)


def test_late_col_full_duplex_with_second_observation_is_high():
    earlier = make_stats(late_collisions=100)
    stats = make_stats(late_collisions=773)
    verdict = run(make_case("Late-Col"), stats, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.LINK_NEGOTIATION
    assert verdict.confidence is Confidence.HIGH


def test_late_col_on_half_duplex_is_physical():
    stats = make_stats(duplex="half", late_collisions=773)
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA


def test_late_col_half_duplex_with_full_duplex_neighbor_is_link_negotiation():
    stats = make_stats(
        duplex="half",
        late_collisions=773,
        neighbor_name="ap-floor2",
        neighbor_duplex="full",
    )
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.LINK_NEGOTIATION
    assert "duplex_mismatch_confirmed" in verdict.reason


def test_late_col_half_duplex_with_logged_mismatch_is_link_negotiation():
    stats = make_stats(duplex="half", late_collisions=773, duplex_mismatch_logged=True)
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.LINK_NEGOTIATION


def test_late_col_zero_on_device_is_ignore():
    verdict = run(make_case("Late-Col"), make_stats(late_collisions=0))
    assert verdict.category is VerdictCategory.IGNORE


def test_late_col_flat_across_observations_is_historic():
    earlier = make_stats(late_collisions=773)
    stats = make_stats(late_collisions=773)
    verdict = run(make_case("Late-Col"), stats, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.HISTORIC_NOT_ACTIVE


# ---- receive errors: the core ladder ---------------------------------------


def test_high_crc_rate_is_physical_media():
    stats = make_stats(input_errors=3271, crc_errors=3271, input_packets=1_000_000)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    # Single observation: the missing second sample caps MEDIUM.
    assert verdict.confidence is Confidence.MEDIUM
    assert DataQualityKind.NO_SECOND_OBSERVATION in flag_kinds(verdict)


def test_negligible_rate_is_ignore():
    stats = make_stats(input_errors=5, crc_errors=5, input_packets=1_000_000_000)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.IGNORE


def test_flat_counter_with_large_lifetime_is_historic_not_active():
    """A never-cleared counter with millions of errors and zero movement is
    not an incident, regardless of how large the lifetime figure is."""
    earlier = make_stats(input_errors=5_000, crc_errors=5_000, input_packets=1_000_000)
    flat = make_stats(input_errors=5_000, crc_errors=5_000, input_packets=1_100_000)
    verdict = run(make_case("Rcv-Err"), flat, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.HISTORIC_NOT_ACTIVE
    assert SignalKind.ZERO_DELTA_NONZERO_LIFETIME in signal_kinds(verdict)


def test_climbing_counter_at_rate_is_physical():
    earlier = make_stats(input_errors=5_000, crc_errors=5_000, input_packets=1_000_000)
    climbing = make_stats(input_errors=5_600, crc_errors=5_600, input_packets=1_100_000)
    verdict = run(make_case("Rcv-Err"), climbing, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA


def test_a_discarded_baseline_never_vetoes_escalation():
    """A counter that went BACKWARDS (clear/reload) yields no delta — and no
    delta must never read as flat."""
    earlier = make_stats(input_errors=9_999, crc_errors=9_999, input_packets=2_000_000)
    current = make_stats(input_errors=3_271, crc_errors=3_271, input_packets=1_000_000)
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert verdict.category is not VerdictCategory.HISTORIC_NOT_ACTIVE
    assert any("discarded" in detail for detail in verdict.details)


def test_missing_baseline_still_escalates_on_lifetime_rate():
    stats = make_stats(input_errors=3_271, crc_errors=3_271, input_packets=1_000_000)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert verdict.confidence is Confidence.MEDIUM


def test_never_cleared_single_sample_is_insufficient_data():
    """Only a never-cleared lifetime figure and no second observation:
    nothing says whether a single error happened this month."""
    stats = make_stats(
        input_errors=316_073_999,
        crc_errors=185,
        input_packets=561_806,
        counters_never_cleared=True,
        last_clearing_minutes=None,
        uptime_minutes=417_731.0,
    )
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.INSUFFICIENT_DATA
    assert verdict.confidence is None


def test_zero_traffic_test_is_physical_high():
    earlier = make_stats(
        input_errors=319_466_596,
        crc_errors=185,
        input_packets=561_806,
        input_rate_pps=0,
    )
    current = make_stats(
        input_errors=320_792_846,
        crc_errors=185,
        input_packets=561_806,
        input_rate_pps=0,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=int(39.8 * 60))
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert verdict.confidence is Confidence.HIGH
    assert SignalKind.ZERO_TRAFFIC_ERRORS in signal_kinds(verdict)


def test_zero_traffic_with_confirmed_duplex_mismatch_is_link_negotiation():
    # A half-duplex port whose CDP neighbor reports full duplex, with late
    # collisions advancing alongside the receive errors: the errors accumulate
    # without traffic, but the link includes its negotiation — the mismatch,
    # not the medium, is the verdict.
    earlier = make_stats(
        input_errors=426_000_000,
        crc_errors=2,
        input_packets=80_914_346,
        input_rate_pps=0,
        duplex="half",
        neighbor_duplex="full",
        neighbor_name="phone-fake-01",
        collisions=160_000,
        late_collisions=80_000,
    )
    current = make_stats(
        input_errors=429_895_397,
        crc_errors=2,
        input_packets=80_914_346,
        input_rate_pps=0,
        duplex="half",
        neighbor_duplex="full",
        neighbor_name="phone-fake-01",
        collisions=161_390,
        late_collisions=87_896,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=int(18.4 * 60))
    assert verdict.category is VerdictCategory.LINK_NEGOTIATION
    assert verdict.confidence is Confidence.HIGH
    assert "duplex_mismatch_confirmed" in verdict.reason
    # The zero-traffic observation stays as evidence for the reader.
    assert SignalKind.ZERO_TRAFFIC_ERRORS in signal_kinds(verdict)
    assert SignalKind.LATE_COLLISIONS_FULL_DUPLEX in signal_kinds(verdict)


def test_zero_traffic_with_collisions_but_no_duplex_evidence_is_not_high():
    # Collision activity without a confirming neighbor: the media reading may
    # still win, but never as a HIGH zero-traffic claim that ignores the
    # collisions.
    earlier = make_stats(
        input_errors=426_000_000,
        crc_errors=2,
        input_packets=80_914_346,
        input_rate_pps=0,
        duplex="half",
        collisions=160_000,
        late_collisions=80_000,
    )
    current = make_stats(
        input_errors=429_895_397,
        crc_errors=2,
        input_packets=80_914_346,
        input_rate_pps=0,
        duplex="half",
        collisions=161_390,
        late_collisions=87_896,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=int(18.4 * 60))
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert verdict.confidence is not Confidence.HIGH
    assert "zero_traffic_errors" not in verdict.reason
    assert SignalKind.ZERO_TRAFFIC_ERRORS in signal_kinds(verdict)


def test_zero_traffic_with_unknown_collision_counters_caps_medium():
    # The guard cannot run when the collision counters were not parsed; the
    # zero-traffic verdict stands but says so and gives up HIGH.
    earlier = make_stats(
        input_errors=319_466_596,
        crc_errors=185,
        input_packets=561_806,
        input_rate_pps=0,
        collisions=None,
        late_collisions=None,
    )
    current = make_stats(
        input_errors=320_792_846,
        crc_errors=185,
        input_packets=561_806,
        input_rate_pps=0,
        collisions=None,
        late_collisions=None,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=int(39.8 * 60))
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert verdict.confidence is Confidence.MEDIUM
    assert "zero_traffic_errors" in verdict.reason
    assert DataQualityKind.NULL_RULE_INPUT in flag_kinds(verdict)


def test_buffer_group_dominant_is_congestion_not_physical():
    earlier = make_stats(input_errors=0, crc_errors=0, overrun=0, ignored=0)
    current = make_stats(
        input_errors=90_000,
        crc_errors=100,
        input_packets=1_400_000,
        overrun=60_000,
        ignored=25_000,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.CONGESTION_BUFFER
    assert SignalKind.BUFFER_GROUP_DOMINANT in signal_kinds(verdict)


def test_unattributed_rx_dominant_is_physical_high():
    earlier = make_stats(
        input_errors=100_000,
        crc_errors=100,
        rcv_err=95_000,
        fcs_errors=100,
        align_errors=0,
        runts=5_000,
    )
    current = make_stats(
        input_errors=200_000,
        crc_errors=185,
        rcv_err=190_000,
        fcs_errors=185,
        align_errors=0,
        runts=10_000,
        input_packets=1_200_000,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert verdict.confidence is Confidence.HIGH
    assert SignalKind.UNATTRIBUTED_RX_DOMINANT in signal_kinds(verdict)
    # The 185 FCS belongs under "evidence against", with the verdict retained.
    against = [signal for signal in verdict.signals if signal.contradicts]
    assert any(
        signal.kind is SignalKind.LOW_FCS_DOES_NOT_CLEAR_MEDIA for signal in against
    )


def test_reconciliation_residual_above_one_percent_caps_low():
    # input_errors != runts + rcv_err by 5%.
    current = make_stats(
        input_errors=200_000,
        crc_errors=185,
        rcv_err=180_000,
        fcs_errors=185,
        align_errors=0,
        runts=10_000,
        input_packets=1_200_000,
    )
    earlier = make_stats(
        input_errors=100_000,
        crc_errors=100,
        rcv_err=90_000,
        fcs_errors=100,
        align_errors=0,
        runts=5_000,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=1080)
    assert DataQualityKind.COUNTER_RECONCILIATION_FAILED in flag_kinds(verdict)
    assert verdict.confidence is Confidence.LOW


def test_giants_dominant_is_link_negotiation():
    earlier = make_stats(input_errors=1_000, crc_errors=0, giants=900)
    current = make_stats(
        input_errors=61_000,
        crc_errors=100,
        giants=55_000,
        input_packets=1_400_000,
        mtu=1500,
    )
    verdict = run(make_case("Rcv-Err"), current, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.LINK_NEGOTIATION
    assert verdict.confidence is Confidence.MEDIUM
    assert SignalKind.GIANTS_WITH_MTU_MISMATCH in signal_kinds(verdict)


def test_speed_below_capability_is_corroborating_only():
    """100M on a gig-capable copper port must never carry a verdict alone."""
    clean = make_stats(speed="100Mb/s", media_type="10/100/1000BaseTX")
    verdict = run(make_case("Rcv-Err"), clean)
    assert verdict.category is VerdictCategory.IGNORE

    dirty = make_stats(
        input_errors=3_271,
        crc_errors=3_271,
        input_packets=1_000_000,
        speed="100Mb/s",
        media_type="10/100/1000BaseTX",
    )
    escalated = run(make_case("Rcv-Err"), dirty)
    assert escalated.category is VerdictCategory.PHYSICAL_MEDIA
    speed_signals = [
        signal
        for signal in escalated.signals
        if signal.kind is SignalKind.SPEED_BELOW_CAPABILITY
    ]
    assert speed_signals and speed_signals[0].weight is Confidence.LOW


def test_dom_out_of_range_is_physical_media():
    stats = make_stats(input_errors=100, crc_errors=100, dom_rx_power_dbm=-18.0)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert SignalKind.DOM_RX_OUT_OF_RANGE in signal_kinds(verdict)


def test_no_division_when_everything_is_zero():
    stats = make_stats(input_packets=0, input_errors=0, crc_errors=0)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.IGNORE
    assert verdict.metrics is not None
    assert verdict.metrics.error_ratio is None


def test_delta_source_disagreement_is_flagged():
    earlier = make_stats(input_errors=0, crc_errors=0)
    current = make_stats(
        input_errors=1_326_250, crc_errors=185, input_packets=1_000_100
    )
    verdict = run(make_case("Rcv-Err", change=112_905), current, earlier, minutes=2388)
    assert DataQualityKind.DELTA_SOURCE_DISAGREEMENT in flag_kinds(verdict)
    assert verdict.metrics.delta_tool == 1_326_250
    assert verdict.metrics.delta_csv == 112_905


def test_stale_poll_is_flagged_but_does_not_cap_a_delta_verdict():
    earlier = make_stats(input_errors=0, crc_errors=0, input_rate_pps=0)
    current = make_stats(input_errors=1_326_250, crc_errors=185, input_rate_pps=0)
    verdict = evaluate_case(
        make_case("Rcv-Err"),
        current,
        earlier,
        2388,
        T,
        report_time=REPORT_TIME,  # poll_time is 2026-08-24: ~8.6 d stale
    )
    assert DataQualityKind.STALE_POLL_TIMESTAMP in flag_kinds(verdict)
    assert verdict.confidence is Confidence.HIGH  # tool's own delta decided


def test_apply_caps_ranking():
    from iftriage.models import DataQualityFlag

    assert (
        apply_caps(
            Confidence.HIGH,
            [DataQualityFlag(DataQualityKind.NO_SECOND_OBSERVATION)],
        )
        is Confidence.MEDIUM
    )
    assert (
        apply_caps(
            Confidence.HIGH,
            [
                DataQualityFlag(
                    DataQualityKind.COUNTER_RECONCILIATION_FAILED,
                    {"residual_fraction": 0.05},
                )
            ],
        )
        is Confidence.LOW
    )
    assert (
        apply_caps(
            Confidence.LOW,
            [DataQualityFlag(DataQualityKind.NO_SECOND_OBSERVATION)],
        )
        is Confidence.LOW
    )


def test_format_window_uses_the_largest_readable_unit():
    assert format_window(45) == "45 min"
    assert format_window(1080) == "18.0 h"
    assert format_window(4320) == "3.0 d"
    assert format_window(None) == "?"


# ---- discards: congestion, not physical ------------------------------------


def test_indiscards_at_rate_is_congestion_buffer_not_physical():
    stats = make_stats(discards_in=200_000, input_packets=1_000_000)
    verdict = run(make_case("InDiscards"), stats)
    assert verdict.category is VerdictCategory.CONGESTION_BUFFER


def test_discards_below_the_threshold_is_ignore():
    stats = make_stats(discards_in=50, input_packets=1_000_000)
    verdict = run(make_case("InDiscards"), stats)
    assert verdict.category is VerdictCategory.IGNORE


def test_flat_discards_are_historic():
    earlier = make_stats(discards_out=223_462)
    stats = make_stats(discards_out=223_462, input_packets=1_100_000)
    verdict = run(make_case("OutDiscards"), stats, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.HISTORIC_NOT_ACTIVE


def test_outdiscards_rate_uses_the_output_side_denominator():
    """The old engine divided output discards by INPUT packets, which is how
    a >100% rate gets printed. The output side must be its own population."""
    earlier = make_stats(discards_out=0, output_packets=1_000, input_packets=40)
    stats = make_stats(discards_out=900, output_packets=1_500, input_packets=41)
    verdict = run(make_case("OutDiscards"), stats, earlier, minutes=1080)
    assert verdict.category is VerdictCategory.CONGESTION_BUFFER
    # 900 discards over (500 delivered + 900 dropped) = 64%, never >100%.


def test_rx_counter_is_ignore():
    verdict = run(make_case("Rx"), make_stats())
    assert verdict.category is VerdictCategory.IGNORE
    assert "not an error" in verdict.reason.lower()


# ---- port-channel member triage --------------------------------------------


def po_case(counter="Rcv-Err"):
    case = make_case(counter=counter)
    case.interface = "Po214"
    return case


def run_po(
    case,
    stats,
    member_stats,
    member_errors=None,
    member_baseline=None,
    baseline=None,
    minutes=None,
):
    return evaluate_case(
        case,
        stats,
        baseline,
        minutes,
        T,
        member_stats=member_stats,
        member_baseline_stats=member_baseline or {},
        member_errors=member_errors or {},
    )


def test_po_fault_is_isolated_to_the_bad_member():
    """Bundle counters are sums across members: the bad member's rate is
    diluted below the noise threshold on the bundle, but not on the member."""
    bundle = make_stats(input_errors=1000, crc_errors=1000, input_packets=200_000_000)
    bad = make_stats(input_errors=1000, crc_errors=1000, input_packets=1_000_000)
    good = make_stats(input_packets=100_000_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet3/0/23": bad, "GigabitEthernet3/0/24": good},
    )

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "fault isolated to member GigabitEthernet3/0/23" in verdict.reason
    assert verdict.member_findings["GigabitEthernet3/0/24"].startswith("IGNORE")


def test_po_member_with_dom_out_of_range_is_physical_media():
    bundle = make_stats(input_errors=100, crc_errors=100, input_packets=200_000_000)
    bad_optic = make_stats(
        input_errors=100,
        crc_errors=100,
        input_packets=1_000_000,
        dom_rx_power_dbm=-18.0,
    )

    verdict = run_po(po_case(), bundle, {"Ethernet1/1": bad_optic})

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "Ethernet1/1" in verdict.reason
    assert SignalKind.DOM_RX_OUT_OF_RANGE in signal_kinds(verdict)


def test_po_member_baseline_delta_confirms_live_errors():
    bundle = make_stats(input_errors=100, crc_errors=100, input_packets=200_000_000)
    earlier = make_stats(input_errors=100, crc_errors=100, input_packets=1_000_000)
    current = make_stats(input_errors=200, crc_errors=200, input_packets=1_050_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet1/0/1": current},
        member_baseline={"GigabitEthernet1/0/1": earlier},
        minutes=1080,
    )

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    # An FCS-dominant profile with an active delta is MEDIUM by design:
    # frames arriving but corrupted reads as marginal signal, not link-level.
    assert verdict.confidence is Confidence.MEDIUM


def test_po_missing_member_fails_closed_to_parse_error():
    bundle = make_stats()
    good = make_stats(input_packets=100_000_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet1/0/1": good},
        member_errors={"GigabitEthernet1/0/2": "member collection failed: timed out"},
    )

    assert verdict.category is VerdictCategory.PARSE_ERROR
    assert "GigabitEthernet1/0/2" in verdict.reason
    assert verdict.member_findings["GigabitEthernet1/0/2"].startswith("not evaluated")


def test_po_bundle_errors_with_clean_members_degrade_gracefully():
    bundle = make_stats(input_errors=5000, crc_errors=5000, input_packets=1_000_000)
    clean = make_stats(input_packets=100_000_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet1/0/1": clean, "GigabitEthernet1/0/2": clean},
    )

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "no current member" in verdict.reason
    assert "since-removed member" in verdict.reason


def test_po_all_clean_is_ignore_with_the_member_breakdown():
    bundle = make_stats(input_packets=100_000_000)
    clean = make_stats(input_packets=50_000_000)

    verdict = run_po(po_case(), bundle, {"GigabitEthernet1/0/1": clean})

    assert verdict.category is VerdictCategory.IGNORE
    assert verdict.member_findings["GigabitEthernet1/0/1"].startswith("IGNORE")


def test_po_with_traffic_counter_stays_ignore_even_with_member_data():
    verdict = run_po(
        po_case(counter="Rx"), make_stats(), {"GigabitEthernet1/0/1": make_stats()}
    )

    assert verdict.category is VerdictCategory.IGNORE
    assert "total traffic counter" in verdict.reason


def test_po_without_member_data_matches_the_single_interface_verdict():
    """Regression guard: an empty bundle / unparsed summary keeps today's path."""
    bundle = make_stats(input_errors=1000, crc_errors=1000, input_packets=1_000_000)

    plain = run(po_case(), bundle)
    with_empty_members = run_po(po_case(), bundle, {})

    assert with_empty_members.category is plain.category
    assert with_empty_members.reason == plain.reason


# ---- a case that is itself a member of a bundle ----------------------------


def member_case(counter="Rcv-Err"):
    case = make_case(counter=counter)
    case.interface = "Et4/15"
    return case


def run_member(case, stats, siblings, member_errors=None):
    return evaluate_case(
        case,
        stats,
        None,
        None,
        T,
        member_stats=siblings,
        member_errors=member_errors or {},
        parent_portchannel="Po195",
    )


def test_member_case_keeps_its_own_verdict_and_lists_siblings():
    """The CSV asked about Et4/15: a dirty sibling is context, not the answer."""
    own = make_stats(input_packets=100_000_000)
    dirty_sibling = make_stats(
        input_errors=1000, crc_errors=1000, input_packets=1_000_000
    )

    verdict = run_member(member_case(), own, {"Ethernet4/16": dirty_sibling})

    assert verdict.category is VerdictCategory.IGNORE
    assert "Ethernet4/16" not in verdict.reason
    assert verdict.member_findings["Ethernet4/16"].startswith("PHYSICAL_MEDIA")
    assert any("member of port-channel Po195" in d for d in verdict.details)


def test_member_case_verdict_matches_the_plain_single_interface_path():
    own = make_stats(input_errors=1000, crc_errors=1000, input_packets=1_000_000)
    case = member_case()

    plain = evaluate_case(case, own, None, None, T)
    with_siblings = run_member(case, own, {"Ethernet4/16": make_stats()})

    assert with_siblings.category is plain.category
    assert with_siblings.reason == plain.reason


def test_uncollectable_sibling_does_not_fail_a_member_case_closed():
    """Contrast with the bundle path, where an unevaluable member is fatal:
    here the reported interface was collected, so it keeps its own answer."""
    own = make_stats(input_packets=100_000_000)

    verdict = run_member(
        member_case(),
        own,
        {},
        member_errors={"Ethernet4/16": "member collection failed: timed out"},
    )

    assert verdict.category is VerdictCategory.IGNORE
    assert verdict.member_findings["Ethernet4/16"].startswith("not evaluated:")
