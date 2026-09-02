"""Population-safe counter math. Pure logic, zero device access."""

import pytest

from iftriage.metrics import (
    RATIO_OUT_OF_RANGE,
    CsvDelta,
    LifetimeView,
    buffer_group_delta,
    bytes_per_frame,
    bytes_per_frame_exceeds_mtu,
    compute_delta_window,
    delta_sources_disagree,
    reconcile_input_errors,
    unattributed_rx,
    zero_traffic_test,
)
from iftriage.models import NormalizedInterfaceStats
from iftriage.timebase import IntervalEstimate, IntervalSource

HOST_WINDOW = IntervalEstimate(39.8 * 60, IntervalSource.HOST_INGEST_TIME)


def golden_stats() -> NormalizedInterfaceStats:
    """The Gi8/0/4 reference case (see the golden fixtures)."""
    return NormalizedInterfaceStats(
        input_packets=561806,
        bytes_input=87262523986,
        input_errors=320792846,
        crc_errors=185,
        fcs_errors=185,
        align_errors=0,
        runts=4718847,
        giants=0,
        undersize=0,
        rcv_err=316073999,
        overrun=0,
        ignored=0,
        no_buffer=0,
        discards_in=0,
        discards_out=0,
        collisions=0,
        late_collisions=0,
        mtu=9160,
        media_type="10/100/1000BaseTX",
        input_rate_pps=0,
        load_interval_seconds=30,
        counters_never_cleared=True,
    )


# ---- reconciliation and the unattributed residual --------------------------


def test_golden_reconciliation_balances():
    outcome = reconcile_input_errors(golden_stats())
    assert outcome is not None
    assert outcome.balanced
    assert outcome.residual == 0
    assert 4718847 + 316073999 == 320792846


def test_golden_unattributed_rx():
    assert unattributed_rx(golden_stats()) == 316073814


def test_unattributed_rx_prefers_subtracting_symbol_when_present():
    stats = golden_stats()
    stats.symbol_errors = 1000
    assert unattributed_rx(stats) == 316073814 - 1000


def test_unattributed_rx_requires_named_buckets():
    stats = golden_stats()
    stats.fcs_errors = None
    assert unattributed_rx(stats) is None


def test_reconciliation_residual_fraction():
    stats = NormalizedInterfaceStats(
        input_errors=100, runts=45, rcv_err=50
    )  # residual 5 = 5%
    outcome = reconcile_input_errors(stats)
    assert outcome is not None
    assert not outcome.balanced
    assert outcome.residual == 5
    assert outcome.residual_fraction == pytest.approx(0.05)


def test_reconciliation_none_when_operand_missing():
    assert reconcile_input_errors(NormalizedInterfaceStats(input_errors=10)) is None


# ---- delta construction ----------------------------------------------------


def test_delta_window_per_field_reset_protection():
    earlier = NormalizedInterfaceStats(
        input_packets=100, input_errors=500, runts=10, crc_errors=None
    )
    later = NormalizedInterfaceStats(
        input_packets=150, input_errors=400, runts=25, crc_errors=7
    )
    window = compute_delta_window(earlier, later, HOST_WINDOW)
    assert window.input_packets == 50
    assert window.runts == 15
    assert window.input_errors is None  # went backwards: cleared, not flat
    assert window.crc_errors is None  # missing on one side stays unknown


def test_golden_rates():
    earlier = NormalizedInterfaceStats(input_packets=561806, input_errors=319466596)
    later = golden_stats()
    window = compute_delta_window(earlier, later, HOST_WINDOW)
    assert window.input_errors == 1326250
    assert window.errors_per_second() == pytest.approx(9.26, abs=0.01)
    assert window.errors_per_hour() == pytest.approx(1326250 / 39.8, rel=1e-6)


def test_no_division_when_zero_everything():
    earlier = NormalizedInterfaceStats(input_packets=0, input_errors=0)
    later = NormalizedInterfaceStats(input_packets=0, input_errors=0)
    window = compute_delta_window(earlier, later, HOST_WINDOW)
    outcome = window.error_ratio()
    assert outcome.value is None
    assert outcome.flag is None  # nothing to divide, nothing to flag


def test_ratio_out_of_range_is_flagged_not_returned():
    window = compute_delta_window(
        NormalizedInterfaceStats(input_packets=100, input_errors=0, discards_out=1000),
        NormalizedInterfaceStats(input_packets=140, input_errors=0, discards_out=6000),
        HOST_WINDOW,
    )
    outcome = window.ratio_of("discards_out")
    assert outcome.value is None
    assert outcome.flag == RATIO_OUT_OF_RANGE
    assert "discards_out" in (outcome.detail or "")


def test_rate_of_follows_the_named_field():
    window = compute_delta_window(
        NormalizedInterfaceStats(late_collisions=57_507_585, input_errors=1),
        NormalizedInterfaceStats(late_collisions=58_462_998, input_errors=1),
        HOST_WINDOW,
    )
    assert window.rate_of("late_collisions") == pytest.approx(
        955_413 / HOST_WINDOW.seconds
    )
    assert window.rate_of("input_errors") == 0.0


def test_ratio_against_transmitted_adds_the_lost_frames_back():
    window = compute_delta_window(
        NormalizedInterfaceStats(late_collisions=0, output_packets=0),
        NormalizedInterfaceStats(late_collisions=400, output_packets=600),
        HOST_WINDOW,
    )
    outcome = window.ratio_against_transmitted("late_collisions")
    assert outcome.value == pytest.approx(0.4)


def test_ratio_against_transmitted_without_output_packets_is_undefined():
    window = compute_delta_window(
        NormalizedInterfaceStats(late_collisions=0),
        NormalizedInterfaceStats(late_collisions=400),
        HOST_WINDOW,
    )
    outcome = window.ratio_against_transmitted("late_collisions")
    assert outcome.value is None
    assert outcome.flag is None


def test_error_ratio_uses_received_frames_denominator():
    window = compute_delta_window(
        NormalizedInterfaceStats(input_packets=0, input_errors=0),
        NormalizedInterfaceStats(input_packets=40, input_errors=960),
        HOST_WINDOW,
    )
    assert window.received_frames() == 1000
    outcome = window.error_ratio()
    assert outcome.value == pytest.approx(0.96)


# ---- zero-traffic test -----------------------------------------------------


def test_golden_zero_traffic_test_passes():
    earlier = NormalizedInterfaceStats(input_packets=561806, input_errors=319466596)
    later = golden_stats()
    window = compute_delta_window(earlier, later, HOST_WINDOW)
    assert zero_traffic_test(window, later) is True


def test_zero_traffic_needs_the_rate_floor():
    earlier = NormalizedInterfaceStats(input_packets=0, input_errors=0)
    later = NormalizedInterfaceStats(
        input_packets=0, input_errors=100, input_rate_pps=0
    )
    window = compute_delta_window(earlier, later, HOST_WINDOW)  # ~0.04/s
    assert zero_traffic_test(window, later) is False


def test_zero_traffic_false_with_real_traffic():
    earlier = NormalizedInterfaceStats(input_packets=0, input_errors=0)
    later = NormalizedInterfaceStats(
        input_packets=90_000_000, input_errors=500_000, input_rate_pps=800
    )
    window = compute_delta_window(earlier, later, HOST_WINDOW)
    assert zero_traffic_test(window, later) is False


def test_zero_traffic_false_when_inputs_missing():
    window = compute_delta_window(
        NormalizedInterfaceStats(), NormalizedInterfaceStats(), HOST_WINDOW
    )
    assert zero_traffic_test(window, NormalizedInterfaceStats()) is False


# ---- delta source comparison -----------------------------------------------


def test_golden_delta_sources_disagree():
    assert delta_sources_disagree(1326250, 112905) is True


def test_delta_sources_within_factor_agree():
    assert delta_sources_disagree(100, 250) is False
    assert delta_sources_disagree(250, 100) is False
    assert delta_sources_disagree(0, 0) is False


def test_delta_sources_zero_vs_nonzero_disagree():
    assert delta_sources_disagree(0, 5) is True


def test_csv_delta_carries_no_rate_methods():
    csv = CsvDelta(counter="Rcv-Err", change=112905)
    assert not hasattr(csv, "errors_per_second")
    assert not hasattr(csv, "error_ratio")


# ---- byte-per-frame sanity check -------------------------------------------


def test_golden_bytes_per_frame_exceeds_mtu():
    stats = golden_stats()
    assert bytes_per_frame(stats) == pytest.approx(155325.0, abs=0.1)
    assert bytes_per_frame_exceeds_mtu(stats) is True


def test_bytes_per_frame_unknown_without_operands():
    assert bytes_per_frame(NormalizedInterfaceStats(input_packets=0)) is None
    assert bytes_per_frame_exceeds_mtu(NormalizedInterfaceStats()) is None


# ---- buffer group and lifetime fallback ------------------------------------


def test_buffer_group_sums_known_buckets():
    window = compute_delta_window(
        NormalizedInterfaceStats(overrun=0, ignored=0, discards_in=0),
        NormalizedInterfaceStats(overrun=40, ignored=10, discards_in=50),
        HOST_WINDOW,
    )
    assert buffer_group_delta(window) == 100  # no_buffer unknown: lower bound


def test_buffer_group_none_when_all_unknown():
    window = compute_delta_window(
        NormalizedInterfaceStats(), NormalizedInterfaceStats(), HOST_WINDOW
    )
    assert buffer_group_delta(window) is None


def test_lifetime_view_ratio_same_population():
    view = LifetimeView(golden_stats())
    outcome = view.error_ratio()
    assert outcome.value == pytest.approx(320792846 / (561806 + 320792846))
