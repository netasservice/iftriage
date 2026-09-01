"""Interval derivation and provenance. Pure logic, zero device access."""

from datetime import UTC, datetime

import pytest

from iftriage.models import NormalizedInterfaceStats
from iftriage.timebase import (
    IntervalSource,
    is_stale,
    lifetime_window,
    matches_round_window,
    observation_window,
    parse_poll_time,
    staleness_minutes,
)

REPORT_TIME = datetime(2026, 9, 1, 17, 53, tzinfo=UTC)


# ---- lifetime accumulation window ------------------------------------------


def test_lifetime_window_never_cleared_uses_uptime():
    stats = NormalizedInterfaceStats(
        counters_never_cleared=True, uptime_minutes=417731.0
    )
    window = lifetime_window(stats)
    assert window is not None
    assert window.minutes == 417731.0
    assert window.source is IntervalSource.DEVICE_UPTIME
    assert window.device_side


def test_lifetime_window_cleared_uses_clear_age():
    stats = NormalizedInterfaceStats(
        counters_never_cleared=False, last_clearing_minutes=90.0
    )
    window = lifetime_window(stats)
    assert window is not None
    assert window.minutes == 90.0
    assert window.source is IntervalSource.DEVICE_LAST_CLEAR


def test_lifetime_window_unknown_epoch_yields_none():
    assert lifetime_window(NormalizedInterfaceStats()) is None
    # "never" without a parsed uptime still supports no rate.
    assert (
        lifetime_window(NormalizedInterfaceStats(counters_never_cleared=True)) is None
    )


# ---- observation window ladder ---------------------------------------------


def test_observation_window_prefers_device_uptime_difference():
    earlier = NormalizedInterfaceStats(uptime_minutes=1000.0)
    later = NormalizedInterfaceStats(uptime_minutes=3388.0)
    window = observation_window(earlier, later, host_minutes=2500.0)
    assert window is not None
    assert window.minutes == pytest.approx(2388.0)
    assert window.source is IntervalSource.DEVICE_UPTIME


def test_observation_window_reload_disqualifies_uptime():
    earlier = NormalizedInterfaceStats(
        uptime_minutes=9000.0, last_clearing_minutes=100.0
    )
    later = NormalizedInterfaceStats(uptime_minutes=50.0, last_clearing_minutes=2488.0)
    window = observation_window(earlier, later, host_minutes=2500.0)
    assert window is not None
    assert window.minutes == pytest.approx(2388.0)
    assert window.source is IntervalSource.DEVICE_LAST_CLEAR


def test_observation_window_falls_back_to_host_and_says_so():
    window = observation_window(
        NormalizedInterfaceStats(), NormalizedInterfaceStats(), host_minutes=2388.0
    )
    assert window is not None
    assert window.source is IntervalSource.HOST_INGEST_TIME
    assert not window.device_side


def test_observation_window_none_without_any_source():
    assert (
        observation_window(
            NormalizedInterfaceStats(), NormalizedInterfaceStats(), host_minutes=None
        )
        is None
    )


# ---- CSV poll time and staleness -------------------------------------------


def test_parse_poll_time_naive_assumed_utc():
    parsed = parse_poll_time("2026-08-06T12:00:00")
    assert parsed == datetime(2026, 8, 6, 12, 0, tzinfo=UTC)


def test_parse_poll_time_unparseable_is_none():
    assert parse_poll_time("") is None
    assert parse_poll_time("last thursday") is None


def test_golden_staleness_flagged():
    poll = parse_poll_time("2026-08-06T12:00:00")
    minutes = staleness_minutes(REPORT_TIME, poll)
    assert minutes is not None
    assert minutes > 25 * 24 * 60  # the ~26-day gap of the reference case
    assert is_stale(REPORT_TIME, poll) is True


def test_fresh_poll_not_stale():
    poll = parse_poll_time("2026-09-01T10:00:00")
    assert is_stale(REPORT_TIME, poll) is False


def test_future_poll_time_yields_no_staleness():
    poll = parse_poll_time("2026-09-02T10:00:00")
    assert staleness_minutes(REPORT_TIME, poll) is None
    assert is_stale(REPORT_TIME, poll) is False


# ---- window labeling -------------------------------------------------------


def test_round_window_label_tolerance():
    day = 24 * 60
    assert matches_round_window(day, day)
    assert matches_round_window(day * 1.09, day)
    assert matches_round_window(day * 0.91, day)
    assert not matches_round_window(39.8 * 60, day)  # the mislabeled Δ24h case
    assert not matches_round_window(day * 1.2, day)
