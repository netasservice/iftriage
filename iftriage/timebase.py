"""Interval derivation and provenance for counter math.

Every rate the report prints must say how long its window is AND where that
length came from. Sources are ranked: device-side evidence (uptime, counter
epoch) beats the CSV poll timestamps, which beat host-side clocks. The source
travels with the value so the rules layer can cap confidence on the weaker
ones and the templates can label them honestly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from .models import NormalizedInterfaceStats

# A poll older than this at report time is a headline data-quality item: every
# rate in the report describes the past, not the present.
STALENESS_HEADLINE_MINUTES = 24 * 60

# A window may only be labeled with a round name ("24h") when it is within
# this fraction of that length; otherwise the label states the real length.
WINDOW_LABEL_TOLERANCE = 0.10


class IntervalSource(StrEnum):
    """Where an interval length came from, strongest first."""

    DEVICE_UPTIME = "device clock (uptime delta)"
    DEVICE_LAST_CLEAR = "device counter-clear age"
    CSV_POLL_TIME = "CSV poll timestamps"
    HOST_INGEST_TIME = "host-side timestamps"


# Sources measured by the device's own clock. Anything else is somebody
# else's clock and caps confidence in the rules layer.
DEVICE_SIDE_SOURCES = frozenset(
    {IntervalSource.DEVICE_UPTIME, IntervalSource.DEVICE_LAST_CLEAR}
)


@dataclass(frozen=True)
class IntervalEstimate:
    """An interval length that knows its own provenance."""

    minutes: float
    source: IntervalSource

    @property
    def seconds(self) -> float:
        return self.minutes * 60

    @property
    def device_side(self) -> bool:
        return self.source in DEVICE_SIDE_SOURCES


def lifetime_window(stats: NormalizedInterfaceStats) -> IntervalEstimate | None:
    """How long the LIFETIME counters have been accumulating.

    Never-cleared counters have accumulated for the whole uptime; cleared ones
    for the parsed age. None when the device gave neither — a lifetime value
    without a window supports no rate at all.
    """
    if stats.counters_never_cleared and stats.uptime_minutes is not None:
        return IntervalEstimate(stats.uptime_minutes, IntervalSource.DEVICE_UPTIME)
    if stats.last_clearing_minutes is not None:
        return IntervalEstimate(
            stats.last_clearing_minutes, IntervalSource.DEVICE_LAST_CLEAR
        )
    return None


def observation_window(
    earlier: NormalizedInterfaceStats,
    later: NormalizedInterfaceStats,
    host_minutes: float | None,
) -> IntervalEstimate | None:
    """Elapsed time between two observations of the same interface.

    Prefers the device's own clock: the difference of the uptimes it reported
    at each poll, then the difference of its counter-clear ages. Falls back to
    the host-side gap (`baseline_minutes`) — honest but somebody else's clock,
    so it is labeled as such. A negative device-side difference (reload
    between polls) disqualifies that source rather than yielding a bogus
    window.
    """
    if earlier.uptime_minutes is not None and later.uptime_minutes is not None:
        elapsed = later.uptime_minutes - earlier.uptime_minutes
        if elapsed > 0:
            return IntervalEstimate(elapsed, IntervalSource.DEVICE_UPTIME)
    if (
        earlier.last_clearing_minutes is not None
        and later.last_clearing_minutes is not None
    ):
        elapsed = later.last_clearing_minutes - earlier.last_clearing_minutes
        if elapsed > 0:
            return IntervalEstimate(elapsed, IntervalSource.DEVICE_LAST_CLEAR)
    if host_minutes is not None and host_minutes > 0:
        return IntervalEstimate(host_minutes, IntervalSource.HOST_INGEST_TIME)
    return None


def parse_poll_time(text: str) -> datetime | None:
    """Parse the CSV `_time` column. A naive timestamp is assumed UTC — the
    export does not label its zone — and callers surface that assumption as a
    data-quality note rather than hiding it."""
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def staleness_minutes(
    report_time: datetime, poll_time: datetime | None
) -> float | None:
    """Age of the CSV poll at report time; None when the poll time is unknown
    or (clock skew) apparently in the future."""
    if poll_time is None:
        return None
    elapsed = (report_time - poll_time).total_seconds() / 60
    if elapsed < 0:
        return None
    return elapsed


def is_stale(report_time: datetime, poll_time: datetime | None) -> bool:
    minutes = staleness_minutes(report_time, poll_time)
    return minutes is not None and minutes > STALENESS_HEADLINE_MINUTES


def matches_round_window(minutes: float, round_minutes: float) -> bool:
    """True when an interval may honestly wear a round label such as "24h":
    within WINDOW_LABEL_TOLERANCE of the round length."""
    if round_minutes <= 0:
        return False
    return abs(minutes - round_minutes) <= round_minutes * WINDOW_LABEL_TOLERANCE
