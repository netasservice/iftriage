"""Rebuild a run's results from the history database, contacting no device.

The expensive half of a run is the collection; the cheap half is the analysis.
This module replays the first so the second can be iterated on — a template
tweak, a threshold change, a new rule — without asking the fleet again. It
reads the canonical model back out of storage and knows nothing about
platforms, sessions or commands.
"""

from __future__ import annotations

from dataclasses import dataclass

from .history import History, StoredCase
from .models import CaseResult, InterfaceCase

# A longer list of missing cases stops being an actionable message and starts
# being a wall of text; the count still reports the true total.
_MAX_LISTED_MISSING = 10


class ReplayError(Exception):
    """The stored history cannot answer for every case in the CSV."""


@dataclass(frozen=True)
class ReplaySource:
    """Which stored runs supplied the replayed data, and when they ran."""

    run_ids: list[int]
    collected_at: list[str]

    def describe(self) -> str:
        runs = ", ".join(f"#{run_id}" for run_id in self.run_ids)
        label = "run" if len(self.run_ids) == 1 else "runs"
        when = self.collected_at[0]
        if len(self.collected_at) > 1:
            when = f"{self.collected_at[0]} .. {self.collected_at[-1]}"
        return f"{label} {runs}, collected {when}"


def _rebuild(case: InterfaceCase, stored: StoredCase) -> CaseResult:
    return CaseResult(
        case=case,
        platform=stored.platform,
        canonical_interface=stored.canonical_interface,
        stats=stored.stats,
        repoll_stats=stored.repoll_stats,
        repoll_minutes=stored.repoll_minutes,
        raw_outputs=stored.raw_outputs,
        collection_error=stored.collection_error,
        repoll_skip_reason=stored.repoll_skip_reason,
        parse_errors=stored.parse_errors,
        parent_portchannel=stored.parent_portchannel,
        member_stats=stored.member_stats,
        member_repoll_stats=stored.member_repoll_stats,
        member_errors=stored.member_errors,
    )


def load_results(
    cases: list[InterfaceCase], history: History
) -> tuple[list[CaseResult], ReplaySource]:
    """Pair every CSV case with its newest stored collection.

    A stored row counts as data even when the original verdict was UNVERIFIED
    or the case was excluded by a data-quality check: replaying it reproduces
    the original report faithfully. Only a case with no stored row at all is
    missing, and one missing case fails the whole replay — a report that
    silently drops rows the operator asked about is worse than no report.
    """
    results: list[CaseResult] = []
    missing: list[str] = []
    run_ids: set[int] = set()
    stamps: set[str] = set()

    for case in cases:
        stored = history.latest_case_result(case.switch, case.interface, case.counter)
        if stored is None:
            missing.append(f"{case.switch} {case.interface} ({case.counter})")
            continue
        results.append(_rebuild(case, stored))
        run_ids.add(stored.run_id)
        stamps.add(stored.run_started_at)

    if missing:
        listed = ", ".join(missing[:_MAX_LISTED_MISSING])
        if len(missing) > _MAX_LISTED_MISSING:
            listed += f", and {len(missing) - _MAX_LISTED_MISSING} more"
        raise ReplayError(
            f"no stored collection for {len(missing)} of {len(cases)} case(s): "
            f"{listed}. Re-run without --from-history to collect them."
        )

    return results, ReplaySource(sorted(run_ids), sorted(stamps))
