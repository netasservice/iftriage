"""Rebuild a run's results from the history database, contacting no device.

The expensive half of a run is the collection; the cheap half is the analysis.
This module replays the first so the second can be iterated on — a template
tweak, a threshold change, a new rule — without asking the fleet again. It
reads the canonical model back out of storage and knows nothing about
platforms, sessions or commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .config import BaselineSettings
from .history import History, StoredCase
from .models import CaseResult, InterfaceCase

# The (switch, interface, counter) triple that identifies a case everywhere.
CaseKey = tuple[str, str, str]

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
        baseline_stats=stored.baseline_stats,
        baseline_minutes=stored.baseline_minutes,
        baseline_taken_at=stored.baseline_taken_at,
        baseline_run_id=stored.baseline_run_id,
        raw_outputs=stored.raw_outputs,
        collection_error=stored.collection_error,
        baseline_note=stored.baseline_note,
        parse_errors=stored.parse_errors,
        parent_portchannel=stored.parent_portchannel,
        member_stats=stored.member_stats,
        member_baseline_stats=stored.member_baseline_stats,
        member_errors=stored.member_errors,
    )


def load_stored(
    cases: list[InterfaceCase], history: History
) -> list[tuple[InterfaceCase, StoredCase]]:
    """Pair every CSV case with its newest stored collection.

    A stored row counts as data even when the original verdict was UNVERIFIED
    or the case was excluded by a data-quality check: replaying it reproduces
    the original report faithfully. Only a case with no stored row at all is
    missing, and one missing case fails the whole replay — a report that
    silently drops rows the operator asked about is worse than no report.
    """
    loaded: list[tuple[InterfaceCase, StoredCase]] = []
    missing: list[str] = []

    for case in cases:
        stored = history.latest_case_result(case.switch, case.interface, case.counter)
        if stored is None:
            missing.append(f"{case.switch} {case.interface} ({case.counter})")
            continue
        loaded.append((case, stored))

    if missing:
        listed = ", ".join(missing[:_MAX_LISTED_MISSING])
        if len(missing) > _MAX_LISTED_MISSING:
            listed += f", and {len(missing) - _MAX_LISTED_MISSING} more"
        raise ReplayError(
            f"no stored collection for {len(missing)} of {len(cases)} case(s): "
            f"{listed}. Re-run without --from-history to collect them."
        )
    return loaded


@dataclass(frozen=True)
class PreviousSelection:
    """Which cases can be paired with their second-newest collection, and
    why the rest cannot. Selection happens before the operator answers the
    prompt, so the offer and the report always describe the same rows."""

    pairs: dict[CaseKey, StoredCase] = field(default_factory=dict)
    notes: dict[CaseKey, str] = field(default_factory=dict)
    total_cases: int = 0

    @property
    def matched(self) -> int:
        return len(self.pairs)


def _collected_at(stored: StoredCase) -> datetime:
    if stored.stats is not None and stored.stats.collected_at is not None:
        return stored.stats.collected_at
    return datetime.fromisoformat(stored.run_started_at)


def select_previous(
    loaded: list[tuple[InterfaceCase, StoredCase]],
    history: History,
    settings: BaselineSettings,
) -> PreviousSelection:
    """For each loaded case, find the second-newest replayable collection
    whose spacing from the newest respects the baseline window — anchored on
    the two collections' own timestamps, never the wall clock: both runs may
    be a month old, only their spacing matters."""
    selection = PreviousSelection(total_cases=len(loaded))
    for case, newest in loaded:
        key: CaseKey = (case.switch, case.interface, case.counter)
        if key in selection.pairs or key in selection.notes:
            continue  # duplicate CSV rows share one answer
        older = history.previous_case_result(
            case.switch, case.interface, case.counter, before_run_id=newest.run_id
        )
        if older is None:
            selection.notes[key] = (
                "no earlier replayable collection stored for this case"
            )
            continue
        if older.stats is None:
            selection.notes[key] = (
                "the previous collection holds no counters for this case"
            )
            continue
        spacing = _collected_at(newest) - _collected_at(older)
        if spacing < timedelta(minutes=settings.min_window_minutes) or (
            spacing > timedelta(days=settings.max_window_days)
        ):
            selection.notes[key] = (
                "previous collection is outside the "
                f"{settings.min_window_minutes:g} minute(s) .. "
                f"{settings.max_window_days:g} day(s) comparison window"
            )
            continue
        selection.pairs[key] = older
    return selection


def build_results(
    loaded: list[tuple[InterfaceCase, StoredCase]],
    selection: PreviousSelection | None = None,
) -> tuple[list[CaseResult], ReplaySource]:
    """Faithful replay of the newest collections; when a selection is given,
    the older collection of each paired case becomes its baseline — replacing
    any baseline the newest row stored from its live run, since the operator
    asked for these two collections (the report names which run)."""
    results: list[CaseResult] = []
    run_ids: set[int] = set()
    stamps: set[str] = set()
    for case, newest in loaded:
        result = _rebuild(case, newest)
        run_ids.add(newest.run_id)
        stamps.add(newest.run_started_at)
        if selection is not None:
            key: CaseKey = (case.switch, case.interface, case.counter)
            older = selection.pairs.get(key)
            if older is not None:
                newer_at = _collected_at(newest)
                older_at = _collected_at(older)
                result.baseline_stats = older.stats
                result.baseline_minutes = (newer_at - older_at).total_seconds() / 60
                result.baseline_taken_at = older_at
                result.baseline_run_id = older.run_id
                result.baseline_note = None
                result.member_baseline_stats = {
                    name: older.member_stats[name]
                    for name in result.member_stats
                    if name in older.member_stats
                }
                run_ids.add(older.run_id)
                stamps.add(older.run_started_at)
            elif result.baseline_stats is None:
                # Unpaired and the stored row had no baseline of its own:
                # carry the reason. A row with a live baseline keeps it and
                # the report describes that comparison truthfully.
                result.baseline_note = selection.notes.get(key)
        results.append(result)
    return results, ReplaySource(sorted(run_ids), sorted(stamps))


def load_results(
    cases: list[InterfaceCase], history: History
) -> tuple[list[CaseResult], ReplaySource]:
    """Faithful single-collection replay: newest stored row per case."""
    return build_results(load_stored(cases, history))
