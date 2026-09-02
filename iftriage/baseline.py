"""Select the earlier sample each case is compared against.

A run takes one sample and stores it; the delta that answers "is this counter
still incrementing NOW?" comes from a previous run instead of from a second
pass the operator has to wait for.

The baseline belongs to the INTERFACE, not to the CSV. The lookup key is
(switch, interface, counter) — today's top-20 list and last week's may share
only a handful of rows, and each row finds its own earlier sample
independently. Partial coverage is therefore the normal case, not an error,
and every rejection is recorded so the report can say, per case, what it was
compared against or why it was not.

This module owns that policy. `history.py` stays a dumb reader and `rules.py`
stays pure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .config import BaselineSettings
from .history import History, StoredSample
from .models import CaseResult, InterfaceCase, Platform
from .normalize import InterfaceNameError, expand_interface

# (switch, interface, counter) — the same triple case_results is indexed on.
CaseKey = tuple[str, str, str]


@dataclass(frozen=True)
class BaselineSelection:
    """What the history can offer for this CSV, decided before any device is
    contacted so the operator answers immediately instead of after a collect."""

    samples: dict[CaseKey, StoredSample] = field(default_factory=dict)
    notes: dict[CaseKey, str] = field(default_factory=dict)
    total_cases: int = 0
    newest_taken_at: datetime | None = None
    oldest_taken_at: datetime | None = None

    @property
    def matched(self) -> int:
        return len(self.samples)


def _case_key(case: InterfaceCase) -> CaseKey:
    return (case.switch, case.interface, case.counter)


def _canonical_guess(case: InterfaceCase, platform: Platform | None) -> str | None:
    """The long form of the CSV's interface name, when it can be known here.

    Two CSVs can spell the same port differently (`Gi1/0/1` one week,
    `GigabitEthernet1/0/1` the next), and the stored row carries both forms.
    The platform is not detected yet at selection time, so this uses the
    cached platform of a device already collected once — and a device with no
    cache entry has never been collected, so it has no earlier sample to miss.
    """
    if platform is None:
        return None
    try:
        return expand_interface(platform, case.interface)
    except InterfaceNameError:
        return None


def select_baselines(
    cases: list[InterfaceCase],
    history: History,
    settings: BaselineSettings,
    now: datetime,
) -> BaselineSelection:
    """Find the newest usable earlier sample for each case.

    One pass over the cases serves both the operator's yes/no question and the
    later attachment, so the prompt and the analysis can never describe
    different rows.
    """
    # Both bounds go into the query. Asking for "the newest sample" and then
    # rejecting it for being too recent would let this morning's run mask
    # yesterday's, which is the one that can actually answer.
    not_after = now - timedelta(minutes=settings.min_window_minutes)
    not_before = now - timedelta(days=settings.max_window_days)

    samples: dict[CaseKey, StoredSample] = {}
    notes: dict[CaseKey, str] = {}
    platforms: dict[str, Platform | None] = {}

    for case in cases:
        if case.excluded:
            continue
        key = _case_key(case)
        if key in samples or key in notes:  # duplicate CSV rows share one answer
            continue
        if case.mgmt_ip not in platforms:
            platforms[case.mgmt_ip] = history.get_platform(case.mgmt_ip)
        sample = history.latest_sample(
            case.switch,
            case.interface,
            _canonical_guess(case, platforms[case.mgmt_ip]),
            case.counter,
            before=not_after.isoformat(timespec="seconds"),
            not_before=not_before.isoformat(timespec="seconds"),
        )
        # The run row is stamped when the run starts; an interface is read
        # some time after that. Re-checking against the sample's own timestamp
        # is what keeps a long collection from slipping under the floor.
        if sample is None or now - sample.taken_at < timedelta(
            minutes=settings.min_window_minutes
        ):
            notes[key] = (
                "no earlier sample stored for this interface between "
                f"{settings.min_window_minutes:g} minute(s) and "
                f"{settings.max_window_days:g} day(s) ago"
            )
            continue
        samples[key] = sample

    stamps = [sample.taken_at for sample in samples.values()]
    return BaselineSelection(
        samples=samples,
        notes=notes,
        total_cases=len(cases),
        newest_taken_at=max(stamps) if stamps else None,
        oldest_taken_at=min(stamps) if stamps else None,
    )


def attach_baselines(
    results: list[CaseResult], selection: BaselineSelection, now: datetime
) -> int:
    """Pair each collected result with its earlier sample; return how many got
    one. A case that did not get one carries the reason, so the report can
    never let an un-compared interface pass for a compared one."""
    attached = 0
    for result in results:
        if result.collection_error is not None or result.stats is None:
            continue  # nothing was collected to compare against
        key = _case_key(result.case)
        sample = selection.samples.get(key)
        if sample is None:
            result.baseline_note = selection.notes.get(key)
            continue
        taken_now = result.stats.collected_at or now
        result.baseline_stats = sample.stats
        result.baseline_minutes = (taken_now - sample.taken_at).total_seconds() / 60
        result.baseline_taken_at = sample.taken_at
        result.baseline_run_id = sample.run_id
        result.baseline_raw_outputs = sample.raw_outputs
        # A member with no earlier sample simply gets no delta; the rules
        # already fail closed on a missing one.
        result.member_baseline_stats = {
            name: sample.member_stats[name]
            for name in result.member_stats
            if name in sample.member_stats
        }
        attached += 1
    return attached
