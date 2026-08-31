"""Choosing the earlier sample each case is compared against.

The baseline belongs to the interface, not to the CSV: a top-20 list changes
from one week to the next, so every case searches history on its own and
partial coverage is the normal outcome.
"""

import sqlite3
from datetime import UTC, datetime, timedelta

from iftriage.baseline import attach_baselines, select_baselines
from iftriage.config import BaselineSettings
from iftriage.history import History
from iftriage.models import (
    CaseResult,
    InterfaceCase,
    NormalizedInterfaceStats,
    Platform,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
SETTINGS = BaselineSettings()


def _case(interface="Gi1/0/1", switch="sw-a", counter="Rcv-Err", ip="10.0.0.1"):
    return InterfaceCase(
        poll_time="2026-08-30T03:00:00",
        switch=switch,
        mgmt_ip=ip,
        interface=interface,
        description="",
        status="up",
        protocol="up",
        counter=counter,
        prev_count=0,
        count=10,
        change=10,
        row_index=0,
    )


def _stored(case, *, hours_ago, crc, canonical=None, members=None):
    """A collected result as a previous run would have saved it."""
    result = CaseResult(case=case)
    result.platform = Platform.IOS_XE
    result.canonical_interface = canonical
    result.stats = NormalizedInterfaceStats(
        link_status="up",
        input_packets=1_000_000,
        crc_errors=crc,
        input_errors=crc,
        collected_at=NOW - timedelta(hours=hours_ago),
    )
    result.member_stats = members or {}
    return result


def _write_run(db, results, *, hours_ago):
    """Store one run and back-date it, so the window under test is real."""
    history = History(db)
    run_id, _ = history.start_run("top20.csv")
    history.save_results(run_id, results)
    history.finish_run(run_id, {"line": "stored"})
    history._conn.execute(
        "UPDATE runs SET started_at=? WHERE id=?",
        ((NOW - timedelta(hours=hours_ago)).isoformat(), run_id),
    )
    history._conn.commit()
    return history


def test_the_newest_earlier_sample_wins_across_runs_and_csvs(tmp_path):
    """Last week's CSV and today's share one interface; the interface is the
    key, so the shared row finds its sample and the new one simply does not."""
    db = tmp_path / "history.db"
    old_case = _case()
    history = _write_run(db, [_stored(old_case, hours_ago=100, crc=10)], hours_ago=100)
    history.close()
    history = _write_run(db, [_stored(old_case, hours_ago=18, crc=40)], hours_ago=18)

    today = [_case(), _case(interface="Gi1/0/9")]
    selection = select_baselines(today, history, SETTINGS, NOW)
    history.close()

    assert selection.matched == 1
    assert selection.total_cases == 2
    sample = selection.samples[("sw-a", "Gi1/0/1", "Rcv-Err")]
    assert sample.stats.crc_errors == 40  # the newer of the two runs
    note = selection.notes[("sw-a", "Gi1/0/9", "Rcv-Err")]
    assert "no earlier sample stored for this interface" in note


def test_a_sample_inside_the_minimum_window_is_refused(tmp_path):
    """Two samples minutes apart read as flat because nothing had time to move,
    and a false flat vetoes escalation. Refusing it is the fail-closed choice."""
    case = _case()
    history = _write_run(
        tmp_path / "history.db", [_stored(case, hours_ago=0.01, crc=10)], hours_ago=0.01
    )

    selection = select_baselines([case], history, SETTINGS, NOW)
    history.close()

    assert selection.matched == 0
    assert "5 minute(s)" in selection.notes[("sw-a", "Gi1/0/1", "Rcv-Err")]


def test_a_too_recent_run_does_not_mask_the_one_that_can_answer(tmp_path):
    """Running twice in one morning must not cost yesterday's baseline. Both
    bounds are applied in the query, so the newest *usable* sample wins rather
    than the newest sample being picked and then thrown away."""
    db = tmp_path / "history.db"
    case = _case()
    history = _write_run(db, [_stored(case, hours_ago=18, crc=10)], hours_ago=18)
    history.close()
    history = _write_run(db, [_stored(case, hours_ago=0.01, crc=40)], hours_ago=0.01)

    selection = select_baselines([case], history, SETTINGS, NOW)
    history.close()

    assert selection.matched == 1
    assert selection.samples[("sw-a", "Gi1/0/1", "Rcv-Err")].stats.crc_errors == 10


def test_a_sample_older_than_the_maximum_window_is_not_offered(tmp_path):
    """ "Still incrementing" stops meaning "now" once the window is weeks wide."""
    case = _case()
    history = _write_run(
        tmp_path / "history.db",
        [_stored(case, hours_ago=24 * 30, crc=10)],
        hours_ago=24 * 30,
    )

    selection = select_baselines([case], history, SETTINGS, NOW)
    history.close()

    assert selection.matched == 0


def test_the_same_port_spelled_differently_in_two_csvs_still_matches(tmp_path):
    """One export writes Gi1/0/1, the next GigabitEthernet1/0/1. Both forms are
    stored, and the cached platform expands today's name before the lookup."""
    db = tmp_path / "history.db"
    history = _write_run(
        db,
        [
            _stored(
                _case("Gi1/0/1"), hours_ago=18, crc=10, canonical="GigabitEthernet1/0/1"
            )
        ],
        hours_ago=18,
    )
    history.set_platform("10.0.0.1", Platform.IOS_XE)

    selection = select_baselines(
        [_case("GigabitEthernet1/0/1")], history, SETTINGS, NOW
    )
    history.close()

    assert selection.matched == 1


def test_members_pair_by_name_and_unmatched_ones_are_simply_absent(tmp_path):
    case = _case("Po214")
    history = _write_run(
        tmp_path / "history.db",
        [
            _stored(
                case,
                hours_ago=18,
                crc=10,
                members={
                    "GigabitEthernet1/0/1": NormalizedInterfaceStats(crc_errors=3)
                },
            )
        ],
        hours_ago=18,
    )
    selection = select_baselines([case], history, SETTINGS, NOW)
    history.close()

    result = CaseResult(case=case)
    result.stats = NormalizedInterfaceStats(crc_errors=20, collected_at=NOW)
    result.member_stats = {
        "GigabitEthernet1/0/1": NormalizedInterfaceStats(crc_errors=9),
        "GigabitEthernet1/0/2": NormalizedInterfaceStats(crc_errors=1),  # new member
    }

    assert attach_baselines([result], selection, NOW) == 1
    assert result.baseline_run_id == 1
    assert result.baseline_minutes == 18 * 60
    assert set(result.member_baseline_stats) == {"GigabitEthernet1/0/1"}


def test_an_uncollected_case_gets_no_baseline_and_no_note(tmp_path):
    """An UNVERIFIED case has nothing to compare; its verdict already says so,
    and a second explanation in the report would only add noise."""
    case = _case()
    history = _write_run(
        tmp_path / "history.db", [_stored(case, hours_ago=18, crc=10)], hours_ago=18
    )
    selection = select_baselines([case], history, SETTINGS, NOW)
    history.close()

    result = CaseResult(case=case)
    result.collection_error = "connection failed: timed out"

    assert attach_baselines([result], selection, NOW) == 0
    assert result.baseline_stats is None
    assert result.baseline_note is None


def test_a_case_with_no_earlier_sample_carries_the_reason(tmp_path):
    case = _case()
    history = _write_run(tmp_path / "history.db", [], hours_ago=18)
    selection = select_baselines([case], history, SETTINGS, NOW)
    history.close()

    result = CaseResult(case=case)
    result.stats = NormalizedInterfaceStats(collected_at=NOW)

    assert attach_baselines([result], selection, NOW) == 0
    assert result.baseline_note is not None


def test_a_pre_replay_schema_run_is_barred_from_replay_but_serves_as_a_baseline(
    tmp_path,
):
    """A deliberate asymmetry. A replay needs the whole row and must refuse
    partial history; a baseline needs one column, stats_json, whose meaning
    never changed — which is what lets the first run after an upgrade already
    compare against yesterday.
    """
    db = tmp_path / "history.db"
    case = _case()
    history = _write_run(db, [_stored(case, hours_ago=18, crc=10)], hours_ago=18)
    history.close()

    conn = sqlite3.connect(db)
    conn.execute("UPDATE runs SET replay_schema = 1")
    conn.commit()
    conn.close()

    history = History(db)
    assert history.latest_case_result("sw-a", "Gi1/0/1", "Rcv-Err") is None
    assert select_baselines([case], history, SETTINGS, NOW).matched == 1
    history.close()
