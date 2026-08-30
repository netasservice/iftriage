"""Rebuilding a run's results from the history database (--from-history)."""

import sqlite3

import pytest
from conftest import FIXTURES

from iftriage.history import History
from iftriage.ingest import ingest_csv
from iftriage.models import (
    CaseResult,
    NormalizedInterfaceStats,
    Platform,
    Verdict,
    VerdictCategory,
)
from iftriage.replay import ReplayError, load_results


def _cases():
    cases, _ = ingest_csv(FIXTURES / "sample_top20.csv")
    return cases


def _collected(case) -> CaseResult:
    """A fully collected case, with every field --from-history must recover."""
    result = CaseResult(case=case)
    result.platform = Platform.IOS_XE
    result.canonical_interface = "GigabitEthernet3/0/20"
    result.stats = NormalizedInterfaceStats(
        link_status="up",
        duplex="full",
        input_packets=1_000_000,
        crc_errors=42,
        dom_rx_power_dbm=-7.5,
        port_channel_members={"Port-channel214": ["GigabitEthernet3/0/23"]},
    )
    result.repoll_stats = NormalizedInterfaceStats(crc_errors=99)
    result.repoll_minutes = 10.0
    result.raw_outputs = {"interface": "GigabitEthernet3/0/20 is up ..."}
    result.parse_errors = ["transceiver: no DOM table"]
    result.parent_portchannel = "Port-channel214"
    result.repoll_skip_reason = "device CPU at 91%"
    result.member_stats = {
        "GigabitEthernet3/0/23": NormalizedInterfaceStats(
            link_status="up", crc_errors=7
        )
    }
    result.member_repoll_stats = {
        "GigabitEthernet3/0/23": NormalizedInterfaceStats(crc_errors=9)
    }
    result.member_errors = {"GigabitEthernet3/0/24": "member collection failed"}
    result.verdict = Verdict(VerdictCategory.PHYSICAL_MEDIA, "PHYSICAL_MEDIA — test.")
    return result


def _unverified(case) -> CaseResult:
    result = CaseResult(case=case)
    result.collection_error = "unreachable: timed out"
    result.verdict = Verdict(VerdictCategory.UNVERIFIED, "UNVERIFIED — test.")
    return result


def _store(db, cases, results, repoll_minutes=10.0) -> History:
    history = History(db)
    history.archive_ingest("sample_top20.csv", "raw,csv", cases)
    run_id = history.start_run("sample_top20.csv", repoll_minutes)
    history.save_results(run_id, results)
    history.finish_run(run_id, {"line": "stored"})
    return history


def test_every_field_survives_the_round_trip(tmp_path):
    cases = _cases()
    stored = [_collected(case) for case in cases]
    history = _store(tmp_path / "history.db", cases, stored)

    results, source = load_results(cases, history)
    history.close()

    assert len(results) == len(cases)
    assert source.run_ids == [1]
    assert "run #1" in source.describe()

    rebuilt = results[0]
    original = stored[0]
    # The case itself comes from the CSV, not from storage: the enriched-CSV
    # echo and the data-quality flags stay exactly what this file says.
    assert rebuilt.case is cases[0]
    assert rebuilt.platform is Platform.IOS_XE
    assert rebuilt.canonical_interface == "GigabitEthernet3/0/20"
    assert rebuilt.stats == original.stats
    assert rebuilt.repoll_stats == original.repoll_stats
    assert rebuilt.repoll_minutes == 10.0
    assert rebuilt.raw_outputs == original.raw_outputs
    assert rebuilt.parse_errors == original.parse_errors
    assert rebuilt.parent_portchannel == "Port-channel214"
    assert rebuilt.repoll_skip_reason == "device CPU at 91%"
    assert rebuilt.member_stats == original.member_stats
    assert rebuilt.member_repoll_stats == original.member_repoll_stats
    assert rebuilt.member_errors == original.member_errors
    # Verdicts are re-derived by the caller, never replayed.
    assert rebuilt.verdict is None


def test_a_case_with_no_stored_row_fails_the_whole_replay(tmp_path):
    cases = _cases()
    history = _store(tmp_path / "history.db", cases, [_collected(cases[0])])

    with pytest.raises(ReplayError) as excinfo:
        load_results(cases, history)
    history.close()

    message = str(excinfo.value)
    assert "8 of 9 case(s)" in message
    assert "sw-b Et4/15 (Rcv-Err)" in message
    assert "--from-history" in message  # says how to fix it


def test_an_unverified_collection_still_counts_as_stored_data(tmp_path):
    """Replaying an unreachable device reproduces the original report."""
    cases = _cases()
    history = _store(
        tmp_path / "history.db", cases, [_unverified(case) for case in cases]
    )

    results, _ = load_results(cases, history)
    history.close()

    assert results[0].stats is None
    assert results[0].collection_error == "unreachable: timed out"


def test_the_newest_run_wins(tmp_path):
    cases = _cases()
    db = tmp_path / "history.db"
    history = _store(db, cases, [_collected(case) for case in cases])
    newer = [_collected(case) for case in cases]
    for result in newer:
        result.stats = NormalizedInterfaceStats(crc_errors=1234)
    run_id = history.start_run("sample_top20.csv", 5.0)
    history.save_results(run_id, newer)

    results, source = load_results(cases, history)
    history.close()

    assert source.run_ids == [2]
    assert all(result.stats.crc_errors == 1234 for result in results)


def test_runs_written_before_the_replay_schema_are_never_reused(tmp_path):
    """An older database is missing fields the verdict depends on.

    Reusing it would look like a faithful replay while quietly answering a
    different question, so it is refused exactly like an empty database.
    """
    cases = _cases()
    db = tmp_path / "history.db"
    history = _store(db, cases, [_collected(case) for case in cases])
    history.close()

    conn = sqlite3.connect(db)
    conn.execute("UPDATE runs SET replay_schema = NULL")
    conn.commit()
    conn.close()

    history = History(db)
    with pytest.raises(ReplayError):
        load_results(cases, history)
    history.close()


def test_stored_stats_degrade_fail_closed(tmp_path):
    """Unknown keys are dropped; fields the row never held stay None."""
    cases = _cases()
    db = tmp_path / "history.db"
    history = _store(db, cases, [_collected(case) for case in cases])
    history._conn.execute(
        "UPDATE case_results SET stats_json = ?",
        ('{"link_status": "up", "retired_field": 1}',),
    )
    history._conn.commit()

    results, _ = load_results(cases, history)
    history.close()

    stats = results[0].stats
    assert stats.link_status == "up"
    assert stats.crc_errors is None  # never coerced to zero
    assert not hasattr(stats, "retired_field")


def test_duplicate_csv_rows_share_one_stored_collection(tmp_path):
    """The CSV lists sw-g Po214 twice; both rows replay the same device data."""
    cases = _cases()
    history = _store(
        tmp_path / "history.db", cases, [_collected(case) for case in cases]
    )

    results, _ = load_results(cases, history)
    history.close()

    po_results = [r for r in results if r.case.interface == "Po214"]
    assert len(po_results) == 2
    assert po_results[0].stats == po_results[1].stats
    # ...but each keeps its own CSV row.
    assert po_results[0].case.description == "po case"
    assert po_results[1].case.description == "po case again"
