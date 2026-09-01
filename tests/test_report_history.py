"""Smoke tests: report rendering and SQLite history round-trip."""

import csv
from datetime import UTC, datetime
from importlib.resources import files

from conftest import FIXTURES

from iftriage.history import REPLAY_SCHEMA, History
from iftriage.ingest import ingest_csv
from iftriage.models import (
    CaseResult,
    Confidence,
    DataQualityFlag,
    DataQualityKind,
    NormalizedInterfaceStats,
    Platform,
    Signal,
    SignalKind,
    Verdict,
    VerdictCategory,
    VerdictMetrics,
)
from iftriage.report import build_summary, render_report


def _results():
    cases, findings = ingest_csv(FIXTURES / "sample_top20.csv")
    results = []
    for index, case in enumerate(cases):
        result = CaseResult(case=case)
        if case.excluded:
            result.verdict = Verdict(
                VerdictCategory.IGNORE, "IGNORE — data-quality artifact."
            )
        elif index % 2:
            result.verdict = Verdict(
                VerdictCategory.PHYSICAL_MEDIA, "PHYSICAL_MEDIA — test reason."
            )
            result.stats = NormalizedInterfaceStats(link_status="up")
            result.platform = Platform.IOS_XE
            result.raw_outputs = {"interface": "GigabitEthernet3/0/20 is up ..."}
        else:
            result.verdict = Verdict(
                VerdictCategory.UNVERIFIED, "UNVERIFIED — test reason."
            )
        results.append(result)
    return results, findings


def test_render_report_html_and_txt(tmp_path):
    results, findings = _results()
    meta = {
        "csv_file": "sample_top20.csv",
        "baseline": {"matched": 1, "total": 9},
        "audit_log": "audit.log",
    }
    paths = render_report(results, findings, meta, "report_en", tmp_path)
    html = paths["html"].read_text()
    txt = paths["txt"].read_text()
    summary = build_summary(results)
    assert summary["line"] in txt
    assert "Executive summary" in html
    assert "PHYSICAL_MEDIA" in html
    assert "Data quality" in html


def test_render_report_enriched_csv(tmp_path):
    results, findings = _results()
    meta = {
        "csv_file": "sample_top20.csv",
        "baseline": {"matched": 1, "total": 9},
        "audit_log": "audit.log",
    }
    paths = render_report(results, findings, meta, "report_en", tmp_path)

    with paths["csv"].open(newline="") as handle:
        header, *rows = list(csv.reader(handle))

    original_columns = list(results[0].case.raw_row.keys())
    assert header[:11] == original_columns
    assert header[11:] == [
        "verdict",
        "reason",
        "platform",
        "link_status",
        "protocol_status",
        "duplex",
        "speed",
        "input_errors",
        "crc_errors",
        "late_collisions",
        "discards_in",
        "discards_out",
        "dom_rx_power_dbm",
        "dom_tx_power_dbm",
        "neighbor_name",
        "neighbor_port",
        "flap_count",
        "dq_flags",
        "duplicate_of",
        "recurrence",
        "baseline_taken_at",
        "baseline_window",
        "member_summary",
    ]
    assert len(rows) == 9

    column = {name: index for index, name in enumerate(header)}
    # Rows keep the original CSV order, not the HTML's verdict order.
    assert [row[column["switch"]] for row in rows[:3]] == ["sw-a", "sw-b", "sw-c"]
    # Original cells are echoed verbatim alongside the verdict.
    assert rows[0][column["change"]] == "3271"
    assert rows[0][column["verdict"]] == "UNVERIFIED"
    # A collected case carries its stats and platform.
    assert rows[1][column["verdict"]] == "PHYSICAL_MEDIA"
    assert rows[1][column["link_status"]] == "up"
    assert rows[1][column["platform"]] == "ios_xe"
    # Unknown stats stay empty (fail-closed) — never rendered as 0.
    assert rows[1][column["crc_errors"]] == ""
    # The excluded data-quality artifact keeps its flags and empty stats cells.
    excluded_row = rows[3]
    assert excluded_row[column["switch"]] == "sw-d"
    assert "cross_device_identical" in excluded_row[column["dq_flags"]]
    assert excluded_row[column["verdict"]] == "IGNORE"
    assert excluded_row[column["link_status"]] == ""


def test_templates_ship_inside_the_package():
    """A template resolved outside the package is missing from an installed wheel."""
    template_dir = files("iftriage") / "templates"
    names = {entry.name for entry in template_dir.iterdir()}
    assert {"report_en.html.j2", "report_en.txt.j2"} <= names


def test_history_roundtrip(tmp_path):
    db = tmp_path / "history.db"
    cases, _ = ingest_csv(FIXTURES / "sample_top20.csv")
    history = History(db)

    history.archive_ingest("sample_top20.csv", "raw,csv", cases)
    assert history.recurrence_count("sw-a", "Gi3/0/20") == 1
    history.archive_ingest("sample_top20_week2.csv", "raw,csv", cases)
    assert history.recurrence_count("sw-a", "Gi3/0/20") == 2
    assert history.recurrence_count("nope", "Gi0/0") == 0

    run_id, _ = history.start_run("sample_top20.csv")
    results, _ = _results()
    history.save_results(run_id, results)
    history.finish_run(run_id, build_summary(results))

    assert history.get_platform("10.9.9.9") is None
    history.set_platform("10.9.9.9", Platform.EOS)
    assert history.get_platform("10.9.9.9") is Platform.EOS
    history.set_platform("10.9.9.9", Platform.NXOS)  # upsert
    assert history.get_platform("10.9.9.9") is Platform.NXOS
    history.close()


def _po_result_with_members():
    cases, _ = ingest_csv(FIXTURES / "sample_top20.csv")
    po_case = next(case for case in cases if case.interface == "Po214")
    result = CaseResult(case=po_case)
    result.platform = Platform.IOS_XE
    result.canonical_interface = "Port-channel214"
    result.stats = NormalizedInterfaceStats(link_status="up")
    result.member_stats = {
        "GigabitEthernet3/0/23": NormalizedInterfaceStats(link_status="up")
    }
    result.member_baseline_stats = {
        "GigabitEthernet3/0/23": NormalizedInterfaceStats(link_status="up")
    }
    result.member_errors = {"GigabitEthernet3/0/24": "member collection failed: x"}
    result.verdict = Verdict(
        VerdictCategory.PHYSICAL_MEDIA,
        "PHYSICAL_MEDIA — port-channel Po214: fault isolated to member "
        "GigabitEthernet3/0/23 — test reason.",
        member_findings={
            "GigabitEthernet3/0/23": "PHYSICAL_MEDIA — test member reason.",
            "GigabitEthernet3/0/24": "not evaluated: member collection failed: x",
        },
    )
    return result


def _member_result_with_siblings():
    cases, _ = ingest_csv(FIXTURES / "sample_top20.csv")
    member_case = next(case for case in cases if case.interface == "Po214")
    member_case.interface = "Gi3/0/23"
    result = CaseResult(case=member_case)
    result.platform = Platform.IOS_XE
    result.canonical_interface = "GigabitEthernet3/0/23"
    result.parent_portchannel = "Po214"
    result.stats = NormalizedInterfaceStats(link_status="up")
    result.member_stats = {
        "GigabitEthernet3/0/24": NormalizedInterfaceStats(link_status="up")
    }
    result.verdict = Verdict(
        VerdictCategory.IGNORE,
        "IGNORE — test reason for the reported member.",
        member_findings={
            "GigabitEthernet3/0/24": "PHYSICAL_MEDIA — test sibling reason."
        },
    )
    return result


def test_reports_label_siblings_as_context_for_a_member_case(tmp_path):
    """The same member list means something different here: these are the
    reported port's siblings, not the culprits behind its verdict."""
    results, findings = _results()
    results.append(_member_result_with_siblings())
    meta = {
        "csv_file": "x.csv",
        "baseline": {"matched": 0, "total": 9},
        "audit_log": "a.log",
    }

    paths = render_report(results, findings, meta, "report_en", tmp_path)

    txt = paths["txt"].read_text()
    assert "Other members of Po214" in txt
    assert "the verdict above is for Gi3/0/23 itself" in txt
    assert "Member interfaces:" not in txt
    assert "GigabitEthernet3/0/24: PHYSICAL_MEDIA — test sibling reason." in txt


def test_reports_render_the_member_breakdown(tmp_path):
    results, findings = _results()
    results.append(_po_result_with_members())
    meta = {
        "csv_file": "x.csv",
        "baseline": {"matched": 0, "total": 9},
        "audit_log": "a.log",
    }

    paths = render_report(results, findings, meta, "report_en", tmp_path)

    txt = paths["txt"].read_text()
    assert "Member interfaces:" in txt
    assert "GigabitEthernet3/0/23: PHYSICAL_MEDIA — test member reason." in txt
    html = paths["html"].read_text()
    assert "GigabitEthernet3/0/23" in html

    with paths["csv"].open(newline="") as handle:
        header, *rows = list(csv.reader(handle))
    member_column = header.index("member_summary")
    po_row = next(
        row for row in rows if "fault isolated" in row[header.index("reason")]
    )
    assert (
        "GigabitEthernet3/0/23=PHYSICAL_MEDIA — test member reason."
        in (po_row[member_column])
    )
    assert "GigabitEthernet3/0/24=not evaluated" in po_row[member_column]
    # Non-Po rows keep the cell empty.
    assert rows[0][member_column] == ""


def test_members_json_roundtrips_and_migrates_old_databases(tmp_path):
    import json
    import sqlite3

    db = tmp_path / "history.db"
    # A database created before the members_json column existed:
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE case_results ("
        "run_id INTEGER NOT NULL, switch TEXT, mgmt_ip TEXT, interface TEXT, "
        "counter TEXT, platform TEXT, verdict TEXT, reason TEXT, "
        "stats_json TEXT, repoll_stats_json TEXT, raw_outputs_json TEXT, "
        "collection_error TEXT, parse_errors_json TEXT)"
    )
    conn.commit()
    conn.close()

    history = History(db)  # migration adds the missing column in place
    run_id, _ = history.start_run("x.csv")
    history.save_results(run_id, [_po_result_with_members()])

    row = history._conn.execute(
        "SELECT members_json FROM case_results WHERE run_id=?", (run_id,)
    ).fetchone()
    payload = json.loads(row[0])
    assert payload["stats"]["GigabitEthernet3/0/23"]["link_status"] == "up"
    assert payload["baseline_stats"]["GigabitEthernet3/0/23"]["link_status"] == "up"
    assert payload["errors"] == {"GigabitEthernet3/0/24": "member collection failed: x"}
    history.close()


def test_baseline_columns_are_added_to_an_existing_database(tmp_path):
    """A pre-0.6.0 database gains the columns the comparison needs, in place.

    The retired repoll_* columns are left exactly where they are: dropping a
    column rewrites the table for no gain, and their data stays auditable.
    """
    import sqlite3

    db = tmp_path / "history.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE runs ("
        "id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, "
        "csv_file TEXT NOT NULL, repoll_minutes REAL, summary_json TEXT)"
    )
    conn.execute(
        "CREATE TABLE case_results ("
        "run_id INTEGER NOT NULL, switch TEXT, mgmt_ip TEXT, interface TEXT, "
        "counter TEXT, platform TEXT, verdict TEXT, reason TEXT, "
        "stats_json TEXT, repoll_stats_json TEXT, raw_outputs_json TEXT, "
        "collection_error TEXT, parse_errors_json TEXT, members_json TEXT, "
        "repoll_minutes REAL)"
    )
    conn.execute("INSERT INTO runs (started_at, csv_file) VALUES ('old', 'old.csv')")
    conn.commit()
    conn.close()

    history = History(db)
    run_id, _ = history.start_run("x.csv")
    history.save_results(run_id, [_po_result_with_members()])

    row = history._conn.execute(
        "SELECT canonical_interface, parent_portchannel, baseline_stats_json, "
        "baseline_minutes, baseline_taken_at, baseline_run_id, baseline_note "
        "FROM case_results WHERE run_id=?",
        (run_id,),
    ).fetchone()
    assert row[0] == "Port-channel214"
    assert len(row) == 7  # every baseline column exists on the migrated table
    # The retired columns survive untouched and are simply never written.
    legacy = history._conn.execute(
        "SELECT repoll_stats_json, repoll_minutes FROM case_results WHERE run_id=?",
        (run_id,),
    ).fetchone()
    assert legacy == (None, None)
    # The pre-existing run keeps a NULL stamp and is therefore never replayed.
    stamps = history._conn.execute("SELECT replay_schema FROM runs ORDER BY id")
    assert [value for (value,) in stamps] == [None, REPLAY_SCHEMA]
    history.close()


def test_provenance_block_appears_only_when_rebuilt_from_history(tmp_path):
    results, findings = _results()
    live = {"csv_file": "x.csv", "audit_log": "audit.log"}
    replayed = {
        "csv_file": "x.csv",
        "from_history": True,
        "collected_from": "run #7, collected 2026-08-29T20:29:21+00:00",
    }

    live_paths = render_report(results, findings, live, "report_en", tmp_path / "live")
    replay_paths = render_report(
        results, findings, replayed, "report_en", tmp_path / "replay"
    )

    for kind in ("html", "txt"):
        assert "stored collection" not in live_paths[kind].read_text().lower()
        rebuilt = replay_paths[kind].read_text()
        assert "stored collection" in rebuilt.lower()
        assert "run #7" in rebuilt
    assert "audit.log" in live_paths["html"].read_text()
    assert "audit" not in replay_paths["html"].read_text().lower()


def test_reports_say_per_case_what_was_compared_and_what_was_not(tmp_path):
    """Coverage is partial by design — the CSV changes from week to week — so a
    case that was never compared must never read like one that was."""
    results, findings = _results()
    compared = [
        r for r in results if r.verdict.category is VerdictCategory.PHYSICAL_MEDIA
    ]
    compared[0].baseline_stats = NormalizedInterfaceStats(crc_errors=1)
    compared[0].baseline_minutes = 1080.0
    compared[0].baseline_taken_at = datetime(2026, 8, 29, 14, 2, tzinfo=UTC)
    compared[0].baseline_run_id = 7
    compared[1].baseline_note = "no earlier sample stored for this interface"
    meta = {"csv_file": "x.csv", "baseline": {"matched": 1, "total": 9}}

    paths = render_report(results, findings, meta, "report_en", tmp_path)

    for kind in ("txt", "html"):
        # The HTML wraps mid-sentence; the claim is what matters, not the fill.
        text = " ".join(paths[kind].read_text().split())
        assert "Compared against the sample from 2026-08-29 14:02 UTC" in text
        assert "18.0 h earlier, run #7" in text
        assert "no earlier sample stored for this interface" in text
        assert "1 of 9 case(s) compared" in text

    with paths["csv"].open(newline="") as handle:
        header, *rows = list(csv.reader(handle))
    column = {name: index for index, name in enumerate(header)}
    windows = {row[column["baseline_window"]] for row in rows}
    assert windows == {"", "18.0 h"}


# ---- structured verdicts (v2 engine data model) ----------------------------


def _structured_verdict() -> Verdict:
    return Verdict(
        VerdictCategory.PHYSICAL_MEDIA,
        "PHYSICAL_MEDIA/HIGH zero_traffic_errors",
        confidence=Confidence.HIGH,
        signals=[
            Signal(
                kind=SignalKind.ZERO_TRAFFIC_ERRORS,
                weight=Confidence.HIGH,
                values={"errors_per_second": 9.26, "input_rate_pps": 0},
                supports=VerdictCategory.PHYSICAL_MEDIA,
            ),
            Signal(
                kind=SignalKind.LOW_FCS_DOES_NOT_CLEAR_MEDIA,
                weight=Confidence.LOW,
                values={"fcs_errors": 185},
                contradicts=True,
            ),
        ],
        data_quality=[
            DataQualityFlag(
                kind=DataQualityKind.STALE_POLL_TIMESTAMP,
                values={"staleness_minutes": 37548},
            )
        ],
        metrics=VerdictMetrics(
            errors_per_second=9.26,
            delta_tool_input_errors=1326250,
            delta_csv_change=112905,
            interval_minutes=2388.0,
            interval_source="host-side timestamps",
        ),
        what_would_change=Signal(
            kind=SignalKind.ERRORS_STOPPED_AFTER_CLEAR,
            weight=Confidence.HIGH,
        ),
    )


def test_structured_verdict_roundtrips():
    from iftriage.history import _verdict_from_json, _verdict_json

    verdict = _structured_verdict()
    restored = _verdict_from_json(_verdict_json(verdict))
    assert restored == verdict


def test_plain_verdict_roundtrips_with_v2_fields_at_defaults():
    from iftriage.history import _verdict_from_json, _verdict_json

    verdict = Verdict(VerdictCategory.IGNORE, "IGNORE — below threshold.")
    restored = _verdict_from_json(_verdict_json(verdict))
    assert restored == verdict
    assert restored is not None
    assert restored.confidence is None
    assert restored.signals == []


def test_unknown_signal_kinds_are_dropped_not_fatal():
    """A row written by a newer iftriage with a signal kind this reader does
    not know must still load — minus that signal, never with a crash."""
    import json

    from iftriage.history import _verdict_from_json, _verdict_json

    data = json.loads(_verdict_json(_structured_verdict()) or "{}")
    data["signals"].append({"kind": "from_the_future", "weight": "HIGH"})
    data["data_quality"].append({"kind": "also_new"})
    restored = _verdict_from_json(json.dumps(data))
    assert restored is not None
    assert len(restored.signals) == 2
    assert len(restored.data_quality) == 1


def test_save_results_persists_verdict_json(tmp_path):
    db = tmp_path / "history.db"
    history = History(db)
    run_id, _ = history.start_run("x.csv")
    result = _po_result_with_members()
    result.verdict = _structured_verdict()
    history.save_results(run_id, [result])

    from iftriage.history import _verdict_from_json

    (stored,) = history._conn.execute(
        "SELECT verdict_json FROM case_results WHERE run_id=?", (run_id,)
    ).fetchone()
    assert _verdict_from_json(stored) == result.verdict
    history.close()


def test_verdict_json_column_is_added_to_an_existing_database(tmp_path):
    import sqlite3

    db = tmp_path / "history.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE case_results ("
        "run_id INTEGER NOT NULL, switch TEXT, mgmt_ip TEXT, interface TEXT, "
        "counter TEXT, platform TEXT, verdict TEXT, reason TEXT, "
        "stats_json TEXT, raw_outputs_json TEXT, collection_error TEXT, "
        "parse_errors_json TEXT, members_json TEXT)"
    )
    conn.commit()
    conn.close()

    history = History(db)
    run_id, _ = history.start_run("x.csv")
    history.save_results(run_id, [_po_result_with_members()])
    row = history._conn.execute(
        "SELECT verdict_json FROM case_results WHERE run_id=?", (run_id,)
    ).fetchone()
    assert row is not None  # column exists on the migrated table
    history.close()
