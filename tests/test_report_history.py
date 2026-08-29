"""Smoke tests: report rendering and SQLite history round-trip."""

import csv
from importlib.resources import files

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
        "repoll_minutes": 10,
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
        "repoll_minutes": 10,
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

    run_id = history.start_run("sample_top20.csv", 10)
    results, _ = _results()
    history.save_results(run_id, results)
    history.finish_run(run_id, build_summary(results))

    assert history.get_platform("10.9.9.9") is None
    history.set_platform("10.9.9.9", Platform.EOS)
    assert history.get_platform("10.9.9.9") is Platform.EOS
    history.set_platform("10.9.9.9", Platform.NXOS)  # upsert
    assert history.get_platform("10.9.9.9") is Platform.NXOS
    history.close()
