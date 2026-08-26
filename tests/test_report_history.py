"""Smoke tests: report rendering and SQLite history round-trip."""

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
