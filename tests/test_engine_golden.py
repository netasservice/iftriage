"""The reference case, end to end: real fixtures -> real parser -> engine ->
rendered reports. Massive Rcv-Err with near-zero FCS on a copper port carrying
no traffic must come out PHYSICAL_MEDIA / HIGH, with the FCS count presented
as evidence against (explained, verdict retained) and no impossible
percentage anywhere in the rendered output. Zero device access."""

import re
from datetime import UTC, datetime

from conftest import FIXTURES, load_fixture
from test_rules import make_case

from iftriage.config import Thresholds
from iftriage.history import REPLAY_SCHEMA
from iftriage.ingest import ingest_csv
from iftriage.metrics import reconcile_input_errors, unattributed_rx
from iftriage.models import (
    CaseResult,
    Confidence,
    DataQualityKind,
    NormalizedInterfaceStats,
    Platform,
    SignalKind,
    VerdictCategory,
)
from iftriage.platforms import get_profile
from iftriage.platforms.base import COMMAND_KEYS
from iftriage.report import render_report
from iftriage.rules import evaluate_case

REPORT_TIME = datetime(2026, 9, 1, 17, 53, tzinfo=UTC)
WINDOW_MINUTES = 39.8 * 60


def golden_stats() -> NormalizedInterfaceStats:
    """Parse the sanitized Gi8/0/4 captures with the real IOS-XE parser and
    merge them in collector order (later commands win)."""
    profile = get_profile(Platform.IOS_XE)
    fixtures = {
        "version": "real_show_version_c9410.txt",
        "interface": "real_show_interfaces_gi8_0_4.txt",
        "counters": "real_counters_errors_gi8_0_4.txt",
    }
    merged: dict = {}
    for key in COMMAND_KEYS:
        if key in fixtures:
            parsed = profile.parse(
                key, load_fixture("ios_xe", fixtures[key]), "GigabitEthernet8/0/4"
            )
            merged.update(
                {name: value for name, value in parsed.items() if value is not None}
            )
    return NormalizedInterfaceStats(**merged)


def golden_baseline(stats: NormalizedInterfaceStats) -> NormalizedInterfaceStats:
    """The run-#11 sample: same interface, 1,326,250 fewer errors, 39.8 h
    earlier by the device's own uptime."""
    earlier = NormalizedInterfaceStats(**vars(stats))
    earlier.input_errors = stats.input_errors - 1_326_250
    earlier.rcv_err = stats.rcv_err - 1_326_250
    earlier.uptime_minutes = stats.uptime_minutes - WINDOW_MINUTES
    return earlier


def golden_case():
    case = make_case("Rcv-Err", change=112_905)
    case.poll_time = "2026-08-06T12:00:00"
    case.interface = "Gi8/0/4"
    return case


def golden_verdict():
    stats = golden_stats()
    return evaluate_case(
        golden_case(),
        stats,
        golden_baseline(stats),
        WINDOW_MINUTES,
        Thresholds(),
        report_time=REPORT_TIME,
    ), stats


def test_golden_fixture_numbers_reconcile():
    stats = golden_stats()
    assert stats.input_errors == 320_792_846
    assert stats.rcv_err == 316_073_999
    assert stats.runts == 4_718_847
    assert stats.fcs_errors == 185
    assert stats.media_type == "10/100/1000BaseTX"
    assert stats.counters_never_cleared is True
    reconciliation = reconcile_input_errors(stats)
    assert reconciliation is not None and reconciliation.balanced
    assert unattributed_rx(stats) == 316_073_814


def test_golden_verdict_is_physical_media_high():
    verdict, _ = golden_verdict()
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert verdict.confidence is Confidence.HIGH
    kinds = {signal.kind for signal in verdict.signals}
    assert SignalKind.ZERO_TRAFFIC_ERRORS in kinds
    assert SignalKind.UNATTRIBUTED_RX_DOMINANT in kinds
    assert SignalKind.SPEED_BELOW_CAPABILITY in kinds
    # Bytes-per-frame above MTU is a corollary of the zero-traffic
    # observation (bytes with almost no counted frames), not independent
    # evidence — the zero-traffic verdict must not list it.
    assert SignalKind.BYTES_PER_FRAME_ABOVE_MTU not in kinds
    # 7 resets over the device's ~2.9-year uptime is ~2.4/year —
    # maintenance noise, not evidence of a current fault; the time-normalized
    # rule suppresses it.
    assert SignalKind.INTERFACE_RESETS not in kinds


def test_golden_fcs_is_evidence_against_not_supporting():
    verdict, _ = golden_verdict()
    against = [signal for signal in verdict.signals if signal.contradicts]
    assert any(
        signal.kind is SignalKind.LOW_FCS_DOES_NOT_CLEAR_MEDIA
        and signal.values["fcs_errors"] == 185
        for signal in against
    )


def test_golden_data_quality_flags():
    verdict, _ = golden_verdict()
    kinds = {flag.kind for flag in verdict.data_quality}
    # ~26 days between the CSV poll and the report run.
    assert DataQualityKind.STALE_POLL_TIMESTAMP in kinds
    # CSV says 112,905; the tool's own delta is 1,326,250.
    assert DataQualityKind.DELTA_SOURCE_DISAGREEMENT in kinds
    assert verdict.metrics.delta_tool == 1_326_250
    assert verdict.metrics.delta_csv == 112_905
    # The interval came from the device's own uptime difference.
    assert verdict.metrics.interval_source == "device clock (uptime delta)"


def _rendered_golden(tmp_path):
    verdict, stats = golden_verdict()
    cases, findings = ingest_csv(FIXTURES / "sample_top20.csv")
    result = CaseResult(case=golden_case())
    result.platform = Platform.IOS_XE
    result.canonical_interface = "GigabitEthernet8/0/4"
    result.stats = stats
    result.baseline_minutes = WINDOW_MINUTES
    result.baseline_taken_at = datetime(2026, 8, 30, 2, 5, tzinfo=UTC)
    result.baseline_run_id = 11
    result.verdict = verdict
    meta = {
        "csv_file": "top20.csv",
        "baseline": {"matched": 1, "total": 1},
        "audit_log": "audit.log",
        "error_rate_percent": 0.001,
        "discard_rate_percent": 1.0,
    }
    return render_report([result], findings[:0], meta, "report_en", tmp_path)


def test_golden_rendered_output_has_no_impossible_percentage(tmp_path):
    paths = _rendered_golden(tmp_path)
    percent = re.compile(r"(\d[\d,]*(?:\.\d+)?)\s?%")
    for key in ("html", "txt"):
        text = paths[key].read_text()
        for match in percent.finditer(text):
            value = float(match.group(1).replace(",", ""))
            assert value <= 100, f"impossible percentage {value}% in {key} report"


def test_golden_rendered_output_never_mentions_transceivers_on_copper(tmp_path):
    paths = _rendered_golden(tmp_path)
    for key in ("html", "txt"):
        assert "transceiver" not in paths[key].read_text().lower()


def test_golden_rendered_output_labels_both_deltas_and_staleness(tmp_path):
    paths = _rendered_golden(tmp_path)
    text = paths["txt"].read_text()
    assert "Delta (iftriage, run-to-run): 1,326,250" in text
    assert "Delta (CSV, Splunk window): 112,905" in text
    assert "device clock (uptime delta)" in text
    assert "old at report time" in text  # the staleness headline
    html = paths["html"].read_text()
    assert "Δ (iftriage, run-to-run)" in html
    assert "Δ (CSV, Splunk window)" in html
    # The old hardcoded label must be gone for good.
    assert "Δ24h" not in html
    assert "delta24h" not in text


def test_golden_zero_traffic_narrative_names_its_counters(tmp_path):
    paths = _rendered_golden(tmp_path)
    text = paths["txt"].read_text()
    assert "1,326,250" in text  # the delta that drove the verdict
    assert "316,073,814" in text  # the unattributed residual, not the total
    assert "185" in text  # the contradicting FCS count, explained
    assert "Evidence against" in text


def test_replay_schema_bumped_for_v2():
    assert REPLAY_SCHEMA == 3


def test_golden_next_steps_are_media_aware_and_separated(tmp_path):
    """Copper remediation: jack/patch-cord language, DOM absence explained as
    expected, and the disruptive actions (TDR, manual clear) labeled apart."""
    paths = _rendered_golden(tmp_path)
    text = paths["txt"].read_text()
    assert "non-disruptive" in text
    assert "Disruptive, coordinate first" in text
    assert "test cable-diagnostics tdr" in text
    assert "DOM is not implemented on this copper port" in text
    assert "expected, not a finding" in text


def test_fiber_case_does_mention_the_transceiver(tmp_path):
    """Guard against over-suppression: optical remediation must still talk
    about the transceiver."""
    from iftriage.config import Thresholds

    stats = NormalizedInterfaceStats(
        link_status="up",
        protocol_status="up",
        duplex="full",
        input_packets=1_000_000,
        input_errors=100,
        crc_errors=100,
        late_collisions=0,
        collisions=0,
        runts=0,
        giants=0,
        discards_in=0,
        discards_out=0,
        dom_rx_power_dbm=-18.0,
        counters_never_cleared=False,
        last_clearing_minutes=1440.0,
    )
    case = make_case("Rcv-Err")
    verdict = evaluate_case(case, stats, None, None, Thresholds())
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    result = CaseResult(case=case)
    result.platform = Platform.NXOS
    result.stats = stats
    result.verdict = verdict
    meta = {"csv_file": "top20.csv", "audit_log": "audit.log"}
    paths = render_report([result], [], meta, "report_en", tmp_path)
    for key in ("html", "txt"):
        assert "transceiver" in paths[key].read_text().lower()


def test_enriched_csv_carries_confidence_and_labeled_deltas(tmp_path):
    import csv as csv_module

    paths = _rendered_golden(tmp_path)
    with paths["csv"].open(newline="") as handle:
        header, row = list(csv_module.reader(handle))
    column = {name: index for index, name in enumerate(header)}
    assert row[column["confidence"]] == "HIGH"
    assert row[column["delta_tool"]] == "1326250"
    assert row[column["delta_csv"]] == "112905"
    assert row[column["interval_source"]] == "device clock (uptime delta)"
    assert "stale_poll_timestamp" in row[column["data_quality"]]
    assert row[column["rcv_err"]] == "316073999"
    assert row[column["runts"]] == "4718847"
