from conftest import FIXTURES

from iftriage.ingest import ingest_csv


def test_ingest_sample_csv():
    cases, findings = ingest_csv(FIXTURES / "sample_top20.csv")
    assert len(cases) == 9

    kinds = {finding.kind for finding in findings}
    assert kinds == {
        "cross_device_identical",
        "negative_delta",
        "duplicate_entry",
        "time_misalignment",
    }

    by_switch = {}
    for case in cases:
        by_switch.setdefault(case.switch, []).append(case)

    # Byte-identical values across different devices: flagged AND excluded.
    for switch in ("sw-d", "sw-e"):
        (case,) = by_switch[switch]
        assert case.excluded
        assert "cross_device_identical" in case.dq_flags

    # Negative delta: flagged, still analyzed.
    (reset_case,) = by_switch["sw-f"]
    assert "negative_delta" in reset_case.dq_flags
    assert not reset_case.excluded

    # Duplicate same device+interface entries: flagged.
    for case in by_switch["sw-g"]:
        assert "duplicate_entry" in case.dq_flags

    # Normal cases untouched.
    (normal,) = by_switch["sw-a"]
    assert not normal.dq_flags
    assert not normal.excluded
    assert normal.prev_count == 1000
    assert normal.count == 4271
    assert normal.change == 3271

    # The raw row is retained verbatim for the enriched CSV report.
    assert len(normal.raw_row) == 11
    assert normal.raw_row["switch"] == "sw-a"
    assert normal.raw_row["change"] == "3271"


def test_ingest_raw_row_keeps_extra_columns(tmp_path):
    extended = tmp_path / "extended.csv"
    extended.write_text(
        "_time,switch,mgmt_ip,interface,description,status,protocol,"
        "counter,prev_count,count,change,site_code\n"
        "2026-08-24T03:12:00,sw-a,10.0.0.1,Gi1/0/1,desc,up,up,Rcv-Err,1,2,1,MTY\n"
    )
    cases, _ = ingest_csv(extended)
    (case,) = cases
    assert list(case.raw_row) == [
        "_time",
        "switch",
        "mgmt_ip",
        "interface",
        "description",
        "status",
        "protocol",
        "counter",
        "prev_count",
        "count",
        "change",
        "site_code",
    ]
    assert case.raw_row["site_code"] == "MTY"


def test_ingest_rejects_wrong_columns(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b,c\n1,2,3\n")
    import pytest

    from iftriage.ingest import IngestError

    with pytest.raises(IngestError):
        ingest_csv(bad)
