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


def test_ingest_rejects_wrong_columns(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b,c\n1,2,3\n")
    import pytest

    from iftriage.ingest import IngestError

    with pytest.raises(IngestError):
        ingest_csv(bad)
