"""CSV ingest + data-quality checks.

Data-quality anomalies get their own report section; they are surfaced, not
analyzed. Cross-device byte-identical counter pairs are excluded from live
collection (known duplicated-indexing artifact in the source data).
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from .models import DataQualityFinding, InterfaceCase

EXPECTED_COLUMNS = [
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
]


class IngestError(ValueError):
    pass


def _to_int(value) -> int | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    try:
        return int(float(str(value).strip().replace(",", "")))
    except (ValueError, TypeError):
        return None


def ingest_csv(
    path: str | Path,
) -> tuple[list[InterfaceCase], list[DataQualityFinding]]:
    path = Path(path)
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df.columns = [column.strip() for column in df.columns]

    missing = [column for column in EXPECTED_COLUMNS if column not in df.columns]
    if missing:
        raise IngestError(
            f"CSV is missing expected columns: {missing}. Found: {list(df.columns)}"
        )

    cases: list[InterfaceCase] = []
    for idx, row in df.iterrows():
        cases.append(
            InterfaceCase(
                poll_time=str(row["_time"]).strip(),
                switch=str(row["switch"]).strip(),
                mgmt_ip=str(row["mgmt_ip"]).strip(),
                interface=str(row["interface"]).strip(),
                description=str(row["description"]).strip(),
                status=str(row["status"]).strip(),
                protocol=str(row["protocol"]).strip(),
                counter=str(row["counter"]).strip(),
                prev_count=_to_int(row["prev_count"]),
                count=_to_int(row["count"]),
                change=_to_int(row["change"]),
                row_index=int(idx),
                raw_row={column: str(row[column]) for column in df.columns},
            )
        )

    findings = _data_quality_checks(cases)
    return cases, findings


def _data_quality_checks(cases: list[InterfaceCase]) -> list[DataQualityFinding]:
    findings: list[DataQualityFinding] = []

    # 1. Byte-identical counter values across DIFFERENT devices.
    by_values: dict[tuple, list[InterfaceCase]] = {}
    for case in cases:
        if not case.prev_count and not case.count:
            continue  # all-zero rows are not evidence of duplication
        key = (case.counter, case.prev_count, case.count)
        by_values.setdefault(key, []).append(case)
    for (counter, prev, count), group in by_values.items():
        switches = {row.switch for row in group}
        if len(switches) > 1:
            for case in group:
                case.dq_flags.append("cross_device_identical")
                case.excluded = True
            findings.append(
                DataQualityFinding(
                    kind="cross_device_identical",
                    detail=(
                        f"Identical {counter} values (prev={prev}, count={count}) "
                        f"reported by different switches: "
                        f"{', '.join(sorted(switches))}. "
                        "Physically near-impossible — indicates duplicated "
                        "indexing/collection at the source. Excluded from analysis."
                    ),
                    rows=[row.row_index for row in group],
                )
            )

    # 2. Negative deltas (counter reset / device reload). Flagged, still analyzed.
    for case in cases:
        if case.change is not None and case.change < 0:
            case.dq_flags.append("negative_delta")
            findings.append(
                DataQualityFinding(
                    kind="negative_delta",
                    detail=(
                        f"{case.switch} {case.interface} {case.counter}: negative "
                        f"delta ({case.change}) — counter reset or device reload "
                        "during the window. Delta is not meaningful; live "
                        "verification decides."
                    ),
                    rows=[case.row_index],
                )
            )

    # 3. Duplicate device+interface entries.
    by_target: dict[tuple, list[InterfaceCase]] = {}
    for case in cases:
        by_target.setdefault((case.switch, case.interface, case.counter), []).append(
            case
        )
    for (switch, interface, counter), group in by_target.items():
        if len(group) > 1:
            for case in group:
                case.dq_flags.append("duplicate_entry")
            findings.append(
                DataQualityFinding(
                    kind="duplicate_entry",
                    detail=(
                        f"{switch} {interface} {counter} listed "
                        f"{len(group)} times with values "
                        f"{[(row.prev_count, row.count) for row in group]}."
                    ),
                    rows=[row.row_index for row in group],
                )
            )

    # 4. Misaligned _time windows (they never align — always note it).
    times = sorted({row.poll_time for row in cases if row.poll_time})
    if len(times) > 1:
        findings.append(
            DataQualityFinding(
                kind="time_misalignment",
                detail=(
                    f"Poll timestamps span {times[0]} .. {times[-1]}: the 24h "
                    "windows are NOT aligned across rows. Deltas are not directly "
                    "comparable between rows."
                ),
                rows=[],
            )
        )

    return findings
