"""Email-ready report rendering (Jinja2 HTML + plain text, plus enriched CSV)."""

from __future__ import annotations

import csv
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .models import VERDICT_ORDER, CaseResult, DataQualityFinding, VerdictCategory

# NormalizedInterfaceStats fields the rules engine actually consults, echoed
# into the enriched CSV under the same names.
_CSV_STATS_FIELDS = (
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
)

_CSV_ANALYSIS_COLUMNS = (
    "verdict",
    "reason",
    "platform",
    *_CSV_STATS_FIELDS,
    "dq_flags",
    "duplicate_of",
    "recurrence",
)


def build_summary(results: list[CaseResult]) -> dict:
    counts = Counter(
        result.verdict.category for result in results if result.verdict is not None
    )
    ordered = [
        (category.value, counts.get(category, 0))
        for category in VERDICT_ORDER
        if counts.get(category, 0)
    ]
    line = f"{len(results)} cases: " + ", ".join(
        f"{count} {name}" for name, count in ordered
    )
    return {
        "total": len(results),
        "counts": {name: count for name, count in ordered},
        "line": line,
    }


def _analysis_cells(result: CaseResult) -> list[str]:
    verdict = result.verdict
    stats = result.stats
    cells = [
        verdict.category.value if verdict else "",
        verdict.reason if verdict else "",
        result.platform.value if result.platform else "",
    ]
    for field_name in _CSV_STATS_FIELDS:
        # None means "unknown / not parsed": render an empty cell, never 0.
        value = getattr(stats, field_name) if stats else None
        cells.append("" if value is None else str(value))
    cells.append(";".join(result.case.dq_flags))
    cells.append(result.duplicate_of or "")
    cells.append(str(result.recurrence))
    return cells


def _write_csv(results: list[CaseResult], path: Path) -> None:
    """Write the input table back out with analysis columns appended.

    Rows keep the original CSV order (row_index), and the base columns are the
    original header verbatim — including columns iftriage does not parse. A
    plain csv.writer (not DictWriter) keeps an input column that happens to
    share a name with an appended column from colliding.
    """
    ordered = sorted(results, key=lambda result: result.case.row_index)
    base_columns = list(ordered[0].case.raw_row.keys()) if ordered else []
    try:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(base_columns + list(_CSV_ANALYSIS_COLUMNS))
            for result in ordered:
                base_cells = [
                    result.case.raw_row.get(column, "") for column in base_columns
                ]
                writer.writerow(base_cells + _analysis_cells(result))
    except OSError as exc:
        raise OSError(f"Failed to write CSV report {path}: {exc}") from exc


def render_report(
    results: list[CaseResult],
    findings: list[DataQualityFinding],
    meta: dict,
    template_base: str,
    out_dir: str | Path,
) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=PackageLoader("iftriage", "templates"),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    order = {category: idx for idx, category in enumerate(VERDICT_ORDER)}
    sorted_results = sorted(
        results,
        key=lambda r: (
            order.get(r.verdict.category, 99) if r.verdict else 99,
            r.case.switch,
            r.case.interface,
        ),
    )

    context = {
        "summary": build_summary(results),
        "results": sorted_results,
        "findings": findings,
        "meta": meta,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "VerdictCategory": VerdictCategory,
    }

    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    paths: dict[str, Path] = {}
    for kind, suffix in (("html", "html.j2"), ("txt", "txt.j2")):
        template = env.get_template(f"{template_base}.{suffix}")
        rendered = template.render(**context)
        path = out_dir / f"iftriage_report_{stamp}.{kind}"
        path.write_text(rendered, encoding="utf-8")
        paths[kind] = path

    csv_path = out_dir / f"iftriage_report_{stamp}.csv"
    _write_csv(results, csv_path)
    paths["csv"] = csv_path
    return paths
