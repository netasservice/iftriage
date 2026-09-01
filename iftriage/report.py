"""Email-ready report rendering (Jinja2 HTML + plain text, plus enriched CSV)."""

from __future__ import annotations

import csv
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .models import VERDICT_ORDER, CaseResult, DataQualityFinding, VerdictCategory
from .rules import format_window

# NormalizedInterfaceStats fields the rules engine actually consults, echoed
# into the enriched CSV under the same names.
_CSV_STATS_FIELDS = (
    "link_status",
    "protocol_status",
    "duplex",
    "speed",
    "media_type",
    "mtu",
    "input_errors",
    "crc_errors",
    "fcs_errors",
    "rcv_err",
    "runts",
    "giants",
    "overrun",
    "ignored",
    "no_buffer",
    "late_collisions",
    "discards_in",
    "discards_out",
    "interface_resets",
    "dom_rx_power_dbm",
    "dom_tx_power_dbm",
    "neighbor_name",
    "neighbor_port",
    "flap_count",
)

_CSV_ANALYSIS_COLUMNS = (
    "verdict",
    "confidence",
    "reason",
    "platform",
    *_CSV_STATS_FIELDS,
    "delta_tool",  # the tool's own run-to-run delta of the flagged counter
    "delta_csv",  # the CSV `change` column, echoed with its label
    "interval_source",  # where the delta's window length came from
    "data_quality",  # semicolon-joined data-quality flag kinds
    "dq_flags",
    "duplicate_of",
    "recurrence",
    "baseline_taken_at",  # empty when the verdict rests on one sample
    "baseline_window",
    "member_summary",  # port-channel cases: one finding per member
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
        verdict.confidence.value if verdict and verdict.confidence else "",
        verdict.reason if verdict else "",
        result.platform.value if result.platform else "",
    ]
    for field_name in _CSV_STATS_FIELDS:
        # None means "unknown / not parsed": render an empty cell, never 0.
        value = getattr(stats, field_name) if stats else None
        cells.append("" if value is None else str(value))
    metrics = verdict.metrics if verdict else None
    cells.append(
        "" if metrics is None or metrics.delta_tool is None else str(metrics.delta_tool)
    )
    cells.append(
        "" if metrics is None or metrics.delta_csv is None else str(metrics.delta_csv)
    )
    cells.append(metrics.interval_source or "" if metrics else "")
    cells.append(
        ";".join(flag.kind.value for flag in verdict.data_quality) if verdict else ""
    )
    cells.append(";".join(result.case.dq_flags))
    cells.append(result.duplicate_of or "")
    cells.append(str(result.recurrence))
    cells.append(
        result.baseline_taken_at.isoformat() if result.baseline_taken_at else ""
    )
    cells.append(
        format_window(result.baseline_minutes)
        if result.baseline_taken_at is not None
        else ""
    )
    findings = dict(verdict.member_findings) if verdict else {}
    for member, error in result.member_errors.items():
        findings.setdefault(member, f"not evaluated: {error}")
    cells.append("; ".join(f"{name}={text}" for name, text in findings.items()))
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
    env.globals["window"] = format_window

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
