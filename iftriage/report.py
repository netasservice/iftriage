"""Email-ready report rendering (Jinja2 HTML + plain text)."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .models import VERDICT_ORDER, CaseResult, DataQualityFinding, VerdictCategory


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
    return paths
