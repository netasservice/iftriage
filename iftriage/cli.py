"""Command-line interface: `iftriage run top20.csv [--repoll 10] [--dry-run]`."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .collectors import (
    RunAborted,
    collect,
    mark_portchannel_duplicates,
    resolve_platform,
)
from .collectors import (
    repoll as repoll_pass,
)
from .config import load_config
from .history import History
from .ingest import IngestError, ingest_csv
from .models import Credentials, Platform
from .platforms import get_profile
from .report import build_summary, render_report
from .rules import evaluate_case
from .session import AuditLog


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iftriage",
        description="Read-only interface error triage for Splunk top-N delta CSVs.",
    )
    parser.add_argument(
        "--version", action="version", version=f"iftriage {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Triage every case in a top-N CSV")
    run.add_argument("csv", help="Path to the Splunk top-N CSV export")
    run.add_argument(
        "--repoll",
        type=float,
        default=None,
        metavar="MINUTES",
        help="Re-poll counters after N minutes (default: config value)",
    )
    run.add_argument(
        "--no-repoll", action="store_true", help="Skip the re-poll pass entirely"
    )
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="Print targets and exact commands; connect to nothing",
    )
    run.add_argument("--config", default=None, help="Path to config.yaml")
    run.add_argument("--output", default=None, help="Report/audit output directory")
    run.add_argument(
        "--workers", type=int, default=None, help="Override bounded concurrency"
    )
    run.add_argument("--db", default=None, help="Override SQLite history path")
    return parser


def _credentials_from_env_or_prompt() -> Credentials:
    username = os.environ.get("IFTRIAGE_USER") or input("Device username: ")
    password = os.environ.get("IFTRIAGE_PASS") or getpass.getpass(
        f"Password for {username}: "
    )
    enable = os.environ.get("IFTRIAGE_ENABLE")
    if enable is None:
        enable = getpass.getpass(
            "Enable secret (blank if accounts land in priv-exec): "
        )
    return Credentials(
        username=username, password=password, enable_secret=enable or None
    )


def _dry_run(cases, config, history) -> int:
    print("DRY RUN — connecting to nothing. Targets and exact commands:\n")
    by_ip: dict[str, list] = {}
    for case in cases:
        by_ip.setdefault(case.mgmt_ip, []).append(case)
    for ip, group in by_ip.items():
        hostname = group[0].switch
        platform = resolve_platform(ip, hostname, config, history, credentials=None)
        label = platform.value if platform else "UNKNOWN (will autodetect on connect)"
        print(f"== {hostname} ({ip}) — platform: {label}")
        platforms = [platform] if platform else list(Platform)
        for case in group:
            if case.excluded:
                print(
                    f"   -- {case.interface} [{case.counter}] EXCLUDED "
                    f"(data quality: {', '.join(case.dq_flags)})"
                )
                continue
            print(f"   -- {case.interface} [{case.counter}]")
            for plat in platforms:
                profile = get_profile(plat)
                try:
                    canonical = profile.canonical_interface(case.interface)
                except Exception as exc:
                    print(f"      {plat.value}: INTERFACE NAME ERROR: {exc}")
                    continue
                prefix = f"      {plat.value}: " if len(platforms) > 1 else "      "
                for command in profile.render_commands(canonical).values():
                    print(f"{prefix}{command}")
        print()
    print("No devices were contacted.")
    return 0


def _cmd_run(args) -> int:
    config = load_config(args.config)
    if args.workers:
        config.connection.workers = args.workers
    if args.db:
        config.db_path = args.db
    output_dir = Path(args.output or config.output_dir)

    try:
        cases, findings = ingest_csv(args.csv)
    except (IngestError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"Ingested {len(cases)} cases from {args.csv}; "
        f"{len(findings)} data-quality finding(s)."
    )
    for finding in findings:
        print(f"  [dq:{finding.kind}] {finding.detail}")

    if args.dry_run:
        history = History(config.db_path) if Path(config.db_path).exists() else None
        try:
            return _dry_run(cases, config, history)
        finally:
            if history:
                history.close()

    repoll_minutes: float | None
    if args.no_repoll:
        repoll_minutes = None
    else:
        repoll_minutes = (
            args.repoll if args.repoll is not None else config.repoll_default_minutes
        )

    history = History(config.db_path)
    history.archive_ingest(args.csv, Path(args.csv).read_text(), cases)
    run_id = history.start_run(args.csv, repoll_minutes)

    credentials = _credentials_from_env_or_prompt()
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    audit = AuditLog(output_dir / f"iftriage_audit_{stamp}.log")
    print(f"Audit log: {audit.path}")

    try:
        print(
            f"Collecting from {len({c.mgmt_ip for c in cases if not c.excluded})} "
            f"device(s), {config.connection.workers} workers max ..."
        )
        results = collect(cases, config, credentials, audit, history)

        if repoll_minutes:
            print(
                f"Waiting {repoll_minutes:g} min before re-poll "
                "(answers: is it still incrementing NOW?) ..."
            )
            time.sleep(repoll_minutes * 60)
            repoll_pass(results, config, credentials, audit, history, repoll_minutes)
    except RunAborted as exc:
        print(f"\nRUN ABORTED: {exc}", file=sys.stderr)
        history.finish_run(run_id, {"aborted": str(exc)})
        history.close()
        return 3

    for result in results:
        result.verdict = evaluate_case(
            case=result.case,
            stats=result.stats,
            repoll_stats=result.repoll_stats,
            repoll_minutes=result.repoll_minutes,
            thresholds=config.thresholds,
            collection_error=result.collection_error,
            parse_errors=result.parse_errors,
        )
        result.recurrence = history.recurrence_count(
            result.case.switch, result.case.interface
        )
    mark_portchannel_duplicates(results)

    history.save_results(run_id, results)
    summary = build_summary(results)
    history.finish_run(run_id, summary)
    history.close()

    meta = {
        "csv_file": args.csv,
        "repoll_minutes": repoll_minutes,
        "audit_log": str(audit.path),
    }
    paths = render_report(results, findings, meta, config.template, output_dir)

    print(f"\n{summary['line']}")
    print(f"Report (HTML): {paths['html']}")
    print(f"Report (text): {paths['txt']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
