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
    abort_if_nothing_collected,
    collect,
    collect_members,
    mark_portchannel_duplicates,
    repoll_eligible,
    resolve_platform,
)
from .collectors import (
    repoll as repoll_pass,
)
from .config import load_config
from .history import History
from .ingest import IngestError, ingest_csv
from .models import Credentials, Platform
from .normalize import is_portchannel_name
from .platforms import get_profile
from .platforms.base import PORTCHANNEL_KEY
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
    run.add_argument(
        "--user",
        default=None,
        metavar="USERNAME",
        help="Device username (default: $IFTRIAGE_USER, else prompt). "
        "Passwords are never accepted as arguments.",
    )
    run.add_argument("--config", default=None, help="Path to config.yaml")
    run.add_argument("--output", default=None, help="Report/audit output directory")
    run.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Contact N devices at the same time (default: 1, one session at a "
        "time). Raising this weakens the AAA circuit breaker — see README.",
    )
    run.add_argument("--db", default=None, help="Override SQLite history path")
    return parser


class CredentialError(Exception):
    """Credentials could not be resolved (missing value, or no usable stdin)."""


def _ask(label: str, *, secret: bool) -> str:
    """Read one credential from the terminal.

    A closed or absent stdin (piped input, cron) would otherwise surface as a
    bare EOFError traceback; it becomes an actionable message instead.
    """
    try:
        return getpass.getpass(label) if secret else input(label)
    except (EOFError, KeyboardInterrupt, OSError) as exc:
        raise CredentialError(
            "cannot prompt for credentials without an interactive terminal — "
            "pass --user and set IFTRIAGE_PASS (and IFTRIAGE_ENABLE if the "
            "fleet needs enable)"
        ) from exc


def _resolve_credentials(username_arg: str | None) -> Credentials:
    """Resolve credentials: CLI flag -> environment -> interactive prompt.

    Passwords are deliberately never accepted as arguments; they would land in
    the shell history and in `ps` output.
    """
    username = (
        username_arg
        or os.environ.get("IFTRIAGE_USER")
        or _ask("Device username: ", secret=False)
    )
    if not username:
        raise CredentialError(
            "no username provided — pass --user, set IFTRIAGE_USER, "
            "or answer the prompt"
        )
    password = os.environ.get("IFTRIAGE_PASS") or _ask(
        f"Password for {username}: ", secret=True
    )
    # An enable secret that is set but empty means "this fleet needs no enable"
    # and suppresses the prompt; a blank answer at the prompt means the same.
    enable = os.environ.get("IFTRIAGE_ENABLE")
    if enable is None:
        enable = _ask(
            "Enable secret (Enter to skip; devices that require it stay UNVERIFIED): ",
            secret=True,
        )
    return Credentials(
        username=username, password=password, enable_secret=enable or None
    )


def _conditional_note(profile, key: str, case_is_portchannel: bool) -> str:
    """Flag the one command the run may decide not to send after all."""
    if key != PORTCHANNEL_KEY or case_is_portchannel:
        return ""
    if not profile.reports_portchannel_membership:
        return "   [always sent: the only way to learn membership here]"
    return "   [only if this port turns out to be a bundle member]"


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
                is_po = is_portchannel_name(case.interface)
                for key, command in profile.render_commands(canonical).items():
                    print(f"{prefix}{command}{_conditional_note(profile, key, is_po)}")
            if is_portchannel_name(case.interface):
                print(
                    "      NOTE: port-channel — members are discovered "
                    "on-device from the summary and each member is then "
                    "polled with the per-interface command set."
                )
        print()
    print("No devices were contacted.")
    return 0


def _cmd_run(args) -> int:
    try:
        config = load_config(args.config)
    except Exception as exc:  # malformed YAML must not surface as a traceback
        print(f"error: could not load configuration: {exc}", file=sys.stderr)
        return 2
    if args.workers < 1:
        print(
            f"error: --workers must be at least 1 (got {args.workers})",
            file=sys.stderr,
        )
        return 2
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

    # Resolved before the history database is opened so that abandoning a
    # prompt does not leave an orphan run row behind.
    try:
        credentials = _resolve_credentials(args.user)
    except CredentialError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    history = History(config.db_path)
    try:
        history.archive_ingest(args.csv, Path(args.csv).read_text(), cases)
        run_id = history.start_run(args.csv, repoll_minutes)

        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        audit = AuditLog(output_dir / f"iftriage_audit_{stamp}.log")
        print(f"Audit log: {audit.path}")

        try:
            device_count = len({case.mgmt_ip for case in cases if not case.excluded})
            pace = (
                "one session at a time"
                if args.workers == 1
                else f"up to {args.workers} devices at a time"
            )
            print(f"Collecting from {device_count} device(s), {pace} ...")
            results = collect(cases, config, credentials, audit, history, args.workers)
            abort_if_nothing_collected(results)

            member_cases = collect_members(
                results, config, credentials, audit, history, args.workers
            )
            if member_cases:
                print(
                    f"Collected member interfaces for {member_cases} "
                    "port-channel case(s)."
                )

            if repoll_minutes and not repoll_eligible(results):
                # Every device was deliberately skipped (the abort gate above
                # already handled outright failures): nothing to re-sample.
                print("Skipping re-poll wait: no collected interfaces to re-sample.")
                repoll_minutes = None
            if repoll_minutes:
                print(
                    f"Waiting {repoll_minutes:g} min before re-poll "
                    "(answers: is it still incrementing NOW?) ..."
                )
                time.sleep(repoll_minutes * 60)
                repoll_pass(
                    results,
                    config,
                    credentials,
                    audit,
                    history,
                    repoll_minutes,
                    args.workers,
                )
        except RunAborted as exc:
            print(f"\nRUN ABORTED: {exc}", file=sys.stderr)
            history.finish_run(run_id, {"aborted": str(exc)})
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
                member_stats=result.member_stats,
                member_repoll_stats=result.member_repoll_stats,
                member_errors=result.member_errors,
                parent_portchannel=result.parent_portchannel,
            )
            result.recurrence = history.recurrence_count(
                result.case.switch, result.case.interface
            )
        mark_portchannel_duplicates(results)

        history.save_results(run_id, results)
        summary = build_summary(results)
        history.finish_run(run_id, summary)
    finally:
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
    print(f"Report (CSV):  {paths['csv']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
