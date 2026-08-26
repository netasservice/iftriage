# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-08-25

### Added
- Initial Phase 1 implementation (built and tested entirely against fixtures,
  zero device access):
  - `ReadOnlySession` with the four safety layers: single egress point, closed
    allow-list (fail closed), prompt/mode verification with abort-on-config-mode,
    and a timestamped audit trail that never records secrets.
  - `PlatformProfile` registry with IOS-XE, NX-OS, and EOS profiles: command
    templates (7 commands per platform), built-in parsers per command, and
    interface-name normalization (`Gi3/0/20` → `GigabitEthernet3/0/20`, platform
    canonical `Po` forms, regex-validated, fail closed on unknown prefixes).
  - Verdict engine (`rules.py`, pure functions): normalized error rates
    (error_delta / packet_delta), late-collision duplex-mismatch detection, DOM
    range checks, discard/capacity classification, and fail-closed `PARSE_ERROR`
    on any missing critical field.
  - CSV ingest with data-quality checks: cross-device byte-identical values
    (excluded from analysis), negative deltas, duplicate entries, and `_time`
    window misalignment.
  - Collection orchestration: bounded concurrency, jitter, per-device timeout,
    AAA circuit breaker (2 consecutive auth failures abort the run), optional
    re-poll pass, port-channel member deduplication, platform detection via
    override → SQLite cache → Netmiko `SSHDetect`.
  - SQLite history: raw CSV archive before analysis, per-run results,
    IP→platform cache, per-interface recurrence counts.
  - Email-ready HTML + plain-text report (Jinja2), with executive summary,
    separate data-quality section, and collapsed raw evidence per case.
  - CLI: `iftriage run <csv> [--repoll N] [--no-repoll] [--dry-run] [--workers N]
    [--config] [--output] [--db]`; `--dry-run` prints exact commands and
    connects to nothing.
  - Test suite: 76 tests over safety layers, normalization, rules, parsers
    (against raw fixtures), ingest, history, report, and CLI dry-run.
