# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- MIT `LICENSE`, declared in `pyproject.toml` as a PEP 639 license expression
  (which raises the build requirement to `setuptools>=77`).
- `--user USERNAME` on `iftriage run`: the device username can now be passed as
  an argument. Resolution order per credential is flag (username only) →
  environment variable → terminal prompt. Passwords are still never accepted as
  arguments, only from `IFTRIAGE_PASS` / `IFTRIAGE_ENABLE` or `getpass`.
- Phase 2 validation: 21 sanitized fixtures transcribed from real fleet
  captures (Catalyst C9410R, Nexus, Arista DCS-7808-CH), including a live
  duplex-mismatch case, a vPC port-channel, an SFP-10G-SR DOM readout, a
  down/down breakout interface, and each platform's copper/empty transceiver
  response — all with real prompt/echo lines, which parsers now tolerate.
- NX-OS collects `show lldp neighbors interface <intf> detail` in addition to
  CDP (non-Cisco uplinks do not speak CDP); CDP wins the merge when present.
- Canonical field `duplex_mismatch_logged` set when filtered logging contains
  `%CDP-4-DUPLEX_MISMATCH` (corroborative only, never required).
- `limits` section in `config.yaml`: `max_output_bytes` (default 1000000) is a
  hard per-command ceiling enforced in `ReadOnlySession.get()`, and
  `evidence_max_lines` (default 300) bounds the head+tail copy of raw output
  stored in the history database and rendered in the report. Truncation is
  marked inline; parsers always receive the full output, so neither limit can
  change a verdict.

### Changed
- The enable secret is explicitly optional: an empty answer (or
  `IFTRIAGE_ENABLE=""`) runs without one, and a device that requires enable is
  skipped with `device skipped: ... requires enable but no enable secret was
  provided` (verdict `UNVERIFIED`) instead of being reported as a connection
  failure. It never counts towards the AAA circuit breaker.
- Credentials are resolved before the history database is opened, so abandoning
  a prompt no longer leaves an orphan run row.
- A credential prompt with no interactive terminal exits 2 with an actionable
  message instead of an `EOFError` traceback.
- Late-collision rule refined with the real fleet case: half-duplex local
  port whose neighbor reports full duplex (or with a logged duplex-mismatch
  event) is now `CONFIG_ISSUE` (confirmed mismatch), not `PHYSICAL_MEDIA`.

### Fixed
- Logging analysis is now scoped to the interface under analysis. Device-side
  `| include <name>` matches substrings, so output collected for
  `GigabitEthernet3/0/2` also contained `GigabitEthernet3/0/20`–`/29` events:
  `flap_count` counted a neighbouring port's flaps, and — with user-visible
  consequences — a neighbouring port's `%CDP-4-DUPLEX_MISMATCH` could
  corroborate this port's `CONFIG_ISSUE` verdict. Both fields are now derived
  only from lines that reference the target interface.
- NX-OS `counters errors`: the fourth (InDiscards) table block is now mapped
  to `discards_in`.
- EOS transceiver parser understands the breakout Slot/Channel row layout
  (`Ethernet3/25  3  ...` for `Et3/25/3`).
- Port-channel member tokens with EOS dense flags (`(PG+)`, `(af^)`) parse
  correctly; NX-OS member lists that wrap onto continuation lines were
  already handled and are now covered by a real fixture.
- CDP/LLDP neighbor parsing: port ids containing spaces (`Port 1` on IP
  phones) are captured whole, and NX-OS's lowercase `Port id:` is matched.

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
