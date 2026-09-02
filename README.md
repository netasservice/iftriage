# iftriage — Interface Error Triage Tool

Read-only triage for the recurring "Top 20 Interface Error Deltas, 24h" CSV
derived from Splunk. For each row, iftriage connects (READ-ONLY) to the listed
device, collects targeted diagnostics for the reported interface, applies a
rules engine, and produces an email-ready verdict report with raw evidence.

**Division of labor:** Splunk decides WHO is suspicious (the top-20 list).
iftriage decides WHETHER they are guilty (live verification). iftriage never
polls the full fleet — only the devices in the CSV.

| | |
|---|---|
| **Input** | one CSV export, 11 columns ([format](#input-the-splunk-csv)) |
| **Output** | HTML + text + enriched CSV report, session audit log, SQLite history ([example](#what-you-get)) |
| **Verdicts** | `PHYSICAL_MEDIA` · `LINK_NEGOTIATION` · `CONGESTION_BUFFER` · `HISTORIC_NOT_ACTIVE` · `INSUFFICIENT_DATA` · `IGNORE` · `UNVERIFIED` · `PARSE_ERROR`, each with a confidence level |
| **Platforms** | Cisco IOS-XE, Cisco NX-OS, Arista EOS |
| **Writes to devices** | none, ever — [read-only by design](#safety-model-non-negotiable) |

**Contents:** [What you get](#what-you-get) · [Requirements](#requirements) ·
[Install](#install) · [Quick start](#quick-start) · [Usage](#usage) ·
[Input](#input-the-splunk-csv) · [Output](#output) ·
[Command reference](#command-reference) · [Configuration](#configuration) ·
[Verdicts](#verdict-vocabulary) · [Platforms](#supported-platforms) ·
[Safety model](#safety-model-non-negotiable) · [Status](#project-status) ·
[Development](#development)

## Read-only by design

Operator credentials have WRITE privileges on these devices, so the tool makes
configuration change structurally impossible rather than merely unlikely: a
single egress point (`iftriage/session.py`), a closed allow-list of exact show
commands, a prompt guard that aborts the run if a `(config` prompt ever
appears, and an audit log of every command sent. CI fails the build if
`send_command`, `send_config`, or `ConnectHandler` appears anywhere outside
`session.py`. Full detail in [Safety model](#safety-model-non-negotiable).

## What you get

The example below is a complete run of eight cases across seven switches. Every
artifact in [`docs/examples/`](docs/examples/) was produced by running iftriage
itself; the devices are simulated by replaying the sanitized captures in
`tests/fixtures/`, so the timestamps are compressed but every command, verdict
string, and rendered file is the tool's real output. Reproduce them with
`python scripts/regen_examples.py` — only the transport under `session.py` is
replaced, so the allow-list, the prompt guard and the audit log doing the work
are the production ones. CI fails if the committed artifacts drift from what
the tool produces today.

**1. Dry run first** — see the exact commands, connect to nothing
([full output](docs/examples/dry_run.txt)):

```
$ iftriage run docs/examples/input.csv --dry-run
Ingested 8 cases from docs/examples/input.csv; 2 data-quality finding(s).
  [dq:negative_delta] sw-acc-02 Gi3/0/20 Late-Col: negative delta (-154073) — counter reset or device reload during the window. Delta is not meaningful; live verification decides.
  [dq:time_misalignment] Poll timestamps span 2026-08-28T02:10:00 .. 2026-08-28T05:20:00: the 24h windows are NOT aligned across rows. Deltas are not directly comparable between rows.
DRY RUN — connecting to nothing. Targets and exact commands:

== sw-acc-01 (192.0.2.11) — platform: UNKNOWN (will autodetect on connect)
   -- Gi3/0/20 [Rcv-Err]
      ios_xe: show processes cpu | include CPU utilization
      ios_xe: show version
      ios_xe: show interfaces GigabitEthernet3/0/20
      ios_xe: show interfaces GigabitEthernet3/0/20 counters errors
      ios_xe: show interfaces GigabitEthernet3/0/20 transceiver detail
      ios_xe: show cdp neighbors GigabitEthernet3/0/20 detail
      ios_xe: show etherchannel summary   [always sent: the only way to learn membership here]
      ios_xe: show logging | include GigabitEthernet3/0/20
      nxos: INTERFACE NAME ERROR: unknown interface prefix 'Gi' for platform nxos in 'Gi3/0/20'
      eos: INTERFACE NAME ERROR: unknown interface prefix 'Gi' for platform eos in 'Gi3/0/20'
...
No devices were contacted.
```

Until the platform of a device is known, the dry run prints the commands each
candidate platform would send — which is also how you see that an interface
name only makes sense on one of them.

**2. The run** ([full transcript](docs/examples/console.txt)):

```
$ iftriage run docs/examples/input.csv --user netops
Ingested 8 cases from docs/examples/input.csv; 2 data-quality finding(s).
  [dq:negative_delta] sw-acc-02 Gi3/0/20 Late-Col: negative delta (-154073) — counter reset or device reload during the window. Delta is not meaningful; live verification decides.
  [dq:time_misalignment] Poll timestamps span 2026-08-28T02:10:00 .. 2026-08-28T05:20:00: the 24h windows are NOT aligned across rows. Deltas are not directly comparable between rows.
Stored earlier samples found for 7 of 8 case(s) (newest 18.0 h ago, oldest 18.0 h ago).
Compare against them, so the report can say whether each counter is still incrementing? [Y/n]: y
Audit log: reports/iftriage_audit_20260829_202921.log
Collecting from 7 device(s), one session at a time ...
Compared 7 of 8 case(s) against an earlier stored sample.

8 cases: 2 PHYSICAL_MEDIA, 1 LINK_NEGOTIATION, 1 CONGESTION_BUFFER, 1 PARSE_ERROR, 1 UNVERIFIED, 1 HISTORIC_NOT_ACTIVE, 1 IGNORE
Report (HTML): reports/iftriage_report_20260829_202921.html
Report (text): reports/iftriage_report_20260829_202921.txt
Report (CSV):  reports/iftriage_report_20260829_202921.csv
```

**3. The report** — one verdict per case, in decision language, with the
evidence that produced it. Excerpt from
[`docs/examples/report.txt`](docs/examples/report.txt); the
[HTML version](docs/examples/report.html) is the same content with colour-coded
verdicts and a collapsible block of raw command output per case, ready to paste
into an email. The [CSV version](docs/examples/report.csv) is the input table
itself — original columns and row order — with the verdict and the analysis
evidence appended as extra columns, ready for Excel:

```
INTERFACE ERROR TRIAGE — TOP-8 VERIFICATION
Generated 2026-08-29 20:29 UTC | source: docs/examples/input.csv
Baseline: 7 of 8 case(s) compared against an earlier stored sample.

EXECUTIVE SUMMARY
  8 cases: 2 PHYSICAL_MEDIA, 1 LINK_NEGOTIATION, 1 CONGESTION_BUFFER, 1 PARSE_ERROR, 1 UNVERIFIED, 1 HISTORIC_NOT_ACTIVE, 1 IGNORE

CASES
--------------------------------------------------------------------------------
[PHYSICAL_MEDIA — confidence MEDIUM] sw-acc-01 Gi3/0/20 (Rcv-Err)
  PHYSICAL_MEDIA — confidence MEDIUM (fcs_fraction_active).
  Evidence:
    - FCS errors are 100.0% of input errors: frames arriving but corrupted
      (marginal signal).
    - 2 interface resets.
  Delta (iftriage, run-to-run): 412 over 18.0 h (host-side timestamps)
  Delta (CSV, Splunk window): 2,123
  Error ratio: 0.0298% of received frames
  Data quality:
    - Delta sources disagree: iftriage run-to-run 412 vs CSV change 2,123; the
      tool's own delta is used for rate math.
  What would change this: If errors stop advancing after a coordinated manual
  counter clear and repoll, reclassify HISTORIC_NOT_ACTIVE.
  Compared against the sample from 2026-08-29 02:29 UTC (18.0 h earlier, run #1).
--------------------------------------------------------------------------------
[LINK_NEGOTIATION — confidence HIGH] sw-acc-02 Gi3/0/20 (Late-Col)
  LINK_NEGOTIATION — confidence HIGH (duplex_mismatch_confirmed).
  Evidence:
    - 38,449,023 late collisions on a half-duplex link (neighbor
      SEP001122AABB99 reports full): negotiation/duplex mismatch, fixed via CLI.
  Delta (iftriage, run-to-run): 3,096 over 18.0 h (host-side timestamps)
  Compared against the sample from 2026-08-29 02:29 UTC (18.0 h earlier, run #1).
  Data-quality flags: negative_delta
--------------------------------------------------------------------------------
[PARSE_ERROR] sw-acc-01 Gi1/0/47 (Rcv-Err)
  PARSE_ERROR — critical field(s) input_errors, crc_errors, input_packets,
  link_status could not be parsed from device output. Refusing to guess (fail
  closed).
--------------------------------------------------------------------------------
[IGNORE] sw-core-02 Eth4/15 (Rcv-Err, delta24h=28)
  IGNORE — error rate 0.0010% (10 per million frames) over lifetime counters,
  counter flat over the 18.0 h since the earlier sample: historical, not
  happening now. DOM rx power -3.5 dBm within range. No action.
  Compared against the sample from 2026-08-29 02:29 UTC (18.0 h earlier, run #1).
```

That is the point of the tool: of eight alarming-looking rows, two were real
media problems, one was a duplex mismatch to fix in the CLI, one was congestion,
and four needed no action at all — and each answer carries its evidence.

**4. The audit log** — every command sent, to which device, when
([full log](docs/examples/audit.log)):

```
2026-08-29T20:29:21+00:00 | 192.0.2.12 | <connected>
2026-08-29T20:29:21+00:00 | 192.0.2.12 | <enable elevation>
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show processes cpu | include CPU utilization
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show version
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show interfaces GigabitEthernet3/0/20
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show interfaces GigabitEthernet3/0/20 counters errors
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show interfaces GigabitEthernet3/0/20 transceiver detail
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show cdp neighbors GigabitEthernet3/0/20 detail
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show logging | include GigabitEthernet3/0/20
2026-08-29T20:29:21+00:00 | 192.0.2.12 | show etherchannel summary
2026-08-29T20:29:21+00:00 | 192.0.2.12 | <disconnected>
```

The input that produced all of the above is
[`docs/examples/input.csv`](docs/examples/input.csv).

## Requirements

- Python 3.11 or newer (CI runs 3.11 and 3.13).
- SSH reachability to the management IPs in the CSV, with an account that can
  run show commands. Nothing is installed on the devices.
- Runtime dependencies, installed automatically: `netmiko>=4.3`, `pandas>=2.0`,
  `jinja2>=3.1`, `pyyaml>=6.0`.

Installing provides the `iftriage` console script.

## Install

On an operator machine, install the wheel built and verified by CI for a
tagged release — it needs no build toolchain and is byte-identical to what the
pipeline tested:

```bash
gh release download v0.2.0 --repo netcraftworks/iftriage -p '*.whl'
```

```bash
pip install ./iftriage-0.2.0-py3-none-any.whl
```

Installing straight from the repository works too, and requires only git
credentials:

```bash
pip install "git+https://github.com/netcraftworks/iftriage.git@v0.2.0"
```

From a checkout:

```bash
pip install .
# development
pip install -e '.[dev]'
pytest
```

> **Version note.** This README documents `main`. One behavior described here
> is not in the published v0.2.0 wheel yet and ships in the next release:
> contacting **one device at a time by default**, with concurrency as the
> command-line opt-in `--workers N`. In v0.2.0, concurrency comes from
> `connection.workers` in `config.yaml` (default 10) and `--workers` merely
> overrides that key. Install from `main` if you want the serial default today.

## Quick start

```bash
# 1. Look at what the run would do. No credentials, no connections.
iftriage run top20.csv --dry-run
```

```bash
# 2. Run it. Username on the command line, secrets typed into the terminal.
iftriage run top20.csv --user youruser
```

The second command contacts each device **once** and returns — nothing blocks.
It offers to compare each interface against the newest sample already stored for
it, prompts for the password (and optionally an enable secret), and writes the
report and audit log into `reports/`. If it collects nothing at all (every device
failed — wrong credentials, unreachable network), the run aborts with exit code 3
rather than writing a report that is already decided.

Run it again tomorrow, next week, or with a different CSV: the second run answers
the question the counters alone cannot, *is this still incrementing now?*

## Usage

```bash
# Today, then tomorrow: the second run compares against the first.
iftriage run top20.csv --user youruser
iftriage run top20.csv --user youruser        # offers the stored samples

# Answer the offer up front, for scripts and cron:
iftriage run top20.csv --user youruser --baseline
iftriage run top20.csv --user youruser --no-baseline --output reports/

# Opt in to contacting several devices at once (see the safety model below):
iftriage run top20.csv --user youruser --workers 5

# Re-render the report from the collection already in the history database:
iftriage run top20.csv --from-history
```

### Comparing against an earlier sample

A counter that is large is not the same as a counter that is *moving*. Two
samples of the same interface answer that, and the second one comes from a
previous run rather than from a wait — so no run ever freezes the terminal.

The baseline belongs to the **interface**, not to the CSV. The lookup key is
`(switch, interface, counter)`, so a different top-20 list tomorrow does not
matter: every row searches history on its own, the interfaces seen before find
their sample, the new ones do not, and **partial coverage is the normal case**.
The report states per case what it was compared against — or that it had no
earlier sample and its verdict rests on one reading. An interface spelled
`Gi1/0/1` in one export and `GigabitEthernet1/0/1` in the next still matches;
both forms are stored.

Windows of different lengths across cases are fine, and that is not a
concession: the rate is `error_delta / packet_delta` — per packet, not per
second — so an interface compared against yesterday and one compared against
five days ago land on the same scale and face the same thresholds. Two bounds
in `config.yaml` guard the *claim*, not the arithmetic:

- `baseline.min_window_minutes` (default 5) — samples closer together than this
  are refused. Nothing had time to move, the counter would read as flat, and a
  false "flat" turns a live fault into `HISTORIC_NOT_ACTIVE` instead of an
  escalation to `PHYSICAL_MEDIA` or `CONGESTION_BUFFER`.
- `baseline.max_window_days` (default 14) — older samples are not offered.
  "Still incrementing" stops meaning *now* once the window is a month wide.

A sample whose counters read *lower* than today's is discarded outright: the
device reloaded, or the counters were cleared. That case is reported as
"unknown", never as flat — a discarded baseline can never veto an escalation.

Without an explicit flag and without a terminal (cron, piped stdin), the answer
is **no**: a baseline can only narrow a verdict, so it is never applied silently
to a run nobody is watching. `--baseline` and `--no-baseline` answer up front.

### Re-rendering a report without collecting again

Collection is the expensive half of a run; the analysis is the cheap half.
`--from-history` replays the first so the second can be iterated on — a template
tweak, a threshold change, a new rule — without asking the fleet again:

```bash
iftriage run top20.csv                 # collects, reports, stores
vim iftriage/templates/report_en.html.j2
iftriage run top20.csv --from-history  # same data, new report, no SSH
```

It contacts no device, asks for no credentials, and **records nothing**: no run
row, and no second archive of the CSV — re-archiving it would inflate every
recurrence count. Because the original run archived it already, the recurrence
numbers come out identical to the report being rebuilt.

Verdicts are re-derived, not replayed: the stored counters go back through
`rules.py` with the thresholds in effect now, so a `config.yaml` edit shows up
in the rebuilt report. The report says which run the data came from and when it
was collected, since nothing stops you from rebuilding week-old data.

The whole CSV is answered or nothing is: if any row has no stored collection —
a new interface, a different CSV, or a database written before 0.6.0 — the
command exits 2 and names the rows to collect. `--baseline`, `--no-baseline`
and `--user` are ignored (a note says so); `--dry-run` is rejected as
contradictory.

Credentials are resolved per value, first match wins:

| Credential | 1st | 2nd | 3rd |
|---|---|---|---|
| Username | `--user` | `$IFTRIAGE_USER` | terminal prompt |
| Password | — | `$IFTRIAGE_PASS` | terminal prompt (`getpass`) |
| Enable secret | — | `$IFTRIAGE_ENABLE` | terminal prompt (`getpass`) |

Passwords are never accepted as arguments — they would be left behind in the
shell history and visible in `ps`. The enable secret is optional and the same
fleet-wide: press Enter to skip it, or set `IFTRIAGE_ENABLE=""` to skip the
prompt in unattended runs. It is only used on devices that land in user exec
(`>`); a device that requires it when it was not supplied is skipped and its
cases are reported `UNVERIFIED` — the run continues.

```bash
export IFTRIAGE_USER=youruser
export IFTRIAGE_PASS=...          # unattended runs; otherwise omit and get prompted
export IFTRIAGE_ENABLE=...        # same enable secret fleet-wide; optional
```

Without a terminal to prompt on (cron, a pipeline) and without those variables,
the run stops immediately with exit code 2 rather than hanging.

## Input: the Splunk CSV

One row per interface counter. All eleven columns are required; a missing
column aborts the run with exit code 2 and names what it found instead.

| Column | Meaning |
|---|---|
| `_time` | Splunk poll timestamp for this row. Rows are typically **not** aligned in time |
| `switch` | Hostname, used for labels and recurrence history |
| `mgmt_ip` | SSH target |
| `interface` | Interface as reported, short form (`Gi3/0/20`, `Et4/15`, `Eth4/15`, `Po214`) |
| `description` | Interface description; carried into the report |
| `status` / `protocol` | Link and line-protocol state at poll time |
| `counter` | Counter name (`Rcv-Err`, `Late-Col`, `InDiscards`, `OutDiscards`, `Rx`, ...) |
| `prev_count` / `count` | Counter at the previous poll / at poll time |
| `change` | The delta Splunk ranked on |

> **The `change` column's window is whatever the Splunk search made it.** A
> field audit compared it against the tool's own measured deltas across five
> cases and found five incompatible ratios — some rows behaved like a ~30-min
> poll delta, others like a 24 h delta. iftriage therefore never uses `change`
> for rate math (its own two observations are measured); it only flags the
> disagreement. If the flag keeps appearing, the place to fix it is the Splunk
> search, not the tool. The same bias explains chronic top-20 residents: the
> search ranks by absolute delta, so a busy uplink with a negligible error
> *ratio* can hold a seat permanently — the report marks these and recommends
> re-ranking the search by ratio.

```csv
_time,switch,mgmt_ip,interface,description,status,protocol,counter,prev_count,count,change
2026-08-28T02:10:00,sw-acc-01,192.0.2.11,Gi3/0/20,ACCESS-FLOOR3-PRINTER,up,up,Rcv-Err,1148,3271,2123
2026-08-28T04:15:00,sw-dist-01,192.0.2.21,Et4/15,UPLINK-SPINE1,up,up,Rcv-Err,12044,21503,9459
2026-08-28T04:50:00,sw-core-01,192.0.2.31,Eth4/15,UPLINK-TO-CORE,up,up,InDiscards,102,388,286
```

Short interface names are expanded per platform before any command is built
(`Gi3/0/20` → `GigabitEthernet3/0/20` on IOS-XE, `Eth4/15` → `Ethernet4/15` on
NX-OS, `Po214` → `Port-Channel214` on EOS). A name that no platform recognizes
is refused, never guessed.

**Data-quality checks** run before any device is contacted. Findings appear in
the console, in the report, and — for the first kind — remove the row from
analysis entirely:

| Finding | Trigger | Effect |
|---|---|---|
| `cross_device_identical` | identical `(counter, prev_count, count)` on different switches | **excluded**: physically near-impossible, so the row is dropped before collection and never verified |
| `negative_delta` | `change` is negative | flagged, still analyzed — a counter reset does not prove health |
| `duplicate_entry` | the same switch + interface + counter listed twice | flagged, still analyzed |
| `time_misalignment` | rows carry different `_time` values | informational: deltas are not comparable across rows |

## Output

Everything lands in the output directory (`reports/` by default), except the
history database:

| Artifact | Default path | Contents |
|---|---|---|
| HTML report | `reports/iftriage_report_<stamp>.html` | Email-ready: summary, data quality, one box per case with raw evidence |
| Text report | `reports/iftriage_report_<stamp>.txt` | Same content, plain text |
| Enriched CSV | `reports/iftriage_report_<stamp>.csv` | The input CSV, original columns and row order, with the verdict and the analysis evidence appended as extra columns (the last one, `member_summary`, holds the per-member findings of a port-channel case) |
| Audit log | `reports/iftriage_audit_<stamp>.log` | `<timestamp> \| <ip> \| <exact command>`, plus `<connected>`, `<enable elevation>`, `<disconnected>` |
| History DB | `iftriage_history.db` | Every ingested CSV archived verbatim, run results, per-case evidence, and the IP→platform cache. Also what `--from-history` reads back |

The history database is what makes "Recurrence: appeared in N ingested top-20
lists" possible — the CSV is archived before analysis, so an interface that
keeps coming back is visible even when each individual run says `IGNORE`.

Run artifacts are gitignored (`reports/`, `*.db`, `iftriage_audit_*.log`);
nothing collected from a device is meant to be committed.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Run completed (or a dry run finished). Verdicts are in the report, not in the exit code |
| `2` | Usage or input error: bad flags, unreadable/malformed `config.yaml`, missing CSV or missing columns, credentials that could not be resolved, or `--from-history` with no stored collection for some case |
| `3` | `RUN ABORTED` — a safety violation (config-mode prompt), the AAA circuit breaker, or a first pass in which no device at all could be collected (e.g. wrong credentials on a single-device run). Whatever caused it is on stderr |

## Command reference

The CLI is deliberately small: one subcommand and nine flags.

| Command / flag | Effect |
|---|---|
| `iftriage run <csv>` | Triage every case in a top-N CSV |
| `--dry-run` | Print targets and exact commands; connect to nothing |
| `--user USERNAME` | Device username (default: `$IFTRIAGE_USER`, else prompt) |
| `--baseline` | Compare each interface against its newest earlier stored sample, without asking |
| `--no-baseline` | Judge on this run's single sample only; ignore stored samples |
| `--config PATH` | Alternate `config.yaml` (default: `./config.yaml` if present) |
| `--output DIR` | Report/audit output directory (default: `reports/`) |
| `--workers N` | Contact N devices at the same time (default: `1`). Explicit opt-in; weakens the AAA circuit breaker |
| `--db PATH` | SQLite history path (default: `iftriage_history.db`) |
| `--from-history` | Rebuild the report from the collection already stored; contact no device and record no new run |
| `-h`, `--help` | Help for `iftriage` or for `iftriage run` |
| `--version` | Print version and exit |

## Configuration

Configuration is optional: `--config PATH`, else `./config.yaml`, else built-in
defaults identical to the file below. **`config.yaml` is not shipped inside the
wheel** — an installed `iftriage` run from a directory without one silently uses
the defaults, which is fine unless you need `platform_overrides` or different
thresholds.

```yaml
thresholds:
  # Normalized rate = counter_delta / packet_delta (baseline) or counter/packets
  # lifetime, expressed here as a PERCENTAGE of the frames. Errors and discards
  # get their own floor because they are different phenomena: Cisco's port
  # troubleshooting guidance (Doc ID 12027) tolerates ~1% of errors only on
  # half-duplex links and expects essentially zero FCS/CRC/alignment on
  # full-duplex, while an out-discard is a frame that arrived intact and was
  # dropped for buffer or policy reasons -- congestion, routine on a busy
  # uplink, and never a media fault.
  error_rate_percent: 0.001   # CRC/FCS/alignment/runts: 10 per million frames
  discard_rate_percent: 1.0   # In/OutDiscards: escalate as capacity from 1% up
  dom_rx_low_dbm: -14.0  # DOM receive power below this -> out of range
  dom_rx_high_dbm: 2.0   # DOM receive power above this -> out of range

connection:
  # Concurrency is NOT configured here. iftriage contacts one device at a time
  # unless the operator asks for more with `--workers N` on the command line.
  timeout_seconds: 30    # per-command read timeout
  jitter_min: 0.5        # random delay before each connection (seconds)
  jitter_max: 2.0
  aaa_failure_abort: 2   # consecutive auth failures before aborting the whole run
  # Devices whose current CPU is above this are skipped (cases UNVERIFIED)
  # instead of being given more work; unreadable CPU also skips (fail closed).
  cpu_skip_threshold_percent: 80

limits:
  max_output_bytes: 1000000  # hard ceiling per command; keeps the tail
  evidence_max_lines: 300    # lines kept as evidence (first 50 + last 250)

baseline:
  # A run takes ONE sample and stores it. The delta that answers "is this
  # counter still incrementing now?" comes from the newest earlier sample
  # stored for the same interface -- whatever CSV or run it came from -- so
  # nothing blocks the terminal. Both bounds guard that answer: a sample taken
  # minutes ago looks flat because nothing had time to move (and a false "flat"
  # suppresses escalation), while one from weeks ago can no longer claim "now".
  min_window_minutes: 5    # earlier samples closer than this are not used
  max_window_days: 14      # ...nor older than this

# Manual platform overrides by mgmt_ip or hostname. Values: ios_xe | nxos | eos
platform_overrides: {}
#  192.0.2.21: eos
#  core-sw-01: nxos

history:
  db_path: iftriage_history.db

report:
  # Template base name; iftriage/templates/<template>.html.j2 and .txt.j2
  template: report_en
  output_dir: reports
```

## Verdict vocabulary

| Verdict | Meaning |
|---|---|
| `PHYSICAL_MEDIA` | Errors placed at the physical layer: the zero-traffic test (errors advancing with no valid frames arriving), a dominant unattributed/symbol/runts profile with no collision activity, a high FCS fraction on an active counter, DOM out of range, late-col on a legacy half-duplex segment |
| `LINK_NEGOTIATION` | Negotiation/duplex/MTU problems: late collisions on full duplex (duplex mismatch, fixed via CLI), a dominant giants profile |
| `CONGESTION_BUFFER` | Overrun/ignored/no-buffer/queue-drop dominance or discards at rate: frames arrived intact and were dropped — oversubscription, policer, or ring sizing, not media |
| `HISTORIC_NOT_ACTIVE` | The lifetime counter is large but did not move between the tool's own two observations — an old event, not an incident |
| `INSUFFICIENT_DATA` | The data parsed fine but cannot support a judgement: a never-cleared lifetime counter with no second observation supports no rate at all |
| `IGNORE` | Activity below the configured threshold / not an error counter |
| `UNVERIFIED` | Device unreachable / auth failed / required an enable secret that was not provided — CSV data only |
| `PARSE_ERROR` | Output did not parse or critical fields missing (fail closed) |

Every judged verdict carries a **confidence** (`HIGH`/`MEDIUM`/`LOW`) with
hard caps: a single observation or an unknown rule input caps `MEDIUM`; an
input-error reconciliation residual above 1% caps `LOW`. The caps' reasons
appear in the report's per-case data-quality list. `UNVERIFIED`, `PARSE_ERROR`
and `INSUFFICIENT_DATA` carry none — they are refusals, not judgements.

Cases are reported most-actionable-first: `PHYSICAL_MEDIA` →
`LINK_NEGOTIATION` → `CONGESTION_BUFFER` → `PARSE_ERROR` → `UNVERIFIED` →
`INSUFFICIENT_DATA` → `HISTORIC_NOT_ACTIVE` → `IGNORE`.

Rates never mix counter populations: the tool's own run-to-run delta is
divided by delta received frames (`packets input` + `input errors`, since
errored frames are not in `packets input`), lifetime values only by lifetime
frames over a device-anchored window, and the CSV's `change` column is
displayed but never used for rate math. A ratio that falls outside 0–100% is
suppressed and flagged, never printed. Thresholds live in `config.yaml`
(defaults: errors ≥ 0.001% of frames, discards ≥ 1%).

**Port-channels pull in the whole bundle.** Whenever a case touches a
port-channel — as the bundle or as one of its members — iftriage reconnects to
the device and runs the per-interface command set on every member of it (member
names are validated before ever reaching a command). What it concludes depends
on which end the CSV reported:

- **The case is the Po.** Bundle counters are sums across members — one bad
  member's rate is diluted by its healthy peers — so the verdict names the
  culprit (`fault isolated to member Gi3/0/23`), a member that could not be
  collected fails the bundle closed to `PARSE_ERROR`, and bundle errors with
  clean members degrade to "not attributable to any current member".
- **The case is a member.** The verdict stays about the interface the CSV
  reported, judged like any single interface. Its siblings are collected
  because a LAG fault often sits on a neighbouring link, but they are listed as
  context: a dirty or uncollectable sibling never changes this port's category.

The member breakdown appears in all three reports. Cost: one extra SSH
connection per device holding such a case.

The port-channel summary itself is the one conditional command. On EOS and
NX-OS a physical port's own `show interfaces` names its bundle (`Member of
Port-Channel195`, `Belongs to Po21`), so the summary is only sent when a case
on that device turns out to be relevant — worth having on an Arista chassis
carrying hundreds of channels. IOS-XE never names the channel-group there, so
`show etherchannel summary` is always sent: it is the only way to learn
membership at all.

## Supported platforms

| Platform | OS | Neighbor discovery | Allow-listed commands |
|---|---|---|---|
| Cisco Catalyst | IOS-XE | CDP | 8 |
| Cisco Nexus | NX-OS | LLDP **and** CDP (CDP wins the merge) | 9 |
| Arista (incl. DCS-7808-CH) | EOS | LLDP | 8 |

NX-OS runs both neighbor protocols because non-Cisco uplinks do not speak CDP.
The exact command list per platform is in
[`PROJECT_SPEC.md` section 5](PROJECT_SPEC.md) — and `--dry-run` prints it for
your own CSV.

Platform detection: `platform_overrides` in `config.yaml` → SQLite cache →
read-only Netmiko `SSHDetect` on first contact.

**Parser note.** The spec recommends Genie/pyATS (Cisco) and ntc-templates
(EOS). iftriage ships lightweight built-in parsers bound per command in each
`PlatformProfile` and tested against fixtures; the `parse(key, raw)` binding is
the single swap-in point if Genie/textfsm is preferred later. The fail-closed
rule protects against a misparse either way: unparsed critical fields produce
`PARSE_ERROR`, never a clean verdict.

## Safety model (non-negotiable)

Operator credentials have WRITE privileges; the tool makes configuration
change structurally impossible:

1. **Single egress point** — `ReadOnlySession` (`iftriage/session.py`) wraps
   the Netmiko connection as a private attribute; `get(command)` is the only
   public command method. *Code-review rule: any `send_command`/`send_config`
   outside `session.py` is an automatic rejection — and CI enforces it with a
   grep that fails the build.*
2. **Closed allow-list, fail closed** — exact command strings derived from
   `PlatformProfile` templates for the target interfaces (interface names are
   regex-validated before substitution). Anything else raises.
3. **Mode verification** — the prompt is checked before and after every
   command; a `(config` prompt disconnects and aborts the whole run.
4. **Audit trail** — every exact command sent to every IP is logged with a
   timestamp. Credentials/enable secret never appear (`<enable elevation>`).

Additional operational safety: **one device at a time by default**, AAA
circuit breaker (2 consecutive auth failures abort the run), per-device
timeouts, jitter between connections, per-device try/except (a failed device
becomes `UNVERIFIED`), and a **CPU guard** — right after login the device's
current CPU utilization is read, and a device above
`connection.cpu_skip_threshold_percent` (default 80) is skipped with the reason
in the report rather than loaded with more work; an unreadable CPU reading also
skips (fail closed). No `clear counters`, no `debug`, no `show tech`, no
config mode, ever.

**Concurrency is opt-in, and only from the command line.** `iftriage run`
contacts one device at a time unless you pass `--workers N`; there is no
setting in `config.yaml` that can widen the fan-out, so a command always tells
you how many devices it touches. The default is serial because the AAA circuit
breaker can only cap the damage when authentication attempts are sequential: N
parallel workers put N attempts in flight before the breaker sees the first
failure, which is enough to lock an operator account against a strict AAA
policy. When you do ask for `--workers N`, the run first contacts a single
device sequentially and aborts on an authentication failure there, so wrong
credentials cost one failed login instead of N.

**Bounded output:** `show logging | include <intf>` can return thousands of
lines on a noisy port. Two limits under `limits` in `config.yaml` keep that
from inflating the history database or the report — `max_output_bytes`
(default 1000000, a hard per-command ceiling that keeps the tail) and
`evidence_max_lines` (default 300, the head+tail copy stored and rendered).
Parsing always sees the full output, so neither limit can change a verdict;
truncation is marked inline in the raw evidence.

**Fail-closed analysis:** a missing/unparsed critical field never yields a
clean verdict — it becomes `PARSE_ERROR`, never a false `IGNORE`.

## Project status

- **Phase 1 — done.** Full pipeline: safety layers, platform registry, rules
  engine, ingest data-quality checks, SQLite history, HTML + text report, CLI.
- **Phase 2 — done (0.2.0).** Sanitized captures from real Catalyst, Nexus and
  Arista hardware became fixtures (live duplex mismatch, vPC port-channel,
  SFP-10G-SR DOM, down/down breakout, empty and wrapped summaries), and the
  parser fixes they exposed landed with them. Zero device access in tests.
- **Phase 3 — in progress.** Live runs against real devices are underway; what
  they surface lands as fixes. 0.4.0 came out of that: fail fast when no device
  could be collected, skip devices under CPU pressure, and judge port-channels
  through their member interfaces. 183 tests.

## Out of scope (by design, forever)

Full-fleet polling, Splunk API integration, ticketing integration, any
configuration capability whatsoever, async at scale.

## Development

Conventions live in [CLAUDE.md](CLAUDE.md); scope and architecture authority
is [PROJECT_SPEC.md](PROJECT_SPEC.md); the module map is in
[docs/architecture.md](docs/architecture.md).

The package layers strictly inward — platform specifics never reach the rules
engine:

| Module | Responsibility |
|---|---|
| `iftriage/cli.py` | Argument parsing, credential resolution, run orchestration, exit codes |
| `iftriage/ingest.py` | CSV parsing and the four data-quality checks |
| `iftriage/session.py` | `ReadOnlySession` and the audit log — **the only module that may touch a device** |
| `iftriage/baseline.py` | Picks the earlier sample per interface, and explains every rejection |
| `iftriage/collectors.py` | Per-device collection, platform resolution, AAA breaker |
| `iftriage/platforms/` | One profile per OS: command templates + parsers (`base.py` holds the shared ones) |
| `iftriage/normalize.py` | Interface-name validation and expansion |
| `iftriage/models.py` | The canonical `NormalizedInterfaceStats` model and the shared dataclasses |
| `iftriage/rules.py` | The verdict engine: pure functions over the canonical model, no platform knowledge |
| `iftriage/report.py` + `templates/` | Jinja2 HTML and text reports, plus the enriched CSV writer |
| `iftriage/history.py` | SQLite archive, run results, platform cache, recurrence |

Adding a platform means a new profile plus its fixtures — and no change to
`rules.py`. Every PR must keep CI green (Python 3.11 and 3.13):

```bash
ruff check . && ruff format --check . && mypy iftriage && pytest --cov=iftriage
```

Work lands via `feat/...` or `fix/...` branches and PRs into the protected
`main` branch — never direct commits. Any change touching the read-only
guarantee (see CLAUDE.md security review) must be called out in the PR
description.

## Releasing

Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`: it re-runs the full
CI gate, builds the wheel and sdist, smoke-tests the wheel outside the source
tree, and publishes a GitHub Release with both artifacts attached and the
matching `CHANGELOG.md` section as its notes. Nothing is published outside this
repository.

1. In a `chore/release-X.Y.Z` PR: bump `__version__` in `iftriage/__init__.py`
   (the single source of truth — `pyproject.toml` reads it) and close
   `## [Unreleased]` in `CHANGELOG.md` as `## [X.Y.Z] - YYYY-MM-DD`.
2. Merge the PR into `main`.
3. Tag the merge commit and push the tag:

```bash
git checkout main && git pull && git tag -a v0.2.0 -m "iftriage 0.2.0" && git push origin v0.2.0
```

The workflow refuses to publish if the tag is not on `main`, if it disagrees
with `__version__`, or if the changelog has no section for that version. A bad
release is fully reversible — `git push --delete origin vX.Y.Z` and
`gh release delete vX.Y.Z` — then fix and re-tag.

## License

MIT — see [LICENSE](LICENSE).
