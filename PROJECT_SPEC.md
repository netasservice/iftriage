# iftriage — Interface Error Triage Tool

> **Handoff document for Claude Code.** This spec captures the full design agreed during planning.
> Read it entirely before writing code. Do not deviate from the safety model without explicit approval.

## 1. Problem statement

A network operations team receives a recurring Excel/CSV export ("Top 20 Interface Error Deltas, 24h")
derived from Splunk, covering a fleet of ~1000 switches. Each row is one interface on one switch that
showed a 24h increase in an error-related counter. The team's job: determine whether each case is a
**real problem requiring physical-media review, a config issue, a capacity issue, or ignorable noise**,
and answer **by email** with supporting evidence.

Today this is manual. `iftriage` automates the verification step: it reads the CSV, connects
(READ-ONLY) to each listed device, collects targeted diagnostic output for the reported interface,
applies a rules engine, and produces a verdict report with raw evidence attached.

**Division of labor:** Splunk decides WHO is suspicious (the top-20 list). iftriage decides WHETHER
they are guilty (live verification). iftriage never polls the full fleet — only the devices in the CSV.

## 2. Input

A CSV file (only scope for now; columns are fixed and always the same):

```
_time, switch, mgmt_ip, interface, description, status, protocol, counter, prev_count, count, change
```

- `_time`: Splunk poll timestamp (NOTE: varies per row — 24h windows are NOT aligned across rows;
  flag this, never treat deltas as directly comparable)
- `switch`: hostname
- `mgmt_ip`: management IP (SSH target)
- `interface`: short interface name as reported (e.g. `Gi3/0/20`, `Et4/15`, `Po214`)
- `counter`: counter name from the Splunk collection (`Late-Col`, `Rcv-Err`, `InDiscards`, `Rx`, ...)
- `prev_count` / `count` / `change`: cumulative counter 24h ago, now, and the delta

## 3. Non-negotiable safety model (READ-ONLY guarantee)

**Critical context:** operator credentials have WRITE privileges on the devices. The tool itself must
make configuration change structurally impossible. This is the most important requirement of the
entire project. Diagnostic tool only — it must NEVER modify device state.

### Layer 1 — Single egress point
- One class, `ReadOnlySession`, wraps the device connection. The raw Netmiko/driver connection is a
  private attribute. The only public method to run a command is `get(command)`.
- No other module may import or call the underlying driver's send methods. Code-review rule:
  any `send_command`/`send_config` outside `session.py` is an automatic rejection.

### Layer 2 — Allow-list (fail closed)
- An explicit closed allow-list of exact command templates per platform (derived from
  `PlatformProfile` definitions). NOT a deny-list.
- The interface parameter is validated by regex before substitution into the template.
- Any command not matching the allow-list raises and aborts. The full list is 7–8 commands ×
  3 platforms (see section 5) — enumerable and auditable.

### Layer 3 — Mode verification
- Before and after every command, verify the prompt is privileged-exec (`#`) and NOT config mode
  (no `(config` substring in prompt).
- If a config-mode prompt is ever detected, disconnect immediately and abort the entire run with a
  loud error.

### Layer 4 — Audit trail
- A session log records every exact command sent to every IP with timestamps.
- Credentials and the enable secret NEVER appear in logs (log `<enable elevation>` for the enable
  step, never the value).

### Additional operational safety
- **AAA circuit breaker:** if 2 consecutive devices fail authentication, ABORT the entire run
  (protects against account lockout across the fleet with centralized AAA).
- **Serial by default:** one device at a time. Concurrency is an explicit `--workers N` on the
  command line and is deliberately absent from `config.yaml`, so no file can widen the fan-out.
  This is what makes the breaker above meaningful: N parallel workers put N authentication
  attempts in flight before the first failure is observed. A run with `--workers N` (N > 1)
  contacts one device sequentially first and aborts on an authentication failure there, capping
  wrong credentials at a single failed login.
- Per-device timeouts (~30s), small random jitter between connection attempts (avoid hammering
  TACACS).
- Command output is bounded client-side (`limits` in `config.yaml`): a hard byte ceiling in
  `session.get()` and a line bound on the evidence copy that reaches SQLite and the report.
  `show logging | include <intf>` can return thousands of lines on a noisy port. The command
  set itself is unchanged — see section 5, which remains the allow-list of record.
- Per-device try/except: one failed device never kills the run; it becomes `UNVERIFIED`.
- NO `clear counters`, ever (deltas come from comparing runs, not clearing). No `debug`, no
  `show tech`, no config mode under any circumstance.
- Credentials: username from `--user`, else `IFTRIAGE_USER`, else an interactive prompt.
  Secrets from `IFTRIAGE_PASS` / `IFTRIAGE_ENABLE`, else interactive getpass. Passwords are
  never accepted as command-line arguments (shell history, `ps`). Never hardcoded, never
  logged, never written to disk. With no interactive terminal and no env vars, the run exits
  2 with an actionable message rather than an `EOFError` traceback.

### Enable handling
- Most accounts land directly in privileged exec. Some devices require enable; the enable password
  is THE SAME across all devices.
- Prompt for it once per run (getpass) or read `IFTRIAGE_ENABLE`. It is OPTIONAL: an empty answer
  (or `IFTRIAGE_ENABLE=""`) means the run carries no enable secret.
- A device that lands in user exec when no enable secret was provided is skipped (`EnableRequired`,
  a `SessionError` subclass): its cases become `UNVERIFIED` and the run continues. It is not an
  authentication failure and never counts towards the AAA circuit breaker.
- `ReadOnlySession` elevates ONLY if it detects a user-exec prompt (`>`), using the driver's native
  `.enable()` — the only sanctioned exception to the allow-list (mode elevation is read-only).

## 4. Supported platforms

| Platform | OS | Neighbor protocol | Parser |
|---|---|---|---|
| Cisco Catalyst | IOS-XE | CDP | Genie (pyATS) |
| Cisco Nexus | NX-OS | CDP | Genie (pyATS) |
| Arista (incl. DCS-7808-CH) | EOS | LLDP (no CDP by default) | ntc-templates / textfsm |

### PlatformProfile abstraction
- `platforms/base.py`: `PlatformProfile` ABC + registry. Each profile declares: command templates,
  expected prompt patterns, parser binding per command.
- The allow-list is derived from the profiles (still a closed list).
- Interface-name normalization is mandatory: CSV short names (`Gi3/0/20`, `Et4/15`, `Po214`) must
  expand to each platform's canonical form (`GigabitEthernet3/0/20`, `Ethernet4/15`,
  `Port-Channel214` on EOS vs `port-channel214` on NX-OS, etc.). Without this, shows fail silently.
- Each collector maps platform output to a canonical model (`NormalizedInterfaceStats`:
  input_errors, crc, late_collisions, discards_in, input_packets, output_packets, duplex, speed,
  link_status, protocol_status, dom_rx_power, dom_tx_power, ...).
- **`rules.py` consumes ONLY the canonical model and never knows the platform.** Adding a future
  platform = new profile + collector; zero changes to rules.

### Platform detection
- CSV has no platform column. First time an IP is seen: read-only autodetection (Netmiko
  `SSHDetect` or equivalent banner/prompt observation), then cache IP→platform in SQLite.
- Subsequent runs use the cache. Manual override via `platform_overrides` in `config.yaml`.

## 5. Commands collected per case (targeted — only the reported interface, never full-chassis)

**IOS-XE (Catalyst):**
```
show processes cpu | include CPU utilization
show version
show interfaces <intf>
show interfaces <intf> counters errors
show interfaces <intf> transceiver detail
show cdp neighbors <intf> detail
show etherchannel summary
show logging | include <intf-pattern>
```

**NX-OS (Nexus):**
```
show system resources
show version
show interface <intf>
show interface <intf> counters errors
show interface <intf> transceiver details
show lldp neighbors interface <intf> detail
show cdp neighbors interface <intf> detail
show port-channel summary
show logging logfile | include <intf-pattern>
```

(NX-OS runs both neighbor protocols: non-Cisco uplinks — e.g. Arista — do not
speak CDP, so LLDP is collected as well; CDP wins the merge when it finds an
entry. Confirmed against real fleet output in Phase 2.)

**EOS (Arista):**
```
show processes top once | include Cpu
show version
show interfaces <intf>
show interfaces <intf> counters errors
show interfaces <intf> transceiver
show lldp neighbors <intf> detail
show port-channel dense
show logging | include <intf-pattern>
```

`show version` is used for platform confirmation + recording model/OS in the audit trail.

The first command on each platform is the CPU guard: right after login, the
device's current CPU utilization is read and the device is skipped entirely
(cases become UNVERIFIED) when it exceeds `connection.cpu_skip_threshold_percent`
(default 80). The guard fails closed — an unreadable CPU reading also skips.

The port-channel summary is the one **conditional** command: it is sent only
when a case on the device is a port-channel by name, or when a case's own
`show interfaces` output declared a parent bundle (EOS `Member of
Port-Channel195`, NX-OS `Belongs to Po21`). IOS-XE never names the
channel-group in `show interfaces`, so there the summary is the only source of
membership and is always sent. The command stays in the allow-list either way —
the allow-list is the auditable ceiling of what *may* be sent; the gate only
narrows what actually is.

For a case that touches a port-channel — as the bundle **or** as one of its
members — the per-interface commands (everything except `show version` and the
summary itself) are additionally rendered for every member of that bundle and
run over a second connection to the same device. A member case skips itself:
pass 1 already sampled it. Member names are device-derived text: each must pass
`normalize.py` validation before substitution, so this widens the *interface*
set of the allow-list, never the command set. This remains targeted — only
members of the one bundle, never full-chassis.

## 6. Analysis pipeline

1. **Ingest (`ingest.py`)**: parse CSV, validate fixed columns, run data-quality checks:
   - Byte-identical counter values across DIFFERENT devices (known real-world artifact in the
     source data: two different switches reporting identical prev/count values — physically
     near-impossible; indicates duplicated indexing/collection). Flag, do not analyze.
   - Misaligned `_time` windows across rows (they are never aligned; note it in the report).
   - Negative deltas (counter reset / reload) — flag.
   - Duplicate interface entries (same device+interface listed twice with different values).
   - Data-quality anomalies get their own report section; they are surfaced, not analyzed.
2. **Collect**: per row, connect to `mgmt_ip`, run the platform's command set for the interface.
3. **Baseline comparison (`baseline.py`, offered before collection)**: a run takes ONE sample.
   The second half of the delta is the newest sample already stored for the same
   `(switch, interface, counter)` — from any previous run, any previous CSV. That answers THE
   key question (is the counter still incrementing NOW, or flat?) over hours or days instead
   of ten minutes of a frozen terminal. The key is the interface, never the CSV, so partial
   coverage is normal and the report says per case what it was compared against. Two bounds in
   `config.yaml` guard the claim, not the arithmetic: `baseline.min_window_minutes` (samples
   too close read as flat, and a false flat SUPPRESSES escalation) and
   `baseline.max_window_days` ("still incrementing" stops meaning now). A sample whose counters
   read lower than today's is discarded as a reload — reported as unknown, never as flat.
4. **Verdict (`rules.py` — pure functions, no I/O)**: apply rules to canonical stats.
5. **Persist (`history.py`)**: original CSV rows + collected data + verdicts → SQLite.
6. **Report (`report.py`)**: render the email-ready report.

### Counter semantics (domain knowledge — encode in rules)

- `Late-Col` (late collisions): on a full-duplex link these must be ZERO (no CSMA/CD). Late
  collisions + full duplex ⇒ duplex mismatch (verify far end via CDP/LLDP neighbor if reachable).
  On half-duplex: if the far end reports FULL duplex (CDP `Duplex: full (Mismatch)`) or the
  device log records `%CDP-4-DUPLEX_MISMATCH`, it is a confirmed duplex mismatch (LINK_NEGOTIATION),
  not a legacy segment — real fleet case validated in Phase 2. Only an uncorroborated legacy
  half-duplex link points to cable out of spec / failing NIC.
- `Rcv-Err`: aggregate receive errors. Use `counters errors` to split CRC/FCS (physical: cable,
  transceiver, EMI) from align/runts. On fiber, correlate with DOM rx power.
- `InDiscards`: frame arrived FINE and was dropped — almost always buffer congestion, VLAN not
  allowed on trunk, or ACL. NOT a physical error. Different escalation (capacity).
- `Rx`: total receive count, not an error at all. Should not drive any problem verdict.
- Port-channels: map Po → members via `etherchannel summary` / `port-channel dense`, in both
  directions — the same output answers "who are my members" and "which bundle am I in". If the
  CSV lists a Po and one of its members on the same device, deduplicate — same physical issue
  counted twice. Whenever a case touches a bundle, collect the per-interface command set for
  every member of it (a second connection to the device; member names are validated by
  `normalize.py` before any template substitution — this widens the interface set, never the
  command set). Members carry their own baseline from the same stored run. The two directions
  differ in what they conclude:
  - **The case IS the port-channel** → the verdict is member-driven: a member with an
    actionable finding names the culprit (`fault isolated to member X`); a member that could
    not be collected fails the bundle closed to PARSE_ERROR; bundle-only errors with clean
    members degrade to "not attributable to any current member". Bundle counters alone are
    misleading — they are sums across members, so one bad member's rate is diluted by its
    healthy peers.
  - **The case is a MEMBER of one** → the verdict stays about the reported interface, judged
    exactly as any single interface. Its siblings are collected because a LAG fault often sits
    on a neighbouring link, but they are listed as context only: a dirty or uncollectable
    sibling never changes the category of the port that was actually reported.
- **Normalization is the core insight: raw delta means nothing. Rate = error_delta /
  packet_delta (or error/packets lifetime as fallback).**
  Two floors, configured as percentages in `config.yaml`, because errors and discards are
  different phenomena (Cisco Doc ID 12027: ~1% of errors is tolerable only on half-duplex,
  full-duplex expects essentially zero FCS/CRC/alignment; an out-discard is an intact frame
  dropped for buffer or policy reasons):
  - `error_rate_percent` (default 0.001% = 10/M packets) → CRC/FCS/alignment/runts and
    generic error counters at or above it are `PHYSICAL_MEDIA`.
  - `discard_rate_percent` (default 1%) → `InDiscards`/`OutDiscards` at or above it are
    `CONGESTION_BUFFER`; below it they are operational noise.
  - Either way the comparison against the earlier stored sample decides activity: a counter
    that is flat across the window is a historical event, reported as `HISTORIC_NOT_ACTIVE`.

### Verdict categories (final output vocabulary)

- `PHYSICAL_MEDIA` — errors placed at the physical layer: the zero-traffic test, a dominant
  unattributed/symbol/runts profile with no collision activity, a high FCS fraction on an
  active counter, DOM out of range, late-col on a legacy half-duplex segment.
- `LINK_NEGOTIATION` — negotiation/duplex/MTU problems: late collisions on full duplex
  (duplex mismatch, fixed via CLI, not by touching media), a dominant giants profile.
- `CONGESTION_BUFFER` — overrun/ignored/no-buffer/queue-drop dominance, or discards at or
  above the configured discard threshold. Not media: saturation or policy.
- `HISTORIC_NOT_ACTIVE` — a large lifetime counter with zero movement between the tool's own
  two observations. An old event; nobody is dispatched.
- `INSUFFICIENT_DATA` — parsed fine but cannot support a judgement (e.g. a never-cleared
  lifetime counter with no second observation).
- `IGNORE` — activity below the configured threshold, or not an error counter.
- `UNVERIFIED` — device unreachable / auth failed / SSH timeout. Report with CSV data only,
  clearly marked unconfirmed.
- `PARSE_ERROR` — command output did not parse or critical fields missing.

Every judged verdict also carries a confidence level (`HIGH`/`MEDIUM`/`LOW`) with hard caps
(single observation or unknown rule input → at most `MEDIUM`; input-error reconciliation
residual above 1% → at most `LOW`), plus typed evidence signals — including evidence AGAINST
the verdict, printed and explained rather than dropped.

**Fail-closed analysis rule (critical):** a failed parse or missing critical field NEVER yields a
clean verdict with empty/zero data. A silent misparse (crc=None → treated as 0 → false IGNORE) is
the worst failure mode of this tool. Missing data ⇒ `PARSE_ERROR`/`UNVERIFIED`, always.

## 7. Report (the actual deliverable — sent by email, no ticketing system)

- Output: HTML (primary) + plain text, rendered via Jinja2 templates. Template defines the
  language of the deliverable (start in English; a Spanish template can be added by editing a
  text file, zero code changes).
- Enriched CSV alongside the HTML/text: the input table echoed verbatim (original columns —
  including ones iftriage does not parse — and original row order) with a curated set of
  analysis columns appended: verdict, reason, platform, the stats fields the rules consult,
  dq_flags, duplicate_of, recurrence. Written with the stdlib csv module; unknown values stay
  empty cells (fail closed), never zero.
- Structure:
  - Executive summary: "20 cases: 3 PHYSICAL_MEDIA, 2 LINK_NEGOTIATION,
    1 CONGESTION_BUFFER, 12 IGNORE, 1 HISTORIC_NOT_ACTIVE, 1 UNVERIFIED".
  - Data-quality section (duplicates, resets, window misalignment) — separate from verdicts.
  - One section per case: verdict, one-line justification written in DECISION language, not data
    language (e.g. "IGNORE — 0.003% error rate over 109M frames, counter flat across 12-min
    the earlier sample, DOM within range. No action."), then raw evidence (relevant show outputs) collapsed
    or attached.
- When SQLite history accumulates: add per-case recurrence line ("this interface appeared in the
  top-20 for 4 consecutive weeks at a constant rate") — turns IGNORE verdicts into
  indisputable ones.

## 8. Persistence (`history.py`, SQLite — single file, zero infra)

- Archive every ingested CSV (raw rows + received timestamp) BEFORE analysis. Each received
  table is free historical feed.
- Store every run: collected stats, verdicts, evidence references, and every
  remaining `CaseResult` field (`canonical_interface`, `parent_portchannel`, and
  the baseline it was judged against — `baseline_stats_json`, `baseline_minutes`,
  `baseline_taken_at`, `baseline_run_id`, `baseline_note`) — a stored run must be
  enough to rebuild the report it produced.
- `runs.replay_schema` marks a run as written with that full column set. A run
  missing fields the verdict depends on is never replayed: partial history is
  refused, not silently filled with defaults (fail closed, section 3's principle
  applied to storage). It is `2` since 0.6.0, because the second stored sample
  changed sides: a schema-1 row held the NEWER sample where a schema-2 row holds
  the OLDER one, and replaying it under the new direction would look faithful
  while answering a different question.
- A **baseline** read is deliberately not gated on that stamp: it consumes one
  column, `stats_json`, whose meaning never changed, so a run from before the
  upgrade can still serve as yesterday's sample even though it can no longer be
  replayed.
- Replay (`replay.py`, `iftriage run <csv> --from-history`) rebuilds the results
  from storage and re-runs the rules: zero device egress, and no run recorded.
  The ingest is deliberately not re-archived — a second row for the same CSV
  would inflate every recurrence count. (Opening the database still applies
  pending schema migrations; nothing else is written.)
- IP→platform cache.
- Future: suppression list with justification ("switch1 Gi3/0/20: chronic late-col since 2024,
  legacy half-duplex industrial link, ref X") so future reports highlight only NEW findings.
- Scale note: ~1000 devices worth of history is trivial for SQLite.

## 9. Package structure

```
iftriage/
├── pyproject.toml            # installable: pip install ., entry point `iftriage`
├── config.yaml               # thresholds, timeouts, baseline window bounds,
│                             # platform_overrides, report options
├── iftriage/
│   ├── cli.py                # `iftriage run top20.csv [--baseline] [--dry-run] ...`
│   ├── ingest.py             # CSV parser + data-quality checks
│   ├── models.py             # dataclasses: Device, InterfaceCase, NormalizedInterfaceStats,
│   │                         # Verdict, Finding
│   ├── session.py            # ReadOnlySession (safety layers 1–3 + audit log live here)
│   ├── baseline.py           # picks each case's earlier sample; explains rejections
│   ├── collectors.py         # per-platform collection orchestration
│   ├── normalize.py          # interface-name expansion + canonical counter schema mapping
│   ├── platforms/
│   │   ├── base.py           # PlatformProfile ABC + registry
│   │   ├── ios_xe.py
│   │   ├── nxos.py
│   │   └── eos.py
│   ├── rules.py              # verdict engine — PURE functions, no I/O, fully testable
│   ├── history.py            # SQLite persistence
│   ├── replay.py             # rebuild results from history (--from-history)
│   ├── report.py             # Jinja2 HTML/text report
│   └── templates/            # report templates, shipped as package data
│                             # (language lives here)
├── tests/
│   ├── fixtures/             # raw .txt show outputs per platform/command/case
│   └── ...                   # rules tested against fixtures; session tested for
│                             # allow-list rejection; zero device access in tests
└── README.md
```

- **Language: all code, docstrings, CLI, README, and identifiers in ENGLISH** (official project
  language). Report language is template-driven.
- CLI must include `--dry-run`: print targets and the exact commands that would run, connect to
  nothing.

## 10. Build plan (phased — fixtures before devices)

**Phase 1 — build without touching any device:**
1. Scaffold package, models, config loading, CLI skeleton with `--dry-run`.
2. Pull public fixtures from ntc-templates (`tests/` dirs contain real `.raw` device outputs with
   expected `.yml`) and genieparser unit-test folders for the three platforms / seven commands.
   These also reveal exactly which output formats the chosen parsers already cover.
3. Implement `session.py` with the three safety layers + audit log. Unit-test that non-allow-listed
   commands are rejected and config-mode prompts abort.
4. Implement platform profiles, normalize.py, collectors against fixtures.
5. Implement rules.py + full test suite using fixtures (this is the brain — test it hardest,
   including the fail-closed PARSE_ERROR behavior).
6. Implement ingest.py with data-quality checks, history.py, report.py.

**Phase 2 — validation with real outputs (user provides, sanitized):**
Real captured outputs from the user's network become additional fixtures. Cases needed:
copper up/up with errors; fiber/SFP interface (DOM parsing is the most fragile — formats vary by
line card and optic, not just OS); down/down interface; a port-channel + its summary; copper
RJ45 port run through the transceiver command (to capture each platform's empty/error response);
`show logging` with and without flap hits; real prompt lines included. If OS versions differ
notably in the fleet (e.g. NX-OS 9.x vs 10.x), one sample per version. Whatever doesn't parse
gets fixed in the parser layer only — the normalize.py boundary protects everything else.

**Phase 3 — first live run:** single device, `--dry-run` first, then one real device the user
designates, then the full top-20 flow.

## 11. Explicitly out of scope (do not build)

- Full-fleet polling (Splunk's job; the tool verifies the top-N only).
- Splunk API integration (team has web access only; a future companion-SPL CSV with traffic
  totals may be added as optional second input for better rate normalization — design ingest
  to allow a second optional CSV later).
- ServiceNow / ticketing integration (deliverable is email).
- Any configuration capability whatsoever. Diagnostic only, forever.
- Async at scale (scrapli-asyncssh) — not needed for top-20 workloads; revisit only if scope
  changes to hundreds of devices per run.

## 12. Recommended stack

- Python 3.11+, Netmiko (connections + SSHDetect), pyATS/Genie (IOS-XE & NX-OS parsing),
  ntc-templates/textfsm (EOS parsing), pandas (CSV ingest), Jinja2 (reports),
  SQLite via stdlib `sqlite3`, `pyproject.toml` packaging, pytest.

> **Implementation note (approved deviation candidate):** Phase 1 ships lightweight built-in
> parsers bound per command in each `PlatformProfile` instead of Genie/ntc-templates; the
> `parse(key, raw)` binding is the single swap-in point if Genie/textfsm is adopted later.
> This does not touch the safety model.
