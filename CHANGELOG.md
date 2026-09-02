# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.8.0] - 2026-09-02

### Added
- Side-by-side raw evidence: whenever a report rests on two collections (a
  live run with a baseline, or a two-collection replay), the HTML report
  renders both raw outputs of every command in two aligned columns — older
  left, newer right, per-command, with placeholders when a side lacks a
  command so rows never shift — and the text report carries the same
  comparison as sequential blocks, older first. The earlier raws are read
  from the baseline run's own stored row: no schema change, nothing new
  persisted.
- `--from-history` can now build the report from the latest TWO stored
  collections: when a second-newest replayable collection exists per case and
  its spacing from the newest respects the `baseline` window (the gap between
  the collections, not the wall clock), the command offers to pair them, the
  older acting as the baseline. `--baseline` / `--no-baseline` answer the
  offer up front — they were previously ignored under `--from-history` — and
  a run without a terminal replays the latest collection only, faithfully.
  Partial coverage falls back per case with a note; nothing is written back.
- Chronic-benign detection: a case that keeps appearing in the ingested
  top-20 (3+ lists) and has never been judged anything but IGNORE — this run
  and at least two stored runs — is marked as a chronic benign resident, with
  the report recommending the fix where it belongs: re-rank the Splunk
  search by error ratio (it ranks by absolute delta, so a busy link's
  negligible ratio holds a seat permanently) or exclude the interface.
  The source-disagreement note and the README now say plainly that the CSV
  `change` column's delta window is unstated and has proven inconsistent
  across rows, and that it is never used for rate math.
- Evidence is now time-aware. Interface resets are normalized by the
  counter's age and cited only when actually frequent ("60 resets" over 9.7
  years is six a year — maintenance, not evidence). When the lifetime error
  total at the current rate spans exactly the time since the last valid
  frame, the report dates the fault's onset — a concrete date to correlate
  with change windows. A reconciliation residual no larger than what the
  counters advance between two show commands is reported as sampling skew
  (no confidence cost) instead of "does not balance". Fiber next steps now
  print the DOM reading the tool already collected instead of sending the
  operator to fetch it, and non-copper ports without a DOM parse say so.
  The 100M-fallback line now connects to the symbol-corruption evidence when
  both are present: one damaged-pair story instead of disconnected facts.
- The canonical model and parsers now capture three pieces of context the
  devices were already printing: the device-computed
  `reliability x/255` triple (with txload/rxload; a value below 255 becomes
  corroborating evidence — the device's own error-weighted average reporting
  degradation), NX-OS vPC membership (`vPC Status/number` — actionable
  verdicts on a healthy vPC now say member-level remediation can be hitless
  and point at the peer leg), and the CDP neighbor `Platform:` string (a
  duplex mismatch against a managed IP phone now says the fix lives in CUCM,
  not at the jack). No new device commands; the allow-list is unchanged.

### Fixed
- Report polish from the field audit: next steps no longer suggest
  correlating with interface resets on a port that has none, and a
  port-channel case's counter-clear step targets the culpable member (the
  bundle only aggregates). The executive summary counts distinct issues when
  port-channel duplicates are present; the duplicate note says "same
  underlying issue" (an IGNORE discards pair is not a "physical issue"); and
  a port-channel verdict no longer prints the same verdict string three
  times (headline, member breakdown, and a bundle-analysis line that now
  appears only when the bundle view disagrees).
- Port-channel member samples now inherit the device-level fields (uptime,
  model, OS version) from their parent case: the member pass deliberately
  skips `show version`, which left members without a device clock — their
  interval provenance degraded to host-side timestamps, with a spurious
  data-quality flag, while the bundle on the same switch kept the device
  clock.
- The unattributed receive-error residual (the symbol-corruption proxy) now
  subtracts every congestion-side bucket the platform reports (overrun,
  ignored, no-buffer, giants), so buffer drops can no longer be labeled
  "symbol-level corruption" on a congested port.
- Input discards at rate on a port whose buffer-side counters are all flat
  are now reported as policy drops (unallowed VLAN, ACL, storm-control) with
  policy-first next steps, at MEDIUM — CONGESTION_BUFFER previously claimed
  buffer pressure the counters themselves refuted. Unknown buffer counters
  cap the claim instead of strengthening it.
- The bytes-per-frame-above-MTU observation is no longer listed as extra
  evidence under a zero-traffic verdict: with almost no counted frames the
  average exceeds the MTU by construction — it is the same observation, not
  corroboration.
- The metrics block now follows the case's own counter. "Error rate" was
  hardwired to the input-errors delta, so a Late-Col case printed
  "0.00/s" beside a 955K late-collision delta; it is now the flagged
  counter over the measured window. "Error ratio" names its denominator
  population — transmit-side counters (Late-Col, OutDiscards) are shares
  of attempted transmissions, never of received frames — and single-sample
  cases now print their lifetime share, labeled as such.
- The interval provenance label "(device uptime)" — which read as if the
  device had been up for 18 hours on a chassis with years of uptime — is now
  "(device clock (uptime delta))": the window was measured by the difference
  of the device's own uptime readings.
- The `zero_traffic_errors` rule no longer returns PHYSICAL_MEDIA HIGH while
  ignoring collision activity. It now applies the same collision guard as the
  media-dominance rule: with collisions or late collisions on the counters,
  the collision-aware rungs decide (a CDP-confirmed duplex mismatch now
  yields LINK_NEGOTIATION from a receive-error case too), and the
  errors-without-traffic observation is kept as evidence for whichever rung
  wins. When the collision counters were not parsed, the zero-traffic verdict
  stands but is capped MEDIUM with a data-quality flag saying why. Found in a
  field audit: a half-duplex port with 87K late collisions was reported as
  PHYSICAL_MEDIA HIGH without mentioning either.

## [0.7.0] - 2026-09-01

### Changed
- **Diagnostic engine v2.** Classification is now driven by WHICH error
  bucket is incrementing, never the total alone, in a deterministic ladder:
  INSUFFICIENT_DATA → HISTORIC_NOT_ACTIVE → CONGESTION_BUFFER →
  PHYSICAL_MEDIA → LINK_NEGOTIATION → IGNORE. New verdict vocabulary:
  `LINK_NEGOTIATION` (absorbs the old CONFIG_ISSUE duplex-mismatch cases,
  plus giants/MTU profiles), `CONGESTION_BUFFER` (renames CAPACITY),
  `HISTORIC_NOT_ACTIVE` (a large lifetime counter with zero movement between
  the tool's own two observations is not an incident), and
  `INSUFFICIENT_DATA` (a never-cleared lifetime counter with no second
  observation supports no rate). `UNVERIFIED` and `PARSE_ERROR` keep their
  fail-closed semantics untouched. Every judged verdict carries a confidence
  (HIGH/MEDIUM/LOW) with hard caps, typed evidence signals — including
  evidence AGAINST the verdict, printed and explained instead of dropped —
  and labeled metrics.
- Rates can no longer exceed 100%: every ratio pairs same-population
  operands (delta received frames as the input-side denominator, delta
  output packets for output discards), and an out-of-range ratio is
  suppressed and flagged instead of printed. The IOS-XE/NX-OS `Rcv-Err`
  column no longer overwrites `input_errors` — it is a different series, and
  the engine now reconciles `input errors == runts + Rcv-Err` at runtime,
  leading its narrative with the unattributed residual (the symbol-error
  proxy) instead of the total.
- The report labels both delta sources (`Δ (iftriage, run-to-run)` vs
  `Δ (CSV, Splunk window)`), never calls a window "24h" unless it is one,
  states each interval's provenance (device uptime → counter-clear age →
  host-side timestamps), and raises a headline data-quality item when the
  CSV poll is older than 24 h at report time. Report sentences are keyed on
  signal kinds in the templates, so a new report language is still a
  template-only change.
- `REPLAY_SCHEMA` is now 3: pre-v2 runs are barred from `--from-history`
  (their rows lack the per-bucket counters the v2 report renders) but still
  serve as baselines, with missing fields capping confidence instead of
  faking values.

### Added
- Media-aware remediation in the reports: next steps are derived from the
  observed media type (a copper port is told about jacks, patch cords and
  TDR, never transceivers — and DOM absence on copper is rendered as
  expected, not a finding; optical ports get connector/DOM/transceiver
  language). Disruptive actions (TDR, manual counter clearing) are labeled
  apart and framed as human-coordinated — the tool still never executes
  them. HISTORIC_NOT_ACTIVE verdicts carry their own "what would change
  this" line.
- The enriched CSV gains `confidence`, the error-decomposition buckets
  (`fcs_errors`, `rcv_err`, `runts`, `giants`, `overrun`, `ignored`,
  `no_buffer`, `interface_resets`, `media_type`, `mtu`), both labeled deltas
  (`delta_tool`, `delta_csv`), `interval_source`, and the per-case
  `data_quality` flag kinds.
- Structured verdict data model (not yet produced by the engine): verdicts
  can now carry a confidence level (HIGH/MEDIUM/LOW), typed evidence signals
  with named counter values (including explicit "evidence against"), typed
  data-quality flags, labeled metrics (both delta sources, interval length
  and its provenance, staleness), and a "what would change this verdict"
  signal. Rules emit enum kinds plus values — zero prose — so report
  sentences live entirely in the templates and a new report language remains
  a template-only change. Stored per case as a new `verdict_json` column
  (added in place to existing databases).
- New pure modules `metrics.py` and `timebase.py` (not yet wired into the
  verdict engine): population-safe delta/ratio math that refuses to mix
  lifetime, tool-delta, and CSV-delta counters in one ratio (an out-of-range
  ratio becomes a data-quality flag, never a printed percentage), input-error
  reconciliation (`input errors == runts + Rcv-Err`) with its unattributed
  residual, the zero-traffic test, the byte-per-frame MTU sanity check, and
  interval derivation that always labels its source (device uptime → counter
  epoch → CSV poll time → host clocks) with staleness detection.
- The canonical interface model now captures the full receive-error
  decomposition (runts, giants, undersize, FCS, alignment, symbol, overrun,
  ignored, no buffer, and the platform's aggregate `Rcv-Err` column kept as
  its own `rcv_err` field), byte counters, MTU, media type, the counter epoch
  (`Last clearing ... never` vs a parsed age), `Last input`, device-reported
  load-interval rates, interface resets, and the device uptime parsed from
  the already-collected `show version`. All new fields are Optional and
  unused by the current verdict engine — groundwork for the v2 diagnostic
  engine. No new device commands; the allow-list is unchanged.

### Fixed
- The EOS `counters errors` `Tx` column now maps to `output_errors`; it was
  previously mapped to `discards_out` although it counts transmit errors.

## [0.6.0] - 2026-08-30

### Added
- **Runs now compare against the newest earlier sample stored for each
  interface.** A run takes one sample, stores it, and — before contacting
  anything — offers the stored samples it found: *"Stored earlier samples found
  for 8 of 20 case(s) (newest 18.3 h ago, oldest 4.9 d ago)."* Answer once and
  the rest of the run is unattended. `--baseline` and `--no-baseline` answer it
  up front for scripts; without an explicit flag and without a terminal the
  answer is no, because a baseline can only narrow a verdict and must never be
  applied silently to a run nobody is watching.
- The baseline belongs to the **interface**, not to the CSV: the key is
  `(switch, interface, counter)`, so next week's top-20 list finds samples for
  the rows it shares with this week's and simply has none for the rest. Partial
  coverage is the normal case, and the report says per case what it was
  compared against — or that its verdict rests on a single reading. A port
  spelled `Gi1/0/1` in one export and `GigabitEthernet1/0/1` in the next still
  matches; both forms are stored.
- **`baseline.min_window_minutes` (5) and `baseline.max_window_days` (14)**
  guard the claim the verdict makes. Samples too close together read as flat
  because nothing had time to move, and a false "flat" *suppresses* escalation
  to `PHYSICAL_MEDIA` or `CAPACITY`; samples weeks apart can no longer support
  "still incrementing NOW". Both are configurable, and crossed bounds are a
  hard error rather than a silently disabled feature.
- Report provenance per case: the timestamp of the sample it was compared
  against, how long the window was, and which run it came from — plus the
  matching `baseline_taken_at` and `baseline_window` columns in the enriched
  CSV.

- **`--from-history` rebuilds the report from the collection already stored**,
  contacting no device and asking for no credentials. Collection is the
  expensive half of a run and the analysis is the cheap half; this replays the
  first so the second can be iterated on — a template tweak, a threshold
  change, a new rule — without asking the fleet again. Verdicts are re-derived
  from the stored counters rather than replayed, so `rules.py` and
  `config.yaml` edits show up too. It writes nothing back: re-archiving the
  same CSV would inflate every recurrence count. If any row of the CSV has no
  stored collection, the whole rebuild fails with exit code 2 and names the
  rows to collect.
- `case_results` now also stores `canonical_interface` and `parent_portchannel`
  — fields a faithful rebuild needs and the schema used to drop. Added in place
  to existing databases, like `members_json` before them.
- `runs.replay_schema` marks a run as written with the full column set. Runs
  recorded by 0.5.0 and earlier are missing fields the verdict depends on, so
  `--from-history` refuses them rather than replaying a report that looks
  faithful while quietly answering a different question.

### Changed
- **The delta now runs from the stored sample to the fresh one**, the opposite
  of the direction the code carried since 0.1.0, where the fresh sample was the
  older half. `rules._counter_delta` is keyword-only (`earlier=`, `later=`) so
  no positional call site can survive the change and silently negate every
  delta. A sample whose counters read *lower* than today's is still discarded
  as a reload or a counter clear — and discarded means unknown, never flat, so
  it can never veto an escalation.
- `runs.replay_schema` is `2`. A schema-1 row stored the newer sample where a
  schema-2 row stores the older one, so runs recorded by 0.5.0 and earlier are
  no longer replayable with `--from-history`. Their samples *can* still serve
  as a baseline: that read consumes one column, `stats_json`, whose meaning
  never changed, which is what lets the first run after an upgrade already
  compare against yesterday.
- `case_results` carries five `baseline_*` columns, added in place to existing
  databases. The four retired `repoll_*` columns are left exactly where they
  are — never written again, never read again — because dropping a column
  rewrites the table for no gain and their data stays auditable.
- **Errors and discards now have their own escalation floor, configured as a
  percentage.** `rate_high` and `rate_warn` are gone; `thresholds` takes
  `error_rate_percent` (default 0.001%, i.e. 10 per million frames) and
  `discard_rate_percent` (default 1%). Cisco's port troubleshooting guidance
  (Doc ID 12027) puts the ~1% error tolerance on half-duplex links only and
  expects essentially zero FCS/CRC/alignment on full-duplex, while an
  out-discard is an intact frame dropped for buffer or policy reasons —
  congestion, routine on a busy uplink. A single number could not serve both,
  and the discard noise that prompted this is what the 1% floor removes.
  The comparison against an earlier sample remains the filter that separates a
  live fault from a counter that stopped moving long ago.
- **A `config.yaml` carrying the retired keys now fails the run** instead of
  being ignored in silence, which would have judged every interface by the
  built-in defaults. Percentages are validated to be within `0 < x <= 100`.
  Unknown keys under `connection` and `limits` are still skipped on purpose:
  that is what keeps a stray `workers:` from widening the fan-out.
- **The report header states the thresholds it judged with**, so a run made
  with a mistyped floor is recognizable from the deliverable alone.
- **`IGNORE` no longer calls a flat counter "below the noise threshold".** A
  rate above the floor that the earlier sample shows flat is reported as
  historical; only a rate under the floor is reported as below it.

### Removed
- **The re-poll is gone, and with it the wait.** `--repoll`, `--no-repoll` and
  the `repoll` section of `config.yaml` no longer exist. A run used to contact
  every device, sleep for ten minutes and contact them all again; the terminal
  was frozen for the whole interval and the answer it bought — is this counter
  still incrementing? — was measured over ten minutes. It is now measured
  against a previous run, over hours or days, and nothing blocks. Each device
  is contacted once instead of twice, so the audit log is shorter too.
- **A `config.yaml` still carrying `repoll:` fails the run** rather than being
  ignored, for the same reason the retired `thresholds` keys do: the file would
  describe behavior that no longer exists, and the operator would go on
  believing the tool waits.

## [0.5.0] - 2026-08-29

### Changed
- **Arista EOS uses `show port-channel dense`** instead of
  `show port-channel summary`. `dense` is the compact table the fleet's 7808
  actually renders for its ~700 channels; the shared parser already handled the
  dense flag characters (`+ ^ *`) and wrapped member lines, so this is a
  command-table change only.
- **The port-channel summary is now sent only when it can matter.** It used to
  run once on every device regardless of what was being diagnosed. On EOS and
  NX-OS a physical port's `show interfaces` names its bundle (`Member of
  Port-Channel195`, `Belongs to Po21`), so the summary is now gated on a case
  being a port-channel by name or declaring a parent. IOS-XE never names the
  channel-group there, so `show etherchannel summary` stays unconditional — it
  is the only source of membership on that platform. The allow-list is
  unchanged: it remains the auditable ceiling of what may be sent, and the gate
  only narrows what actually is.

### Added
- **`scripts/regen_examples.py`** regenerates every artifact in
  `docs/examples/` by replaying the sanitized fixtures. Only the transport
  under `session.py` is replaced, so the allow-list, the prompt guard and the
  audit log doing the work are the production ones; the clock is frozen so the
  output is byte-reproducible. `--check` fails when the committed artifacts
  drift, and `tests/test_examples.py` runs it, so behavior changes can no
  longer leave the examples stale. The committed artifacts had been generated
  before 0.4.0 and were missing the CPU guard commands entirely.
- **Member cases expand to their whole bundle.** Membership is now resolved in
  both directions from the same summary output, so a CSV case that is a
  *member* of a port-channel — not just a case that IS one — pulls in every
  other member of that bundle for collection. The verdict stays about the
  interface the CSV reported and is judged exactly as any single interface;
  the siblings are attached as `member_findings` context, and a dirty or
  uncollectable sibling never changes the reported port's category. Sibling
  members shared by two cases on one device are sampled once.

## [0.4.0] - 2026-08-29

### Added
- **Port-channel member triage.** When a CSV case is a port-channel, iftriage
  now reconnects to the device and runs the full per-interface command set
  (interface, counters, transceiver, neighbors, logging) on every member
  discovered in the `etherchannel`/`port-channel summary` output, re-polls the
  members alongside the bundle, and judges the case member by member: the
  verdict names the culpable member (`fault isolated to member Gi3/0/23 — ...`)
  instead of applying cable/transceiver language to a logical bundle whose
  summed counters dilute a single bad member below the noise threshold. A
  member that cannot be collected or parsed fails the bundle closed to
  PARSE_ERROR; bundle errors with clean members degrade to "not attributable
  to any current member". Member names are device-derived text and pass
  `normalize.py` validation before any command substitution; the member session
  gets a key-scoped allow-list and `session.py` is unchanged. The member
  breakdown is rendered in the HTML/text reports, a new `member_summary` CSV
  column, and a new `members_json` column in the history database (added in
  place to existing databases).
- **CPU guard before collection.** Right after login, iftriage reads the
  device's current CPU utilization (`show processes cpu` on IOS-XE,
  `show system resources` on NX-OS, `show processes top once` on Arista EOS)
  and skips the device — its cases become UNVERIFIED with the reason in the
  report — when utilization is above `connection.cpu_skip_threshold_percent`
  (default 80, configurable in `config.yaml`). The guard fails closed: an
  unreadable CPU reading also skips the device. During the re-poll pass a busy
  device keeps its first sample and only gives up the delta, with the skip
  noted on the case. A run in which every device was CPU-skipped still writes
  its report (and skips the pointless re-poll wait).

### Fixed
- **A run in which every device failed collection no longer waits for the
  re-poll.** With a single device and wrong credentials (one failure — below
  the AAA breaker's limit of 2 consecutive), the tool used to sit out the full
  re-poll interval and then emit an all-UNVERIFIED report. The first pass now
  aborts immediately (`RUN ABORTED`, exit code 3, no report) when nothing at
  all was collected. Deliberate skips (`device skipped: ...`, e.g. a device
  that requires an enable secret the run does not have) still produce the
  report — those are outcomes worth reading, not collection failures.

## [0.3.0] - 2026-08-29

### Added
- **Enriched CSV report.** Every run now writes
  `reports/iftriage_report_<stamp>.csv` next to the HTML and text reports: the
  input CSV echoed verbatim (original columns — including ones iftriage does
  not parse — and original row order) with the analysis appended as extra
  columns (verdict, reason, platform, the stats fields the rules consult,
  dq_flags, duplicate_of, recurrence). Unknown values stay empty cells, never
  zero, keeping the fail-closed convention visible in the spreadsheet.

### Changed
- **iftriage now contacts one device at a time by default.** Concurrency became
  an explicit command-line opt-in (`--workers N`, default 1) and the
  `connection.workers` key was removed from `config.yaml` entirely, so no
  configuration file can widen the fan-out — a command states how many devices
  it touches. The previous default opened up to 10 SSH sessions at once, which
  defeated the AAA circuit breaker: 10 workers put 10 authentication attempts
  in flight before the breaker could observe the first failure, enough to lock
  an operator account against a strict lockout policy. A `config.yaml` that
  still carries `connection.workers` is loaded normally and that key is
  ignored.
- A run that does ask for `--workers N` (N > 1) now contacts a single device
  sequentially before fanning out and aborts if authentication fails there, so
  wrong credentials cost one failed login instead of N.
- `--workers 0` and negative values are now a usage error (exit 2) instead of
  being silently discarded by a falsy check.

### Documentation
- `README.md` restructured around what an operator actually needs, in order:
  what the tool is, what a run produces, install, use, input, output, reference.
  New sections document the input CSV (all eleven columns and the four
  data-quality checks), the output artifacts and exit codes, `config.yaml`, the
  requirements, and the module map. Stale claims were removed: Phase 2 is
  finished, and NX-OS collects LLDP as well as CDP.
- Added `docs/examples/`: a worked end-to-end run (input CSV, dry run, console
  transcript, HTML and text report, audit log), generated by running iftriage
  against devices that replay the sanitized fixtures in `tests/fixtures/`.

## [0.2.0] - 2026-08-28

### Added
- Continuous delivery: pushing a `vX.Y.Z` tag runs
  `.github/workflows/release.yml`, which re-runs the CI gate (`ci.yml` is now a
  reusable workflow, so the checks are shared rather than copied), builds the
  wheel and sdist, smoke-tests the wheel in a clean environment outside the
  source tree, and publishes a GitHub Release with both artifacts and the
  matching changelog section as its notes. Three guards must pass first: the
  tag is an ancestor of `main`, it matches `iftriage.__version__`, and the
  changelog documents that version. Distribution stays inside this repository —
  no package index is involved.
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
- `pyproject.toml` no longer carries its own `version`; it reads
  `iftriage.__version__` as a dynamic attribute, so a release cannot ship with
  the two out of step.
- Fixture sanitization now covers interface descriptions and neighbor names, not
  just hostnames/IPs/serials/MACs. Real rack-and-slot descriptions
  (`SERVER-205-RU15`, `ACCESS-PHONE-205-RU15`) and two genuine-format serials
  (`FCW2245L0AB`, `FNS17221H4A`) that predated the rule were replaced with
  fictional equivalents. No canonical field is derived from either, so no
  parser, rule, or assertion changes.
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
- Report templates now live inside the package (`iftriage/templates/`) and are
  loaded with Jinja2's `PackageLoader` instead of a path walked up from
  `report.py`. The old location resolved to `<site-packages>/templates`, which
  does not exist in an installed distribution, so any run that reached the
  rendering step from a `pip install`-ed copy (as opposed to an editable
  install) failed. Selecting a report language is unchanged: drop a new
  `report_<lang>.html.j2` / `.txt.j2` pair in `iftriage/templates/`.
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
