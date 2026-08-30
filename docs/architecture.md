# Architecture

`iftriage` verifies the top-N interface-error cases that Splunk flags, by
collecting read-only diagnostics per device and rendering an email-ready
verdict report. The design goal ranked above all others is the READ-ONLY
guarantee (`PROJECT_SPEC.md` §3): configuration change is structurally
impossible, not merely avoided.

## Layering

Dependencies point strictly inward; `rules.py` never knows the platform.

```
CSV ──> ingest.py ──────────────┐
                                v
cli.py ──> collectors.py ──> models.py (InterfaceCase, NormalizedInterfaceStats,
              │                          Verdict, CaseResult)
              │                ^                     │
              │                │                     v
              ├──> platforms/  │                  rules.py (pure, no I/O)
              │     base.py ───┘                     │
              │     ios_xe.py / nxos.py / eos.py     v
              │        │                          report.py ──> iftriage/templates/
              │        │                          (HTML + text; enriched CSV written
              │        v                           directly with the stdlib csv module)
              ├──> normalize.py (interface-name expansion, validation)
              │
              ├──> session.py (ReadOnlySession — the ONLY device egress)
              │
              └──> history.py (SQLite: archive, results, platform cache)
                        │
                        └──> replay.py (--from-history: results back out of
                              storage, straight into rules.py — no device)
```

## Module responsibilities

| Module | Responsibility | May touch devices? |
|---|---|---|
| `cli.py` | Argument parsing, run orchestration, credential resolution (flag → env → prompt) | no (delegates) |
| `ingest.py` | CSV parsing + data-quality checks | no |
| `models.py` | Shared dataclasses; `None` always means "unknown" | no |
| `session.py` | `ReadOnlySession`: safety layers 1–4, audit log | **only module allowed** |
| `collectors.py` | Concurrency, platform resolution, per-device collection, AAA breaker | via `session.py` only |
| `normalize.py` | Short→canonical interface names, safe-substitution validation | no |
| `platforms/` | `PlatformProfile` ABC + registry; command templates and parsers | no |
| `rules.py` | Verdict engine — pure functions over the canonical model | no |
| `history.py` | SQLite persistence (archive, runs, platform cache, recurrence) | no |
| `replay.py` | Rebuilds a run's results from stored data (`--from-history`); reads the database, never writes it | no |
| `report.py` | Jinja2 HTML/text rendering + enriched CSV writer (input rows echoed with analysis columns appended) | no |

## Key invariants

1. **Single egress point.** `ReadOnlySession.get()` is the only path to a
   device; the raw Netmiko connection is a private attribute. Any
   `send_command`/`send_config`/`ConnectHandler` outside `session.py` fails
   code review automatically.
2. **Closed allow-list.** The set of runnable commands is derived from
   `PlatformProfile.templates` rendered for the validated, canonical interface
   names of the current device — frozen at session construction. Everything
   else raises `CommandNotAllowed`.
3. **Prompt guard.** Privileged-exec (`#`) is verified before and after every
   command; a `(config` prompt disconnects and aborts the entire run
   (`ConfigModeDetected` → `RunAborted`).
4. **Fail-closed analysis.** `NormalizedInterfaceStats` fields are `Optional`;
   `None` is never coerced to zero. `rules.py` declares required fields per
   counter class and returns `PARSE_ERROR` when any are missing.
5. **Bounded evidence.** `session.get()` enforces a hard byte ceiling per
   command (keeping the tail, with a visible marker), and `collectors.py`
   stores a line-bounded head+tail copy in `raw_outputs`. Parsing always runs
   on the full output, so bounding evidence can never change a verdict. Both
   limits are configurable under `limits` in `config.yaml`.
6. **One failed device never kills the run** — it degrades to `UNVERIFIED`.
   The two deliberate exceptions that DO abort everything: a safety violation
   and the AAA circuit breaker (2 consecutive auth failures).

## Extension points

- **New platform**: add `platforms/<name>.py` with a `PlatformProfile`
  subclass and `register()` call. No changes to `rules.py`, `collectors.py`,
  or the report.
- **New/changed parser**: parsers are bound per command key inside each
  profile (`parse(key, raw, canonical_interface)`); swapping to Genie or
  textfsm affects only the platform layer. Every parser change ships with a
  raw fixture under `tests/fixtures/<platform>/`.
- **Report language**: a new Jinja2 template pair in `iftriage/templates/`
  (`report_<lang>.html.j2` / `.txt.j2`) selected via `config.yaml` — zero code
  changes.
- **Second optional CSV** (future traffic totals for better normalization):
  ingest is the designated seam; see `PROJECT_SPEC.md` §11.

## Data flow of one run

1. Ingest CSV → `InterfaceCase` list + data-quality findings (bad rows are
   surfaced and excluded, not analyzed).
2. Archive the raw CSV to SQLite **before** analysis.
3. Collection pass: group cases by management IP, resolve platform
   (override → cache → SSHDetect), open one `ReadOnlySession` per device, check
   the CPU guard (a device above `cpu_skip_threshold_percent` — or one whose
   CPU cannot be read — is skipped, fail closed), then run the per-interface
   command set from the platform profile (device-level commands once per
   device), parse into `NormalizedInterfaceStats`. The raw output kept as
   evidence is bounded; the text handed to parsers is not. The port-channel
   summary comes last and is conditional: it is sent only once every case's
   interface output is in hand and one of them proves relevant (a port-channel
   by name, or a port that named its parent bundle). IOS-XE cannot answer that
   from `show interfaces`, so it always sends the summary.
4. Abort gate: if the first pass collected nothing at all (every live case
   failed, none deliberately skipped), the run aborts here — exit code 3, no
   re-poll wait, no report.
5. Member pass: for each case that touches a port-channel — as the bundle or
   as one of its members, resolved in both directions from the pass-1 summary —
   reconnect to the device and run the per-interface command set on every
   member of that bundle (member names are validated by `normalize.py` before
   any template substitution; the session's allow-list is scoped to the member
   commands). A member case skips itself; a member shared by two cases on one
   device is sampled once. Failures land in `member_errors`, never on the
   pass-1 sample.
6. Optional re-poll pass after N minutes re-runs the counter commands (for the
   case interface and for every sampled member) to answer: still incrementing
   NOW, or historical?
7. `rules.py` produces one `Verdict` per case — a port-channel with member
   data is judged member by member and the verdict names the culpable member,
   while a case that is itself a member keeps its own single-interface verdict
   and carries its siblings as context only; port-channel members listed
   alongside their Po are marked duplicates; recurrence counts come from
   history.
8. Results persist to SQLite; Jinja2 renders the HTML + text report and the
   enriched CSV echoes the input table with the analysis columns appended (in
   the original row order); the audit log holds every command sent.

`iftriage run <csv> --from-history` short-circuits steps 2–6: `replay.py` pairs
every case ingested at step 1 with its newest stored collection and hands the
rebuilt `CaseResult`s straight to step 7. Analysis re-runs in full, so a rules
or threshold change is visible; collection does not happen at all. Nothing is
recorded — no run row, and no second archive of the CSV, which would inflate
every recurrence count. A case with no
stored collection fails the whole rebuild rather than quietly dropping a row
the operator asked about.
