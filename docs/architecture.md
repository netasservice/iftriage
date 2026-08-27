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
              │        │                          report.py ──> templates/
              │        v
              ├──> normalize.py (interface-name expansion, validation)
              │
              ├──> session.py (ReadOnlySession — the ONLY device egress)
              │
              └──> history.py (SQLite: archive, results, platform cache)
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
| `report.py` | Jinja2 HTML/text rendering | no |

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
- **Report language**: a new Jinja2 template pair in `templates/`
  (`report_<lang>.html.j2` / `.txt.j2`) selected via `config.yaml` — zero code
  changes.
- **Second optional CSV** (future traffic totals for better normalization):
  ingest is the designated seam; see `PROJECT_SPEC.md` §11.

## Data flow of one run

1. Ingest CSV → `InterfaceCase` list + data-quality findings (bad rows are
   surfaced and excluded, not analyzed).
2. Archive the raw CSV to SQLite **before** analysis.
3. Collection pass: group cases by management IP, resolve platform
   (override → cache → SSHDetect), open one `ReadOnlySession` per device, run
   the per-interface command set from the platform profile (device-level
   commands once per device), parse into `NormalizedInterfaceStats`. The raw
   output kept as evidence is bounded; the text handed to parsers is not.
4. Optional re-poll pass after N minutes re-runs the counter commands to
   answer: still incrementing NOW, or historical?
5. `rules.py` produces one `Verdict` per case; port-channel members listed
   alongside their Po are marked duplicates; recurrence counts come from
   history.
6. Results persist to SQLite; Jinja2 renders the HTML + text report; the audit
   log holds every command sent.
