# iftriage — Interface Error Triage Tool

Read-only triage for the recurring "Top 20 Interface Error Deltas, 24h" CSV
derived from Splunk. For each row, iftriage connects (READ-ONLY) to the listed
device, collects targeted diagnostics for the reported interface, applies a
rules engine, and produces an email-ready verdict report with raw evidence.

**Division of labor:** Splunk decides WHO is suspicious (the top-20 list).
iftriage decides WHETHER they are guilty (live verification). iftriage never
polls the full fleet — only the devices in the CSV.

## Safety model (non-negotiable)

Operator credentials have WRITE privileges; the tool makes configuration
change structurally impossible:

1. **Single egress point** — `ReadOnlySession` (`iftriage/session.py`) wraps
   the Netmiko connection as a private attribute; `get(command)` is the only
   public command method. *Code-review rule: any `send_command`/`send_config`
   outside `session.py` is an automatic rejection.*
2. **Closed allow-list, fail closed** — exact command strings derived from
   `PlatformProfile` templates for the target interfaces (interface names are
   regex-validated before substitution). Anything else raises.
3. **Mode verification** — the prompt is checked before and after every
   command; a `(config` prompt disconnects and aborts the whole run.
4. **Audit trail** — every exact command sent to every IP is logged with a
   timestamp. Credentials/enable secret never appear (`<enable elevation>`).

Additional operational safety: AAA circuit breaker (2 consecutive auth
failures abort the run), bounded concurrency (default 10), per-device
timeouts, jitter between connections, per-device try/except (a failed device
becomes `UNVERIFIED`). No `clear counters`, no `debug`, no `show tech`, no
config mode, ever.

**Bounded output:** `show logging | include <intf>` can return thousands of
lines on a noisy port. Two limits under `limits` in `config.yaml` keep that
from inflating the history database or the report — `max_output_bytes`
(default 1000000, a hard per-command ceiling that keeps the tail) and
`evidence_max_lines` (default 300, the head+tail copy stored and rendered).
Parsing always sees the full output, so neither limit can change a verdict;
truncation is marked inline in the raw evidence.

**Fail-closed analysis:** a missing/unparsed critical field never yields a
clean verdict — it becomes `PARSE_ERROR`, never a false `IGNORE`.

## Install

```bash
pip install .
# development
pip install -e '.[dev]'
pytest
```

## Usage

```bash
# Username on the command line, secrets typed into the terminal (getpass):
iftriage run top20.csv --user youruser --repoll 10

# See targets and the exact commands, connecting to nothing (no prompts):
iftriage run top20.csv --dry-run

iftriage run top20.csv --user youruser --no-repoll --output reports/ --workers 5
```

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

Outputs: HTML + plain-text report in the output directory, the session audit
log, and a SQLite history file (`iftriage_history.db`) archiving every
ingested CSV, run results, and the IP→platform cache.

### Command reference

| Command / flag | Effect |
|---|---|
| `iftriage run <csv>` | Triage every case in a top-N CSV |
| `--dry-run` | Print targets and exact commands; connect to nothing |
| `--user USERNAME` | Device username (default: `$IFTRIAGE_USER`, else prompt) |
| `--repoll MINUTES` | Re-poll counters after N minutes (default: config value) |
| `--no-repoll` | Skip the re-poll pass |
| `--config PATH` | Alternate `config.yaml` |
| `--output DIR` | Report/audit output directory (default: `reports/`) |
| `--workers N` | Override bounded concurrency |
| `--db PATH` | Override SQLite history path |
| `--version` | Print version |

## Development

Conventions live in [CLAUDE.md](CLAUDE.md); scope and architecture authority
is [PROJECT_SPEC.md](PROJECT_SPEC.md); the module map is in
[docs/architecture.md](docs/architecture.md). Every PR must keep CI green:

```bash
ruff check . && ruff format --check . && mypy iftriage && pytest --cov=iftriage
```

Work lands via `feat/...` or `fix/...` branches and PRs into the protected
`main` branch — never direct commits. Any change touching the read-only
guarantee (see CLAUDE.md security review) must be called out in the PR
description.

## Verdict vocabulary

| Verdict | Meaning |
|---|---|
| `PHYSICAL_MEDIA` | Real CRC/FCS at meaningful rate, DOM out of range, late-col on legacy half-duplex — inspect cable/transceiver/path |
| `CONFIG_ISSUE` | Duplex mismatch confirmed (late-col on full-duplex) — fixed via CLI |
| `CAPACITY` | Discards under load — saturation, not media |
| `IGNORE` | Negligible normalized rate / flat on re-poll / not an error counter |
| `UNVERIFIED` | Device unreachable / auth failed / required an enable secret that was not provided — CSV data only |
| `PARSE_ERROR` | Output did not parse or critical fields missing (fail closed) |

Rates are normalized: `error_delta / packet_delta` (re-poll window) or
lifetime errors/packets as fallback. Thresholds live in `config.yaml`
(default: ≥1e-4 high, ≥1e-5 warn).

## Supported platforms

| Platform | OS | Neighbors | Parsing |
|---|---|---|---|
| Cisco Catalyst | IOS-XE | CDP | built-in parsers (see note) |
| Cisco Nexus | NX-OS | CDP | built-in parsers (see note) |
| Arista (incl. DCS-7808-CH) | EOS | LLDP | built-in parsers (see note) |

Platform detection: `platform_overrides` in `config.yaml` → SQLite cache →
read-only Netmiko `SSHDetect` on first contact.

**Parser note (deliberate Phase-1 choice):** the spec recommends Genie/pyATS
(Cisco) and ntc-templates (EOS). Phase 1 ships lightweight built-in parsers
bound per command in each `PlatformProfile` and tested against fixtures; the
`parse(key, raw)` binding is the single swap-in point if Genie/textfsm is
preferred later. The fail-closed rule protects against any misparse either
way: unparsed critical fields produce `PARSE_ERROR`, never a clean verdict.

## Project phases

- **Phase 1 (this code):** everything built and tested against fixtures; zero
  device access in tests.
- **Phase 2:** sanitized real outputs from the fleet become additional
  fixtures (copper up/up with errors, fiber/SFP DOM, down/down, Po + summary,
  copper port through the transceiver command, `show logging` with/without
  flaps, per-OS-version samples). Parser fixes stay inside the platform
  layer; `normalize.py` protects everything else.
- **Phase 3:** first live run — `--dry-run`, then one designated device, then
  the full top-20 flow.

## Out of scope (by design, forever)

Full-fleet polling, Splunk API integration, ticketing integration, any
configuration capability whatsoever, async at scale.
