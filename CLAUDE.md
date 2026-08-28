# CLAUDE.md — Engineering Conventions

This file governs how work is done in this repository. It takes precedence over
`PROJECT_SPEC.md` whenever the two disagree on conventions (workflow, style, process).
`PROJECT_SPEC.md` is the authority on scope, architecture, and the delivery plan — and its
section 3 (the READ-ONLY safety model) is non-negotiable: no convention, refactor, or
convenience ever overrides it.

## Documentation maintenance

`README.md`, `CHANGELOG.md`, `docs/architecture.md`, and `PROJECT_SPEC.md` must always
describe the state of the project that actually exists. Any change to scope, architecture,
the data model, the CLI surface, the command allow-list, or dependencies updates the
relevant document(s) **in the same commit** as the code change. A PR that changes behavior
without a documentation update is incomplete.

The CLI surface is deliberately small (`iftriage run` plus flags), so the full command
reference lives directly in `README.md` — no external wiki. If the CLI ever grows beyond
what a README table can hold, split the reference out and update this rule in the same PR.

Two documents deserve special care:
- Any change to the per-platform command set updates the command tables in
  `PROJECT_SPEC.md` section 5 (they ARE the auditable allow-list documentation).
- Any new verdict category or threshold updates `README.md` (verdict vocabulary table)
  and `config.yaml` comments.

## Git workflow

- One branch per issue, named `feat/<short-description>` or `fix/<short-description>`.
- Every change lands via a pull request into `main`. Never commit directly to `main`.
- `main` is protected: no direct pushes, PRs require passing CI checks before merge.
- Keep PRs scoped to one issue. If a PR touches anything noted in the security review
  section below, say so explicitly in the PR description.
- Releases are cut from `main` only: bump `__version__`, close `[Unreleased]` in the
  changelog, merge, then push a `vX.Y.Z` tag. `.github/workflows/release.yml` rejects a
  tag that is not an ancestor of `main`, disagrees with `__version__`, or has no
  changelog section — see the README "Releasing" section.

## English-only rule

All code, identifiers, comments, commit messages, PR descriptions, and documentation are
written in English, regardless of the language used to discuss the work. Report language
is the one exception by design: it lives in `iftriage/templates/` (a Spanish report is
a new template file, zero code changes).

## Coding principles

> Writing good code is less about making a machine understand your intent and more about
> ensuring other developers can easily read and modify your work later.

Follow these principles in order of priority.

### Architecture (SOLID)

- **Single Responsibility** — each function/class has exactly one reason to change.
- **Open/Closed** — extend behavior without modifying existing code.
- **Dependency Inversion** — depend on abstractions, not concrete implementations.

This is why `iftriage` layers strictly inward: `platforms/` (profiles + parsers) →
`normalize.py` → the canonical `NormalizedInterfaceStats` model; `rules.py` consumes ONLY
the canonical model and never knows the platform; `collectors.py` orchestrates;
`session.py` is the single egress point to devices. Adding a future platform = new
profile + parser registration, with **zero changes to `rules.py`**. Parser choice is a
per-command binding on each `PlatformProfile` (`parse(key, raw)`), so swapping in
Genie/textfsm later touches only the platform layer.

### Simplicity triad

- **DRY** — extract repeated logic into reusable helpers (see `platforms/base.py` shared
  table/neighbor parsers).
- **KISS** — choose the simplest design; avoid clever or over-engineered solutions.
- **YAGNI** — do not write code for assumed future requirements. `PROJECT_SPEC.md`
  section 11 lists what is explicitly out of scope (fleet polling, Splunk API, ticketing,
  async at scale, any configuration capability) — do not build it.

### Daily practices

- Descriptive naming: clear, unambiguous identifiers — no single-letter variables.
- PEP 8 formatting throughout (enforced by `ruff format` in CI).
- Comments explain *why*, not *what*. If removing a comment wouldn't confuse a future
  reader, don't write it.
- Wrap external calls (SSH/device I/O, file I/O, SQLite) in `try`/`except` with meaningful
  error strings — a raw traceback is never the only diagnostic. Device-level failures
  degrade to `UNVERIFIED`; they never kill the run.
- Always clean up resources: device sessions disconnect in `finally` blocks (see
  `collectors.py`), SQLite connections are closed, audit log writes are flushed per line.
- Errors of analysis fail CLOSED: a missing or unparsed critical field becomes
  `PARSE_ERROR`, never a default value and never a clean verdict.

## Security review (mandatory)

Every change is checked against the READ-ONLY guarantee (`PROJECT_SPEC.md` section 3),
which plays the role OWASP Top 10 plays in a web project. Concretely:

1. **Single egress point** — any `send_command`/`send_config`/`ConnectHandler` usage
   outside `iftriage/session.py` is an **automatic rejection**. No exceptions.
2. **Closed allow-list** — new commands are added only as `PlatformProfile` templates
   (never ad hoc strings), and the interface parameter must pass `normalize.py`
   validation before substitution. Deny-list thinking is rejected in review.
3. **Mode verification** — nothing may weaken the prompt guard (`(config` detection,
   privileged-exec check before/after every command, abort-on-violation).
4. **Secrets hygiene** — credentials and the enable secret are never logged, never
   persisted, never in `repr()`s or tracebacks. The audit log records commands, not
   secrets (`<enable elevation>`).
5. **No dangerous primitives** — no `eval`/`exec`/`os.system`/`shell=True` on any parsed
   or CSV-derived content; YAML is loaded with `yaml.safe_load` only; no `pickle`.
6. **Forbidden commands stay forbidden** — no `clear counters`, `debug`, `show tech`, or
   config mode, ever, including in tests and fixtures.

`tests/test_session.py` and `tests/test_normalize.py` are the executable enforcement of
rules 1–3; they must never be weakened to make a change pass. If a change touches any of
the above and the mitigation isn't obvious from the diff, call it out in the PR
description.

## Testing

- Every PR keeps CI green: `ruff check`, `ruff format --check`, `mypy`, `pytest --cov`.
- New logic ships with tests in the same PR. `rules.py` (the brain, including fail-closed
  behavior) and the platform parsers are the highest-value, most test-critical code in
  the project — new parser support lands with a raw fixture under `tests/fixtures/` and
  assertions on the canonical fields.
- **Zero device access in tests.** Sessions are exercised with fake connections;
  collectors and CLI are tested through `--dry-run` and pure logic paths. A test that
  opens a network connection is rejected.
- Real device outputs added as fixtures (Phase 2) must be sanitized: hostnames, IPs,
  serials, MACs, interface descriptions, and neighbor names replaced with fictional values
  before commit. Descriptions matter as much as the rest: site naming conventions
  (`SERVER-<rack>-RU<slot>`) leak the customer's physical topology even when every
  identifier around them is fake.
