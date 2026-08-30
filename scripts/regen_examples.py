#!/usr/bin/env python3
"""Regenerate the artifacts under docs/examples/ from the sanitized fixtures.

No device is ever contacted. Only the *transport* beneath `ReadOnlySession` is
replaced, so the allow-list, the prompt guard, the enable elevation and the
audit log are the production ones — the artifacts are genuinely the tool's own
output, which is what the README claims about them.

What is scripted here is only what a device would have supplied: the raw text
of each command, and how the counters moved between yesterday and today. The
earlier sample is served from `tests/fixtures/` verbatim and stored by a
priming run that is then back-dated; only the climb is authored, because a
delta cannot be captured in a single snapshot.

    python scripts/regen_examples.py            # rewrite docs/examples/
    python scripts/regen_examples.py --check    # fail if they are out of date
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from iftriage import cli, collectors  # noqa: E402
from iftriage import history as history_mod  # noqa: E402
from iftriage import report as report_mod  # noqa: E402
from iftriage import session as session_mod  # noqa: E402
from iftriage.models import Platform  # noqa: E402
from iftriage.session import ReadOnlySession  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures"
EXAMPLES = REPO_ROOT / "docs" / "examples"
INPUT_CSV = "docs/examples/input.csv"

# Every timestamp in the artifacts comes from this instant, so re-running the
# script produces a byte-identical result.
FROZEN_NOW = datetime(2026, 8, 29, 20, 29, 21, tzinfo=UTC)

# IOS-XE answer for an interface that no longer exists on the chassis. It
# parses to nothing, which is what drives the fail-closed PARSE_ERROR case.
IOS_INVALID_INTERFACE = (
    "                                       ^\n"
    "% Invalid input detected at '^' marker.\n"
)


@dataclass
class DeviceScript:
    """One simulated device: what it answers, and how its counters move."""

    platform: Platform
    prompt: str
    # command -> fixture path relative to tests/fixtures, or literal text
    responses: dict[str, str] = field(default_factory=dict)
    # Applied to every pass: retargets a captured port onto this device's port
    # and trims counters the capture carries but this story does not, so no
    # device is ever shown output that belongs to a different interface.
    edits: list[tuple[str, str]] = field(default_factory=list)
    # Applied to today's sample only: (old, new) substitutions standing in for
    # counters that moved since the stored earlier one. The fixtures hold the
    # earlier values, so these are always the larger numbers.
    climb_edits: list[tuple[str, str]] = field(default_factory=list)
    # A device that starts in user exec and must be elevated to run shows.
    starts_in_user_exec: bool = False
    connect_error: str | None = None


def _ios_xe(interface: str, *, invalid: bool = False) -> dict[str, str]:
    """The IOS-XE per-interface command set for one access port."""
    if invalid:
        return {
            f"show interfaces {interface}": IOS_INVALID_INTERFACE,
            f"show interfaces {interface} counters errors": IOS_INVALID_INTERFACE,
            f"show interfaces {interface} transceiver detail": IOS_INVALID_INTERFACE,
            f"show cdp neighbors {interface} detail": IOS_INVALID_INTERFACE,
            f"show logging | include {interface}": "",
        }
    return {
        f"show interfaces {interface}": "ios_xe/show_interfaces.txt",
        f"show interfaces {interface} counters errors": "ios_xe/counters_errors.txt",
        # A copper access port: the chassis has no optics to report on it.
        f"show interfaces {interface} transceiver detail": (
            "ios_xe/real_transceiver_not_implemented.txt"
        ),
        f"show cdp neighbors {interface} detail": "ios_xe/cdp_neighbors_detail.txt",
        f"show logging | include {interface}": "ios_xe/logging.txt",
    }


_IOS_XE_COMMON = {
    "show processes cpu | include CPU utilization": "ios_xe/processes_cpu.txt",
    "show version": "ios_xe/real_show_version_c9410.txt",
    "show etherchannel summary": "ios_xe/etherchannel_summary.txt",
}

_NXOS_COMMON = {
    "show system resources": "nxos/system_resources.txt",
    "show version": "nxos/show_version.txt",
    "show port-channel summary": "nxos/port_channel_summary.txt",
}


def _nxos(interface: str) -> dict[str, str]:
    return {
        f"show interface {interface}": "nxos/show_interface.txt",
        f"show interface {interface} counters errors": "nxos/counters_errors.txt",
        f"show interface {interface} transceiver details": (
            "nxos/transceiver_details.txt"
        ),
        f"show lldp neighbors interface {interface} detail": (
            "nxos/cdp_neighbors_detail.txt"
        ),
        f"show cdp neighbors interface {interface} detail": (
            "nxos/cdp_neighbors_detail.txt"
        ),
        f"show logging logfile | include {interface}": "",
    }


DEVICES: dict[str, DeviceScript] = {
    # sw-acc-01: a printer port with real CRC errors that are still climbing,
    # plus a decommissioned port the chassis no longer knows about.
    "192.0.2.11": DeviceScript(
        platform=Platform.IOS_XE,
        prompt="switch_catalyst#",
        responses={
            **_IOS_XE_COMMON,
            **_ios_xe("GigabitEthernet3/0/20"),
            **_ios_xe("GigabitEthernet1/0/47", invalid=True),
        },
        # +412 errors over +1,382,200 frames: a live rate of 298 per million.
        climb_edits=[
            ("3271 input errors, 3271 CRC", "3683 input errors, 3683 CRC"),
            ("109443210 packets input", "110825410 packets input"),
            (
                "Gi3/0/20              0        3271           0        3271",
                "Gi3/0/20              0        3683           0        3683",
            ),
        ],
    ),
    # sw-acc-02: half duplex against a phone that reports full — the textbook
    # duplex mismatch. This device also starts in user exec.
    "192.0.2.12": DeviceScript(
        platform=Platform.IOS_XE,
        prompt="switch_catalyst#",
        starts_in_user_exec=True,
        responses={
            **_IOS_XE_COMMON,
            "show interfaces GigabitEthernet3/0/20": (
                "ios_xe/real_show_interfaces_half_duplex.txt"
            ),
            "show interfaces GigabitEthernet3/0/20 counters errors": (
                "ios_xe/real_counters_errors_late_col.txt"
            ),
            "show interfaces GigabitEthernet3/0/20 transceiver detail": (
                "ios_xe/real_transceiver_not_implemented.txt"
            ),
            "show cdp neighbors GigabitEthernet3/0/20 detail": (
                "ios_xe/real_cdp_neighbors_phone_mismatch.txt"
            ),
            "show logging | include GigabitEthernet3/0/20": (
                "ios_xe/real_logging_duplex_mismatch.txt"
            ),
        },
        # +3,096 late collisions: the mismatch is live, not historical.
        climb_edits=[
            ("38445916 late collision", "38449023 late collision"),
            (
                "Gi3/0/20     2221984     463596   38445927",
                "Gi3/0/20     2221984     463596   38449023",
            ),
            ("92971720 packets input", "92983104 packets input"),
        ],
    ),
    # sw-acc-03: an access point port flagged on a total-traffic counter. The
    # captured shapes are retargeted onto Gi2/0/1 and its error counters
    # cleared: this port was never flagged for errors, only for throughput.
    "192.0.2.13": DeviceScript(
        platform=Platform.IOS_XE,
        prompt="switch_catalyst#",
        responses={**_IOS_XE_COMMON, **_ios_xe("GigabitEthernet2/0/1")},
        # Order matters: the counters row is rewritten before the generic
        # short-name rename, which would otherwise stop it matching.
        edits=[
            (
                "Gi3/0/20              0        3271           0        3271",
                "Gi2/0/1               0           0           0           0",
            ),
            ("3271 input errors, 3271 CRC", "0 input errors, 0 CRC"),
            ("GigabitEthernet3/0/20", "GigabitEthernet2/0/1"),
            ("Gi3/0/20  ", "Gi2/0/1   "),
            ("gi3/0/20", "gi2/0/1"),  # the prompt echo in the real captures
            ("ACCESS-FLOOR3-PRINTER", "ACCESS-FLOOR2-AP"),
        ],
    ),
    # sw-acc-04: unreachable. Its case must degrade to UNVERIFIED, not vanish.
    "192.0.2.14": DeviceScript(
        platform=Platform.IOS_XE,
        prompt="switch_catalyst#",
        connect_error="TCP connection to device failed: timed out",
    ),
    # sw-dist-01: an Arista uplink whose optics are out of range.
    "192.0.2.21": DeviceScript(
        platform=Platform.EOS,
        prompt="switch_arista#",
        responses={
            "show processes top once | include Cpu": "eos/processes_top_cpu.txt",
            "show version": "eos/show_version.txt",
            "show port-channel dense": "eos/real_port_channel_dense.txt",
            "show interfaces Ethernet4/15": "eos/show_interfaces.txt",
            "show interfaces Ethernet4/15 counters errors": "eos/counters_errors.txt",
            "show interfaces Ethernet4/15 transceiver": "eos/transceiver.txt",
            "show lldp neighbors Ethernet4/15 detail": (
                "eos/lldp_neighbors_detail.txt"
            ),
            "show logging | include Ethernet4/15": "",
        },
    ),
    # sw-core-01: discards under load on a Nexus uplink — capacity, not media.
    "192.0.2.31": DeviceScript(
        platform=Platform.NXOS,
        prompt="switch_nexus#",
        responses={**_NXOS_COMMON, **_nxos("Ethernet4/15")},
        # A congestion case: frames arrive intact and are dropped, so the
        # capture's CRC counters are cleared — nothing is wrong with the media.
        edits=[("912 CRC", "0 CRC"), ("912 input error", "0 input error")],
        climb_edits=[
            ("388 input discard", "3988 input discard"),
            ("89425035 input packets", "89605035 input packets"),
        ],
    ),
    # sw-core-02: the mirror case — real receive errors, but far below the
    # noise floor and flat since the earlier sample. Its discards are cleared.
    "192.0.2.32": DeviceScript(
        platform=Platform.NXOS,
        prompt="switch_nexus#",
        responses={**_NXOS_COMMON, **_nxos("Ethernet4/15")},
        edits=[("388 input discard", "0 input discard")],
    ),
}

# Cases carried over from a previous week's top-20, so that recurrence is not
# uniformly 1 across the report.
PRIOR_INGEST = [("sw-acc-01", "Gi3/0/20"), ("sw-dist-01", "Et4/15")]


class UnscriptedCommand(Exception):
    """A command reached the simulator that no device script answers."""


# Flipped between the priming run (yesterday's counters) and the run whose
# output becomes the artifacts (today's, higher, counters).
_CLIMBING = False


class FakeConnection:
    """The Netmiko-shaped object `ReadOnlySession` drives. Answers from text."""

    def __init__(self, script: DeviceScript, climbing: bool):
        self._script = script
        self._climbing = climbing
        self._elevated = not script.starts_in_user_exec

    def find_prompt(self) -> str:
        if self._elevated:
            return self._script.prompt
        return self._script.prompt.rstrip("#") + ">"

    def enable(self) -> None:
        self._elevated = True

    def send_command(self, command: str, read_timeout: int | None = None) -> str:
        try:
            body = self._script.responses[command]
        except KeyError:
            raise UnscriptedCommand(
                f"no scripted answer for {command!r} on this device"
            ) from None
        text = (FIXTURES / body).read_text() if body.endswith(".txt") else body
        edits = list(self._script.edits)
        if self._climbing:
            edits += self._script.climb_edits
        for old, new in edits:
            text = text.replace(old, new)
        return text

    def disconnect(self) -> None:
        pass


class _FrozenDateTime(datetime):
    """datetime whose now() is pinned, so artifacts are reproducible."""

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return FROZEN_NOW if tz is not None else FROZEN_NOW.replace(tzinfo=None)


def _install_simulator() -> None:
    """Swap in the fake transport, the scripted platforms and frozen time."""

    def fake_connect(host, device_type, credentials, timeout):
        script = DEVICES[host]
        if script.connect_error:
            raise OSError(script.connect_error)
        return FakeConnection(script, climbing=_CLIMBING)

    def session_factory(**kwargs):
        return ReadOnlySession(**kwargs, connect_fn=fake_connect)

    def fake_autodetect(mgmt_ip, credentials, timeout):
        script = DEVICES[mgmt_ip]
        if script.connect_error:
            # Autodetection is itself an SSH connection: an unreachable device
            # cannot answer it either.
            raise OSError(script.connect_error)
        return script.platform

    collectors.ReadOnlySession = session_factory  # type: ignore[assignment]
    collectors._autodetect = fake_autodetect  # type: ignore[assignment]
    for module in (cli, collectors, report_mod, session_mod, history_mod):
        module.datetime = _FrozenDateTime  # type: ignore[attr-defined]


def _seed_history(db_path: Path) -> None:
    """Record one earlier top-20 list so recurrence has something to count."""
    from iftriage.ingest import ingest_csv

    cases, _ = ingest_csv(str(REPO_ROOT / INPUT_CSV))
    earlier = [case for case in cases if (case.switch, case.interface) in PRIOR_INGEST]
    store = history_mod.History(str(db_path))
    store.archive_ingest("last_week_top20.csv", "", earlier)
    # sw-acc-04 was reachable last week, so its platform is already cached.
    # That is what lets an unreachable device still be reported as a known
    # IOS-XE switch rather than an unidentifiable one.
    store.set_platform("192.0.2.14", Platform.IOS_XE)
    store.close()


# How far in the past the priming run is placed. Wide enough to be a real
# comparison window, short enough that "still incrementing" still means now.
BASELINE_AGE = timedelta(hours=18)


def _invoke(db_path: Path, out_dir: Path, flag: str) -> str:
    """One CLI run against the simulator; returns everything it printed."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = cli.main(
            [
                "run",
                INPUT_CSV,
                "--user",
                "netops",
                flag,
                "--db",
                str(db_path),
                "--output",
                str(out_dir),
            ]
        )
    if code != 0:
        sys.stdout.write(buffer.getvalue())
        raise SystemExit(f"iftriage exited {code}; artifacts not regenerated")
    return buffer.getvalue()


def _prime_baseline(db_path: Path, workdir: Path) -> None:
    """Store yesterday's sample the way a real operator would have: by running.

    Time is frozen, so the run is back-dated afterwards — both the run row and
    the samples it took, since the comparison window is measured from when each
    interface was actually read. Its ingest is then removed: this run exists
    only to leave counters behind, and counting it would inflate every
    recurrence number in the report.
    """
    global _CLIMBING
    _CLIMBING = False
    _invoke(db_path, workdir / "priming", "--no-baseline")

    moved = (FROZEN_NOW - BASELINE_AGE).isoformat(timespec="seconds")
    store = sqlite3.connect(db_path)
    store.execute("UPDATE runs SET started_at=?, finished_at=?", (moved, moved))
    for rowid, raw in store.execute(
        "SELECT rowid, stats_json FROM case_results WHERE stats_json IS NOT NULL"
    ).fetchall():
        stats = json.loads(raw)
        stats["collected_at"] = moved
        store.execute(
            "UPDATE case_results SET stats_json=? WHERE rowid=?",
            (json.dumps(stats), rowid),
        )
    store.execute("DELETE FROM ingest_rows WHERE ingest_id > 1")
    store.execute("DELETE FROM ingests WHERE id > 1")
    store.commit()
    store.close()


def _run(workdir: Path) -> str:
    """Prime yesterday's sample, then produce today's artifacts against it."""
    global _CLIMBING
    db_path = workdir / "history.db"
    _seed_history(db_path)

    os.environ["IFTRIAGE_PASS"] = "simulated"
    os.environ["IFTRIAGE_ENABLE"] = "simulated"
    _prime_baseline(db_path, workdir)

    _CLIMBING = True
    return _invoke(db_path, workdir / "reports", "--baseline")


def _collect_artifacts(workdir: Path, console: str) -> dict[str, str]:
    """Map each produced file onto its docs/examples name."""
    reports = workdir / "reports"
    stamp = FROZEN_NOW.strftime("%Y%m%d_%H%M%S")
    produced = {
        "console.txt": console,
        "audit.log": (reports / f"iftriage_audit_{stamp}.log").read_text(),
        "report.html": (reports / f"iftriage_report_{stamp}.html").read_text(),
        "report.txt": (reports / f"iftriage_report_{stamp}.txt").read_text(),
        "report.csv": (reports / f"iftriage_report_{stamp}.csv").read_text(),
    }
    # The run writes into a throwaway directory; the artifacts should read as
    # if it had used the default one, and must not carry a path that changes
    # on every run.
    return {
        name: text.replace(str(reports), "reports") for name, text in produced.items()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if docs/examples/ is out of date instead of rewriting it",
    )
    args = parser.parse_args()

    _install_simulator()
    workdir = Path(tempfile.mkdtemp(prefix="iftriage-examples-"))
    try:
        os.chdir(REPO_ROOT)
        produced = _collect_artifacts(workdir, _run(workdir))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    stale = [
        name
        for name, text in produced.items()
        if not (EXAMPLES / name).exists() or (EXAMPLES / name).read_text() != text
    ]
    if args.check:
        if stale:
            print("docs/examples is out of date: " + ", ".join(sorted(stale)))
            print("Run: python scripts/regen_examples.py")
            return 1
        print("docs/examples is up to date.")
        return 0

    for name, text in produced.items():
        (EXAMPLES / name).write_text(text)
    print(
        f"Wrote {len(produced)} artifact(s) to docs/examples/"
        + (f" ({len(stale)} changed)" if stale else " (no change)")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
