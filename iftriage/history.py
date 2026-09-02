"""SQLite persistence: ingest archive, run results, IP->platform cache."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    CaseResult,
    Confidence,
    DataQualityFlag,
    DataQualityKind,
    InterfaceCase,
    NormalizedInterfaceStats,
    Platform,
    Signal,
    SignalKind,
    Verdict,
    VerdictCategory,
    VerdictMetrics,
)

# Marks a run whose case_results rows carry every field `--from-history` needs
# to rebuild a CaseResult. Runs written before these columns existed have NULL
# here and are never replayed: a missing parent_portchannel would silently
# change a member case's verdict. Bump when a new column becomes load-bearing.
#
# 2 (0.6.0): the second stored sample changed sides. A schema-1 row's
# repoll_stats_json held the NEWER sample; a schema-2 row's baseline_stats_json
# holds the OLDER one. Replaying a schema-1 row under the new direction would
# look faithful while answering a different question, so those runs are barred
# from replay — `latest_sample` deliberately still accepts them as baselines,
# for the reasons in its docstring.
#
# 3 (0.7.0): the v2 engine. Schema-2 rows lack the per-bucket error counters
# (runts, Rcv-Err, buffer group, media type, counter epoch) the v2 verdicts
# and report are built from; replaying them would render a v2 report from v1
# evidence. `latest_sample` still accepts them as baselines: their missing
# fields deserialize as None, and a None among a rule's inputs caps the
# verdict's confidence instead of faking a value.
REPLAY_SCHEMA = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ingests (
    id INTEGER PRIMARY KEY,
    received_at TEXT NOT NULL,
    source_file TEXT NOT NULL,
    raw_csv TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_rows (
    ingest_id INTEGER NOT NULL REFERENCES ingests(id),
    row_index INTEGER NOT NULL,
    poll_time TEXT, switch TEXT, mgmt_ip TEXT, interface TEXT,
    description TEXT, status TEXT, protocol TEXT, counter TEXT,
    prev_count INTEGER, count INTEGER, change INTEGER
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    csv_file TEXT NOT NULL,
    summary_json TEXT,
    replay_schema INTEGER
);
CREATE TABLE IF NOT EXISTS case_results (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    switch TEXT, mgmt_ip TEXT, interface TEXT, counter TEXT,
    platform TEXT, verdict TEXT, reason TEXT,
    stats_json TEXT, raw_outputs_json TEXT,
    collection_error TEXT, parse_errors_json TEXT, members_json TEXT,
    canonical_interface TEXT, parent_portchannel TEXT,
    baseline_stats_json TEXT, baseline_minutes REAL, baseline_taken_at TEXT,
    baseline_run_id INTEGER, baseline_note TEXT, verdict_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_case_results_target
    ON case_results (switch, interface, counter);
CREATE TABLE IF NOT EXISTS platform_cache (
    mgmt_ip TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    detected_at TEXT NOT NULL
);
"""

# Columns added to tables that already shipped. The schema above is CREATE TABLE
# IF NOT EXISTS, so an existing database keeps its old shape; every column added
# after its table's first release is listed here and added in place.
_ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "runs": {"replay_schema": "INTEGER"},
    "case_results": {
        "members_json": "TEXT",
        "canonical_interface": "TEXT",
        "parent_portchannel": "TEXT",
        "baseline_stats_json": "TEXT",
        "baseline_minutes": "REAL",
        "baseline_taken_at": "TEXT",
        "baseline_run_id": "INTEGER",
        "baseline_note": "TEXT",
        "verdict_json": "TEXT",
    },
}

# Written by 0.5.0 and earlier, never read or written again: runs.repoll_minutes
# and case_results.repoll_stats_json / repoll_skip_reason / repoll_minutes. A
# database that already has them keeps them and their data, because dropping a
# column rewrites the table for no gain. Never SELECT repoll_stats_json: it holds
# the NEWER of two samples, and that is the one direction this schema inverted.

_CASE_RESULT_COLUMNS = (
    "run_id",
    "switch",
    "mgmt_ip",
    "interface",
    "counter",
    "platform",
    "verdict",
    "reason",
    "stats_json",
    "raw_outputs_json",
    "collection_error",
    "parse_errors_json",
    "members_json",
    "canonical_interface",
    "parent_portchannel",
    "baseline_stats_json",
    "baseline_minutes",
    "baseline_taken_at",
    "baseline_run_id",
    "baseline_note",
    "verdict_json",
)

_STATS_FIELDS = {stats_field.name for stats_field in fields(NormalizedInterfaceStats)}


class HistoryError(RuntimeError):
    """The history database could not be read (missing, locked, corrupt)."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _stats_json(stats) -> str | None:
    if stats is None:
        return None
    return json.dumps(_stats_dict(stats))


def _stats_dict(stats) -> dict:
    data = asdict(stats)
    if data.get("collected_at"):
        data["collected_at"] = data["collected_at"].isoformat()
    return data


def _stats_from_dict(data: dict) -> NormalizedInterfaceStats:
    """Rebuild stats from a stored row, keeping only fields the model declares.

    A field the stored row does not carry stays None, which the rules engine
    already treats fail-closed — an old row can never yield a clean verdict from
    a value it never held.
    """
    kept = {key: value for key, value in data.items() if key in _STATS_FIELDS}
    collected = kept.get("collected_at")
    if isinstance(collected, str):
        try:
            kept["collected_at"] = datetime.fromisoformat(collected)
        except ValueError:
            kept["collected_at"] = None
    return NormalizedInterfaceStats(**kept)


def _stats_from_json(text: str | None) -> NormalizedInterfaceStats | None:
    if not text:
        return None
    return _stats_from_dict(json.loads(text))


def _verdict_json(verdict: Verdict | None) -> str | None:
    """Serialize the full structured verdict (signals, data-quality flags,
    metrics). StrEnums serialize as their plain string values."""
    if verdict is None:
        return None
    return json.dumps(asdict(verdict))


def _kept_fields(cls: type, data: dict) -> dict:
    """Keep only the keys a dataclass declares, like `_stats_from_dict`: a
    field an old row does not carry stays at its default, and a field a newer
    writer added is dropped rather than crashing the read."""
    names = {stored_field.name for stored_field in fields(cls)}
    return {key: value for key, value in data.items() if key in names}


def _signal_from_dict(data: dict) -> Signal | None:
    try:
        kind = SignalKind(data["kind"])
        weight = Confidence(data["weight"])
    except (KeyError, ValueError):
        return None  # a kind this reader does not know: drop, don't crash
    supports = data.get("supports")
    return Signal(
        kind=kind,
        weight=weight,
        values=data.get("values") or {},
        supports=VerdictCategory(supports) if supports else None,
        contradicts=bool(data.get("contradicts", False)),
    )


def _verdict_from_json(text: str | None) -> Verdict | None:
    if not text:
        return None
    data = json.loads(text)
    try:
        category = VerdictCategory(data["category"])
    except (KeyError, ValueError):
        return None
    confidence = data.get("confidence")
    signals = [
        signal
        for signal in (_signal_from_dict(item) for item in data.get("signals", []))
        if signal is not None
    ]
    flags: list[DataQualityFlag] = []
    for item in data.get("data_quality", []):
        try:
            flag_kind = DataQualityKind(item["kind"])
        except (KeyError, ValueError):
            continue
        flags.append(DataQualityFlag(kind=flag_kind, values=item.get("values") or {}))
    metrics_data = data.get("metrics")
    what_would_change = data.get("what_would_change")
    return Verdict(
        category=category,
        reason=data.get("reason", ""),
        details=list(data.get("details", [])),
        member_findings=dict(data.get("member_findings", {})),
        confidence=Confidence(confidence) if confidence else None,
        signals=signals,
        data_quality=flags,
        metrics=VerdictMetrics(**_kept_fields(VerdictMetrics, metrics_data))
        if metrics_data
        else None,
        what_would_change=_signal_from_dict(what_would_change)
        if what_would_change
        else None,
    )


def _members_json(result: CaseResult) -> str | None:
    if not (result.member_stats or result.member_errors):
        return None
    return json.dumps(
        {
            "stats": {
                name: _stats_dict(stats) for name, stats in result.member_stats.items()
            },
            "baseline_stats": {
                name: _stats_dict(stats)
                for name, stats in result.member_baseline_stats.items()
            },
            "errors": result.member_errors,
        }
    )


def _members_from_json(
    text: str | None,
) -> tuple[
    dict[str, NormalizedInterfaceStats],
    dict[str, NormalizedInterfaceStats],
    dict[str, str],
]:
    if not text:
        return {}, {}, {}
    data = json.loads(text)
    return (
        {
            name: _stats_from_dict(raw)
            for name, raw in (data.get("stats") or {}).items()
        },
        {
            name: _stats_from_dict(raw)
            for name, raw in (data.get("baseline_stats") or {}).items()
        },
        dict(data.get("errors") or {}),
    )


@dataclass(frozen=True)
class StoredSample:
    """One earlier sample of an interface, offered as a comparison baseline.

    Deliberately smaller than StoredCase: a baseline needs the counters and
    when they were read, nothing else. Everything a verdict adds on top comes
    from the fresh sample.
    """

    run_id: int
    taken_at: datetime
    stats: NormalizedInterfaceStats
    member_stats: dict[str, NormalizedInterfaceStats] = field(default_factory=dict)


@dataclass
class StoredCase:
    """One case_results row rebuilt into the shapes the pipeline uses.

    Everything a CaseResult needs except the InterfaceCase itself, which the
    caller re-derives from the CSV.
    """

    run_id: int
    run_started_at: str
    platform: Platform | None = None
    canonical_interface: str | None = None
    stats: NormalizedInterfaceStats | None = None
    baseline_stats: NormalizedInterfaceStats | None = None
    baseline_minutes: float | None = None
    baseline_taken_at: datetime | None = None
    baseline_run_id: int | None = None
    raw_outputs: dict[str, str] = field(default_factory=dict)
    collection_error: str | None = None
    parse_errors: list[str] = field(default_factory=list)
    parent_portchannel: str | None = None
    baseline_note: str | None = None
    member_stats: dict[str, NormalizedInterfaceStats] = field(default_factory=dict)
    member_baseline_stats: dict[str, NormalizedInterfaceStats] = field(
        default_factory=dict
    )
    member_errors: dict[str, str] = field(default_factory=dict)


class History:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._add_missing_columns()
        self._conn.commit()

    def _add_missing_columns(self) -> None:
        for table, columns in _ADDED_COLUMNS.items():
            existing = {
                row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            for column, column_type in columns.items():
                if column not in existing:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {column_type}"
                    )

    def close(self) -> None:
        self._conn.close()

    # -- ingest archive ------------------------------------------------------

    def archive_ingest(
        self, source_file: str, raw_csv: str, cases: list[InterfaceCase]
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO ingests (received_at, source_file, raw_csv) "
                "VALUES (?,?,?)",
                (_now(), source_file, raw_csv),
            )
            ingest_id = cur.lastrowid
            self._conn.executemany(
                "INSERT INTO ingest_rows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        ingest_id,
                        case.row_index,
                        case.poll_time,
                        case.switch,
                        case.mgmt_ip,
                        case.interface,
                        case.description,
                        case.status,
                        case.protocol,
                        case.counter,
                        case.prev_count,
                        case.count,
                        case.change,
                    )
                    for case in cases
                ],
            )
            self._conn.commit()
            assert ingest_id is not None  # always set after INSERT
            return ingest_id

    # -- runs ----------------------------------------------------------------

    def start_run(self, csv_file: str) -> tuple[int, str]:
        """Open a run row; returns its id and the instant it started.

        The caller needs that instant: it is the cutoff that makes a run
        structurally incapable of being its own baseline.
        """
        started_at = _now()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO runs (started_at, csv_file, replay_schema) VALUES (?,?,?)",
                (started_at, csv_file, REPLAY_SCHEMA),
            )
            self._conn.commit()
            run_id = cur.lastrowid
            assert run_id is not None  # always set after INSERT
            return run_id, started_at

    def save_results(self, run_id: int, results: list[CaseResult]) -> None:
        columns = ", ".join(_CASE_RESULT_COLUMNS)
        placeholders = ", ".join("?" * len(_CASE_RESULT_COLUMNS))
        with self._lock:
            self._conn.executemany(
                f"INSERT INTO case_results ({columns}) VALUES ({placeholders})",
                [
                    (
                        run_id,
                        result.case.switch,
                        result.case.mgmt_ip,
                        result.case.interface,
                        result.case.counter,
                        result.platform.value if result.platform else None,
                        result.verdict.category.value if result.verdict else None,
                        result.verdict.reason if result.verdict else None,
                        _stats_json(result.stats),
                        json.dumps(result.raw_outputs),
                        result.collection_error,
                        json.dumps(result.parse_errors),
                        _members_json(result),
                        result.canonical_interface,
                        result.parent_portchannel,
                        _stats_json(result.baseline_stats),
                        result.baseline_minutes,
                        result.baseline_taken_at.isoformat()
                        if result.baseline_taken_at
                        else None,
                        result.baseline_run_id,
                        result.baseline_note,
                        _verdict_json(result.verdict),
                    )
                    for result in results
                ],
            )
            self._conn.commit()

    def finish_run(self, run_id: int, summary: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET finished_at=?, summary_json=? WHERE id=?",
                (_now(), json.dumps(summary), run_id),
            )
            self._conn.commit()

    def recurrence_count(self, switch: str, interface: str) -> int:
        """Number of PRIOR ingests in which this switch+interface appeared."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(DISTINCT ingest_id) FROM ingest_rows "
                "WHERE switch=? AND interface=?",
                (switch, interface),
            )
            return int(cur.fetchone()[0])

    def verdict_history(
        self, switch: str, interface: str, counter: str, limit: int = 10
    ) -> list[str]:
        """Verdict categories stored for this case in prior runs, newest
        first. Used to spot chronic benign top-20 residents; an empty list
        means the case was never judged before."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT verdict FROM case_results "
                "WHERE switch=? AND interface=? AND counter=? "
                "AND verdict IS NOT NULL "
                "ORDER BY run_id DESC, rowid DESC LIMIT ?",
                (switch, interface, counter, limit),
            )
            return [str(row[0]) for row in cur.fetchall()]

    def latest_case_result(
        self, switch: str, interface: str, counter: str
    ) -> StoredCase | None:
        """Newest replayable collection stored for one CSV case, if any.

        Rows written by runs that predate REPLAY_SCHEMA are ignored: they are
        missing fields the verdict depends on, and reusing them would look like
        a faithful replay while quietly answering a different question.
        """
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT r.id, r.started_at, c.platform, c.canonical_interface, "
                    "c.stats_json, c.baseline_stats_json, c.baseline_minutes, "
                    "c.raw_outputs_json, c.collection_error, c.parse_errors_json, "
                    "c.parent_portchannel, c.baseline_note, c.members_json, "
                    "c.baseline_taken_at, c.baseline_run_id "
                    "FROM case_results AS c JOIN runs AS r ON r.id = c.run_id "
                    "WHERE c.switch=? AND c.interface=? AND c.counter=? "
                    "AND r.replay_schema >= ? "
                    "ORDER BY c.run_id DESC, c.rowid DESC LIMIT 1",
                    (switch, interface, counter, REPLAY_SCHEMA),
                )
                row = cur.fetchone()
        except sqlite3.Error as exc:
            raise HistoryError(f"could not read {self.path}: {exc}") from exc
        if row is None:
            return None
        try:
            return self._stored_case(row)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise HistoryError(
                f"stored collection for {switch} {interface} ({counter}) is "
                f"unreadable: {exc}"
            ) from exc

    def latest_sample(
        self,
        switch: str,
        interface: str,
        canonical: str | None,
        counter: str,
        *,
        before: str,
        not_before: str,
    ) -> StoredSample | None:
        """Newest stored sample of one interface inside a time window.

        The key is the interface, never the CSV: today's work list and
        yesterday's may share only a few rows, and each row finds its own
        earlier sample independently. `interface` and `canonical` are both
        matched because two CSVs can spell the same port differently
        (`Gi1/0/1` / `GigabitEthernet1/0/1`).

        `before` and `not_before` are the window bounds, both pushed into SQL:
        picking the newest row and rejecting it afterwards would let a run from
        minutes ago mask yesterday's, which is the one that can answer. `before`
        also makes a run structurally incapable of being its own baseline.

        Deliberately NOT filtered on replay_schema, unlike latest_case_result:
        a baseline consumes one column, stats_json, whose meaning has never
        changed. A full replay needs the whole row and must refuse partial
        history; a baseline needs the earlier sample and nothing else, and a
        field an old row does not carry simply yields no delta (rules.py fails
        closed on that). This is what lets the first run after an upgrade
        already compare against yesterday.
        """
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT r.id, r.started_at, c.stats_json, c.members_json "
                    "FROM case_results AS c JOIN runs AS r ON r.id = c.run_id "
                    "WHERE c.switch=? AND c.counter=? "
                    "AND (c.interface=? OR c.canonical_interface=?) "
                    "AND c.stats_json IS NOT NULL "
                    "AND r.started_at < ? AND r.started_at >= ? "
                    "ORDER BY c.run_id DESC, c.rowid DESC LIMIT 1",
                    (
                        switch,
                        counter,
                        interface,
                        canonical or interface,
                        before,
                        not_before,
                    ),
                )
                row = cur.fetchone()
        except sqlite3.Error as exc:
            raise HistoryError(f"could not read {self.path}: {exc}") from exc
        if row is None:
            return None
        try:
            stats = _stats_from_json(row[2])
            member_stats, _, _ = _members_from_json(row[3])
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise HistoryError(
                f"stored sample for {switch} {interface} ({counter}) is "
                f"unreadable: {exc}"
            ) from exc
        if stats is None:
            return None
        # The sample's own timestamp beats the run's: it is when this
        # interface was actually read, which is what the window measures.
        taken_at = stats.collected_at or datetime.fromisoformat(str(row[1]))
        return StoredSample(
            run_id=int(row[0]),
            taken_at=taken_at,
            stats=stats,
            member_stats=member_stats,
        )

    @staticmethod
    def _stored_case(row) -> StoredCase:
        member_stats, member_baseline_stats, member_errors = _members_from_json(row[12])
        taken_at = row[13]
        return StoredCase(
            run_id=int(row[0]),
            run_started_at=str(row[1]),
            platform=_platform_or_none(row[2]),
            canonical_interface=row[3],
            stats=_stats_from_json(row[4]),
            baseline_stats=_stats_from_json(row[5]),
            baseline_minutes=row[6],
            baseline_taken_at=datetime.fromisoformat(taken_at) if taken_at else None,
            baseline_run_id=row[14],
            raw_outputs=json.loads(row[7]) if row[7] else {},
            collection_error=row[8],
            parse_errors=json.loads(row[9]) if row[9] else [],
            parent_portchannel=row[10],
            baseline_note=row[11],
            member_stats=member_stats,
            member_baseline_stats=member_baseline_stats,
            member_errors=member_errors,
        )

    # -- platform cache ------------------------------------------------------

    def get_platform(self, mgmt_ip: str) -> Platform | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT platform FROM platform_cache WHERE mgmt_ip=?", (mgmt_ip,)
            )
            row = cur.fetchone()
        if row:
            return _platform_or_none(row[0])
        return None

    def set_platform(self, mgmt_ip: str, platform: Platform) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO platform_cache (mgmt_ip, platform, detected_at) "
                "VALUES (?,?,?) ON CONFLICT(mgmt_ip) DO UPDATE SET "
                "platform=excluded.platform, detected_at=excluded.detected_at",
                (mgmt_ip, platform.value, _now()),
            )
            self._conn.commit()


def _platform_or_none(value) -> Platform | None:
    if not value:
        return None
    try:
        return Platform(value)
    except ValueError:
        return None
