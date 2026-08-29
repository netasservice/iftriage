"""SQLite persistence: ingest archive, run results, IP->platform cache."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .models import CaseResult, InterfaceCase, Platform

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
    repoll_minutes REAL,
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS case_results (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    switch TEXT, mgmt_ip TEXT, interface TEXT, counter TEXT,
    platform TEXT, verdict TEXT, reason TEXT,
    stats_json TEXT, repoll_stats_json TEXT, raw_outputs_json TEXT,
    collection_error TEXT, parse_errors_json TEXT, members_json TEXT
);
CREATE TABLE IF NOT EXISTS platform_cache (
    mgmt_ip TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    detected_at TEXT NOT NULL
);
"""


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


def _members_json(result: CaseResult) -> str | None:
    if not (result.member_stats or result.member_errors):
        return None
    return json.dumps(
        {
            "stats": {
                name: _stats_dict(stats) for name, stats in result.member_stats.items()
            },
            "repoll_stats": {
                name: _stats_dict(stats)
                for name, stats in result.member_repoll_stats.items()
            },
            "errors": result.member_errors,
        }
    )


class History:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        # The schema is CREATE TABLE IF NOT EXISTS, so databases created before
        # a column existed keep their old shape; add what is missing in place.
        existing = {
            row[1] for row in self._conn.execute("PRAGMA table_info(case_results)")
        }
        if "members_json" not in existing:
            self._conn.execute("ALTER TABLE case_results ADD COLUMN members_json TEXT")
        self._conn.commit()

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

    def start_run(self, csv_file: str, repoll_minutes: float | None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO runs (started_at, csv_file, repoll_minutes) "
                "VALUES (?,?,?)",
                (_now(), csv_file, repoll_minutes),
            )
            self._conn.commit()
            run_id = cur.lastrowid
            assert run_id is not None  # always set after INSERT
            return run_id

    def save_results(self, run_id: int, results: list[CaseResult]) -> None:
        with self._lock:
            self._conn.executemany(
                "INSERT INTO case_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                        _stats_json(result.repoll_stats),
                        json.dumps(result.raw_outputs),
                        result.collection_error,
                        json.dumps(result.parse_errors),
                        _members_json(result),
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

    # -- platform cache ------------------------------------------------------

    def get_platform(self, mgmt_ip: str) -> Platform | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT platform FROM platform_cache WHERE mgmt_ip=?", (mgmt_ip,)
            )
            row = cur.fetchone()
        if row:
            try:
                return Platform(row[0])
            except ValueError:
                return None
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
