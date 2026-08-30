"""Configuration loading (config.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml


@dataclass
class Thresholds:
    """Escalation floors, expressed as a percentage of the frames.

    Errors and discards get their own floor because they are different
    phenomena. Cisco's port troubleshooting guidance (Doc ID 12027) puts the
    tolerance for FCS/CRC/alignment errors on a full-duplex link at
    essentially zero, while an out-discard is a frame that arrived intact and
    was dropped for buffer or policy reasons -- congestion, not media, and
    routine on a busy uplink. One number cannot serve both.
    """

    error_rate_percent: float = 0.001  # 10 per million frames
    discard_rate_percent: float = 1.0
    dom_rx_low_dbm: float = -14.0
    dom_rx_high_dbm: float = 2.0

    @property
    def error_rate(self) -> float:
        """The error floor as a fraction, which is what the rules compare."""
        return self.error_rate_percent / 100

    @property
    def discard_rate(self) -> float:
        return self.discard_rate_percent / 100


@dataclass
class ConnectionSettings:
    """Connection tuning. Concurrency is deliberately absent: the number of
    devices contacted at once is a command-line decision (`--workers N`,
    default 1), never a file the operator may not be looking at."""

    timeout_seconds: int = 30
    jitter_min: float = 0.5
    jitter_max: float = 2.0
    aaa_failure_abort: int = 2
    # Devices whose current CPU utilization exceeds this are skipped (their
    # cases become UNVERIFIED) rather than loaded with more work. An unreadable
    # CPU reading also skips: the guard fails closed.
    cpu_skip_threshold_percent: float = 80.0


@dataclass
class Limits:
    """Bounds on command output, so one noisy interface cannot inflate the
    history DB or make the HTML report unusable. `show logging | include ...`
    is the command that reaches these in practice."""

    max_output_bytes: int = 1_000_000
    evidence_max_lines: int = 300


@dataclass
class Config:
    thresholds: Thresholds = field(default_factory=Thresholds)
    connection: ConnectionSettings = field(default_factory=ConnectionSettings)
    limits: Limits = field(default_factory=Limits)
    repoll_default_minutes: float = 10.0
    platform_overrides: dict[str, str] = field(default_factory=dict)
    db_path: str = "iftriage_history.db"
    template: str = "report_en"
    output_dir: str = "reports"


_PERCENT_KEYS = ("error_rate_percent", "discard_rate_percent")


def _load_thresholds(thresholds: Thresholds, data: dict) -> None:
    """Apply the `thresholds` section, refusing anything unrecognized.

    Unlike the other sections, an unknown key here is an error rather than
    something to skip: a config file still carrying the pre-0.6 `rate_high` /
    `rate_warn` would otherwise be accepted in silence and the run would judge
    every interface by the built-in defaults instead.
    """
    accepted = tuple(field.name for field in fields(thresholds))
    for key, raw in data.items():
        if key not in accepted:
            raise ValueError(
                f"unknown key 'thresholds.{key}'; accepted keys are "
                f"{', '.join(accepted)}"
            )
        value = float(raw)
        if key in _PERCENT_KEYS and not 0 < value <= 100:
            raise ValueError(
                f"'thresholds.{key}' is a percentage of the frames: it must be "
                f"greater than 0 and at most 100 (got {value})"
            )
        setattr(thresholds, key, value)


def load_config(path: str | Path | None = None) -> Config:
    """Load config.yaml; missing file or missing keys fall back to defaults."""
    cfg = Config()
    if path is None:
        candidate = Path("config.yaml")
        path = candidate if candidate.exists() else None
    if path is None:
        return cfg

    data = yaml.safe_load(Path(path).read_text()) or {}

    _load_thresholds(cfg.thresholds, data.get("thresholds") or {})
    for key, value in (data.get("connection") or {}).items():
        if hasattr(cfg.connection, key):
            current = getattr(cfg.connection, key)
            setattr(cfg.connection, key, type(current)(value))
    for key, value in (data.get("limits") or {}).items():
        if hasattr(cfg.limits, key):
            setattr(cfg.limits, key, int(value))
    repoll = data.get("repoll") or {}
    if "default_minutes" in repoll:
        cfg.repoll_default_minutes = float(repoll["default_minutes"])
    cfg.platform_overrides = {
        str(k): str(v) for k, v in (data.get("platform_overrides") or {}).items()
    }
    history = data.get("history") or {}
    if "db_path" in history:
        cfg.db_path = str(history["db_path"])
    report = data.get("report") or {}
    if "template" in report:
        cfg.template = str(report["template"])
    if "output_dir" in report:
        cfg.output_dir = str(report["output_dir"])
    return cfg
