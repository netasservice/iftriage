"""Configuration loading (config.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Thresholds:
    rate_high: float = 1.0e-4
    rate_warn: float = 1.0e-5
    dom_rx_low_dbm: float = -14.0
    dom_rx_high_dbm: float = 2.0


@dataclass
class ConnectionSettings:
    workers: int = 10
    timeout_seconds: int = 30
    jitter_min: float = 0.5
    jitter_max: float = 2.0
    aaa_failure_abort: int = 2


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


def load_config(path: str | Path | None = None) -> Config:
    """Load config.yaml; missing file or missing keys fall back to defaults."""
    cfg = Config()
    if path is None:
        candidate = Path("config.yaml")
        path = candidate if candidate.exists() else None
    if path is None:
        return cfg

    data = yaml.safe_load(Path(path).read_text()) or {}

    for key, value in (data.get("thresholds") or {}).items():
        if hasattr(cfg.thresholds, key):
            setattr(cfg.thresholds, key, float(value))
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
