"""Collector-side safety logic that needs no device access."""

import threading

import pytest

from iftriage.collectors import (
    RunAborted,
    _AaaBreaker,
    _bounded_evidence,
    _collect_device,
    _run_pass,
    mark_portchannel_duplicates,
)
from iftriage.config import Config
from iftriage.models import (
    CaseResult,
    Credentials,
    InterfaceCase,
    NormalizedInterfaceStats,
    VerdictCategory,
)
from iftriage.platforms.base import COMMAND_KEYS
from iftriage.rules import evaluate_case
from iftriage.session import AuditLog, EnableRequired


def test_aaa_breaker_trips_on_consecutive_failures_only():
    breaker = _AaaBreaker(limit=2)
    breaker.record_failure()
    assert not breaker.tripped.is_set()
    breaker.record_success()  # resets the streak
    breaker.record_failure()
    assert not breaker.tripped.is_set()
    breaker.record_failure()
    assert breaker.tripped.is_set()


def _case(switch, interface):
    return InterfaceCase(
        poll_time="t",
        switch=switch,
        mgmt_ip="10.0.0.1",
        interface=interface,
        description="",
        status="up",
        protocol="up",
        counter="Rcv-Err",
        prev_count=0,
        count=1,
        change=1,
        row_index=0,
    )


def test_po_member_listed_alongside_po_is_marked_duplicate():
    po = CaseResult(case=_case("sw-a", "Po214"))
    po.canonical_interface = "Port-channel214"
    po.stats = NormalizedInterfaceStats(
        port_channel_members={"Po214": ["Gi3/0/20", "Gi3/0/21"]}
    )
    member = CaseResult(case=_case("sw-a", "Gi3/0/20"))
    member.canonical_interface = "GigabitEthernet3/0/20"
    member.stats = NormalizedInterfaceStats()

    unrelated = CaseResult(case=_case("sw-b", "Gi3/0/20"))
    unrelated.canonical_interface = "GigabitEthernet3/0/20"

    mark_portchannel_duplicates([po, member, unrelated])
    assert member.duplicate_of == "Po214"
    assert po.duplicate_of is None
    assert unrelated.duplicate_of is None


def test_device_requiring_enable_without_a_secret_is_skipped_not_failed(
    tmp_path, monkeypatch
):
    """The enable secret is optional: a device that insists on it is skipped,
    its cases become UNVERIFIED, and neither the AAA breaker nor the rest of the
    run is affected."""

    class RefusingSession:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            raise EnableRequired(
                "10.0.0.1: device requires enable but no enable secret was provided"
            )

        def disconnect(self):
            raise AssertionError("connect() never succeeded; nothing to disconnect")

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", RefusingSession)

    config = Config()
    config.connection.jitter_min = 0.0
    config.connection.jitter_max = 0.0
    config.platform_overrides = {"10.0.0.1": "ios_xe"}
    breaker = _AaaBreaker(limit=2)
    result = CaseResult(case=_case("sw-a", "Gi1/0/1"))

    _collect_device(
        mgmt_ip="10.0.0.1",
        device_cases=[result],
        config=config,
        credentials=Credentials(username="ops", password="pw"),
        audit=AuditLog(tmp_path / "audit.log"),
        history=None,
        breaker=breaker,
        keys=COMMAND_KEYS,
    )

    assert result.collection_error is not None
    assert result.collection_error.startswith("device skipped:")
    assert "requires enable" in result.collection_error
    assert (
        not breaker.tripped.is_set()
    )  # a missing optional secret is not an AAA failure

    verdict = evaluate_case(
        case=result.case,
        stats=result.stats,
        repoll_stats=result.repoll_stats,
        repoll_minutes=result.repoll_minutes,
        thresholds=config.thresholds,
        collection_error=result.collection_error,
        parse_errors=result.parse_errors,
    )
    assert verdict.category is VerdictCategory.UNVERIFIED


def test_bounded_evidence_keeps_head_and_tail():
    raw = "\n".join(f"line {i}" for i in range(1000))
    bounded = _bounded_evidence(raw, max_lines=300)
    lines = bounded.splitlines()

    assert len(lines) == 301  # 300 kept plus the marker
    assert lines[0] == "line 0"  # head preserved: table headers survive
    assert lines[-1] == "line 999"  # tail preserved: newest syslog lines survive
    assert "700 lines elided" in lines[50]


def test_bounded_evidence_leaves_short_output_untouched():
    raw = "\n".join(f"line {i}" for i in range(10))
    assert _bounded_evidence(raw, max_lines=300) == raw


def test_evidence_is_bounded_but_parsing_sees_the_full_output(tmp_path, monkeypatch):
    """A noisy port must not inflate the history DB or the report, and bounding
    the stored evidence must not change the parsed result."""
    flaps = "\n".join(
        f"Aug 24 02:{i:02d}:41.520: %LINK-3-UPDOWN: Interface "
        "GigabitEthernet1/0/1, changed state to down"
        for i in range(400)
    )

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            pass

        def get(self, command):
            return flaps if "logging" in command else ""

        def disconnect(self):
            pass

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", FakeSession)

    config = Config()
    config.connection.jitter_min = 0.0
    config.connection.jitter_max = 0.0
    config.platform_overrides = {"10.0.0.1": "ios_xe"}
    result = CaseResult(case=_case("sw-a", "Gi1/0/1"))

    _collect_device(
        mgmt_ip="10.0.0.1",
        device_cases=[result],
        config=config,
        credentials=Credentials(username="ops", password="pw"),
        audit=AuditLog(tmp_path / "audit.log"),
        history=None,
        breaker=_AaaBreaker(limit=2),
        keys=COMMAND_KEYS,
    )

    stored = result.raw_outputs["logging"]
    assert len(stored.splitlines()) == config.limits.evidence_max_lines + 1
    assert "lines elided" in stored
    assert result.stats.flap_count == 400  # parsed from the full, unbounded text


class _ConcurrencyProbe:
    """Fake session that records how many are ever connected at the same time."""

    def __init__(self, ledger, barrier=None, fail_auth_for=None):
        self.ledger = ledger
        self.barrier = barrier
        self.fail_auth_for = fail_auth_for or set()

    def __call__(self, **kwargs):
        with self.ledger["lock"]:
            self.ledger["attempts"].append(kwargs["host"])
            # The sequential pre-flight device is always the first attempt; it
            # runs alone by design and must not wait on the fan-out barrier.
            is_preflight = len(self.ledger["attempts"]) == 1
        return _ProbeSession(self, kwargs["host"], is_preflight)


class _ProbeSession:
    def __init__(self, probe, host, is_preflight):
        self._probe = probe
        self._host = host
        self._is_preflight = is_preflight

    def connect(self):
        if self._host in self._probe.fail_auth_for:
            raise RuntimeError(f"{self._host}: Authentication failed.")
        ledger = self._probe.ledger
        with ledger["lock"]:
            ledger["live"] += 1
            ledger["peak"] = max(ledger["peak"], ledger["live"])
        if self._probe.barrier is not None and not self._is_preflight:
            # Times out (and fails the test) unless the pass really does run
            # this many devices at once.
            self._probe.barrier.wait(timeout=5)

    def get(self, command):
        return ""

    def disconnect(self):
        ledger = self._probe.ledger
        with ledger["lock"]:
            ledger["live"] = max(0, ledger["live"] - 1)


def _ledger():
    return {"live": 0, "peak": 0, "attempts": [], "lock": threading.Lock()}


def _four_device_pass(tmp_path):
    ips = [f"10.0.0.{n}" for n in range(1, 5)]
    config = Config()
    config.connection.jitter_min = 0.0
    config.connection.jitter_max = 0.0
    config.platform_overrides = {ip: "ios_xe" for ip in ips}
    results_by_ip = {ip: [CaseResult(case=_case(f"sw-{ip}", "Gi1/0/1"))] for ip in ips}
    return results_by_ip, config, AuditLog(tmp_path / "audit.log")


def test_default_pass_contacts_one_device_at_a_time(tmp_path, monkeypatch):
    """The default is serial: never more than one live session, so the AAA
    breaker observes every failure before the next attempt begins."""
    results_by_ip, config, audit = _four_device_pass(tmp_path)
    ledger = _ledger()
    monkeypatch.setattr(
        "iftriage.collectors.ReadOnlySession", _ConcurrencyProbe(ledger)
    )

    _run_pass(
        results_by_ip,
        config,
        Credentials(username="ops", password="pw"),
        audit,
        None,
        COMMAND_KEYS,
        workers=1,
    )

    assert ledger["peak"] == 1
    assert len(ledger["attempts"]) == 4


def test_explicit_workers_flag_really_fans_out(tmp_path, monkeypatch):
    """--workers N is a genuine opt-in, not a no-op: after the sequential
    pre-flight device, the remaining three run concurrently."""
    results_by_ip, config, audit = _four_device_pass(tmp_path)
    ledger = _ledger()
    monkeypatch.setattr(
        "iftriage.collectors.ReadOnlySession",
        _ConcurrencyProbe(ledger, barrier=threading.Barrier(3)),
    )

    _run_pass(
        results_by_ip,
        config,
        Credentials(username="ops", password="pw"),
        audit,
        None,
        COMMAND_KEYS,
        workers=3,
    )

    assert ledger["peak"] == 3
    assert len(ledger["attempts"]) == 4


def test_parallel_pass_aborts_on_the_first_auth_failure(tmp_path, monkeypatch):
    """Wrong credentials must cost exactly one failed login, not `workers` of
    them: the pre-flight device runs alone and aborts before the fan-out."""
    results_by_ip, config, audit = _four_device_pass(tmp_path)
    ledger = _ledger()
    monkeypatch.setattr(
        "iftriage.collectors.ReadOnlySession",
        _ConcurrencyProbe(ledger, fail_auth_for={"10.0.0.1"}),
    )

    with pytest.raises(RunAborted) as excinfo:
        _run_pass(
            results_by_ip,
            config,
            Credentials(username="ops", password="wrong"),
            audit,
            None,
            COMMAND_KEYS,
            workers=3,
        )

    assert "authentication failed on the first device" in str(excinfo.value)
    assert ledger["attempts"] == ["10.0.0.1"]  # the other three were never touched


def test_serial_pass_stops_at_the_aaa_breaker_limit(tmp_path, monkeypatch):
    """Serial runs need no pre-flight: the breaker itself caps the damage at
    `aaa_failure_abort` attempts."""
    results_by_ip, config, audit = _four_device_pass(tmp_path)
    ledger = _ledger()
    monkeypatch.setattr(
        "iftriage.collectors.ReadOnlySession",
        _ConcurrencyProbe(ledger, fail_auth_for={f"10.0.0.{n}" for n in range(1, 5)}),
    )

    with pytest.raises(RunAborted) as excinfo:
        _run_pass(
            results_by_ip,
            config,
            Credentials(username="ops", password="wrong"),
            audit,
            None,
            COMMAND_KEYS,
            workers=1,
        )

    assert "AAA circuit breaker" in str(excinfo.value)
    assert len(ledger["attempts"]) == config.connection.aaa_failure_abort == 2
