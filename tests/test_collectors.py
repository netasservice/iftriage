"""Collector-side safety logic that needs no device access."""

import threading

import pytest

from iftriage.collectors import (
    RunAborted,
    _AaaBreaker,
    _bounded_evidence,
    _collect_device,
    _resolve_portchannel_group,
    _run_pass,
    abort_if_nothing_collected,
    collect_members,
    collected_results,
    mark_portchannel_duplicates,
)
from iftriage.config import Config
from iftriage.models import (
    CaseResult,
    Credentials,
    InterfaceCase,
    NormalizedInterfaceStats,
    Platform,
    VerdictCategory,
)
from iftriage.platforms import get_profile
from iftriage.platforms.base import COMMAND_KEYS
from iftriage.rules import evaluate_case
from iftriage.session import AuditLog, EnableRequired

# Healthy answer to the IOS-XE cpu guard command; fakes must provide one or the
# fail-closed guard would skip every device.
HEALTHY_CPU = (
    "CPU utilization for five seconds: 5%/0%; one minute: 5%; five minutes: 5%"
)


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


def test_collected_results_filters_excluded_failed_and_uncollected():
    collected = CaseResult(case=_case("sw-a", "Gi1/0/1"))
    collected.stats = NormalizedInterfaceStats()
    failed = CaseResult(case=_case("sw-a", "Gi1/0/2"))
    failed.collection_error = "connection failed: timed out"
    uncollected = CaseResult(case=_case("sw-a", "Gi1/0/3"))  # stats never arrived
    excluded = CaseResult(case=_case("sw-a", "Gi1/0/4"))
    excluded.case.excluded = True
    excluded.stats = NormalizedInterfaceStats()

    eligible = collected_results([collected, failed, uncollected, excluded])

    assert eligible == [collected]


def test_all_failed_first_pass_aborts_with_the_first_error():
    first = CaseResult(case=_case("sw-a", "Gi1/0/1"))
    first.collection_error = "connection failed: 10.0.0.1: Authentication failed."
    second = CaseResult(case=_case("sw-b", "Gi1/0/2"))
    second.collection_error = "connection failed: timed out"

    with pytest.raises(RunAborted) as excinfo:
        abort_if_nothing_collected([first, second])

    message = str(excinfo.value)
    assert "no device could be collected" in message
    assert "Authentication failed." in message


def test_abort_gate_is_silent_when_any_device_was_collected():
    collected = CaseResult(case=_case("sw-a", "Gi1/0/1"))
    collected.stats = NormalizedInterfaceStats()
    failed = CaseResult(case=_case("sw-b", "Gi1/0/2"))
    failed.collection_error = "connection failed: timed out"

    abort_if_nothing_collected([collected, failed])  # must not raise


def test_abort_gate_is_silent_when_all_cases_are_data_quality_excluded():
    excluded = CaseResult(case=_case("sw-a", "Gi1/0/1"))
    excluded.case.excluded = True

    abort_if_nothing_collected([excluded])  # a DQ-only run still gets its report


def test_deliberate_device_skips_do_not_abort_the_run():
    """A "device skipped:" outcome means the device was reached and purposely
    left alone (missing enable secret today); that belongs in the report."""
    skipped = CaseResult(case=_case("sw-a", "Gi1/0/1"))
    skipped.collection_error = (
        "device skipped: device requires enable but no enable secret was provided"
    )

    abort_if_nothing_collected([skipped])  # must not raise


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
        baseline_stats=result.baseline_stats,
        baseline_minutes=result.baseline_minutes,
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
            if "processes cpu" in command:
                return HEALTHY_CPU
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
        return HEALTHY_CPU if "processes cpu" in command else ""

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


# ---- CPU guard -------------------------------------------------------------

BUSY_CPU = (
    "CPU utilization for five seconds: 92%/45%; one minute: 90%; five minutes: 88%"
)


def _cpu_gated_device(tmp_path, monkeypatch, cpu_response, keys=COMMAND_KEYS):
    """Run _collect_device against a fake whose cpu command answers
    `cpu_response`; returns (result, commands sent, breaker)."""
    commands: list[str] = []

    class CpuSession:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            pass

        def get(self, command):
            commands.append(command)
            if "processes cpu" in command:
                if isinstance(cpu_response, Exception):
                    raise cpu_response
                return cpu_response
            return ""

        def disconnect(self):
            pass

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", CpuSession)

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
        keys=keys,
    )
    return result, commands, breaker


def test_high_cpu_device_is_skipped_with_the_reading_in_evidence(tmp_path, monkeypatch):
    result, commands, breaker = _cpu_gated_device(tmp_path, monkeypatch, BUSY_CPU)

    assert result.collection_error == (
        "device skipped: CPU utilization 92% above 80% threshold"
    )
    assert len(commands) == 1  # the cpu reading itself; no interface command ran
    assert result.raw_outputs["cpu"] == BUSY_CPU
    assert not breaker.tripped.is_set()
    assert breaker.consecutive_failures == 0  # a busy device is not an AAA failure


def test_low_cpu_device_is_collected_normally(tmp_path, monkeypatch):
    result, commands, _breaker = _cpu_gated_device(tmp_path, monkeypatch, HEALTHY_CPU)

    assert result.collection_error is None
    assert result.stats is not None
    assert len(commands) > 1  # the interface command set ran after the guard


def test_unreadable_cpu_output_skips_the_device_fail_closed(tmp_path, monkeypatch):
    result, commands, _breaker = _cpu_gated_device(
        tmp_path, monkeypatch, "% Invalid input detected"
    )

    assert result.collection_error is not None
    assert "could not determine CPU utilization" in result.collection_error
    assert len(commands) == 1


def test_failing_cpu_command_skips_the_device_fail_closed(tmp_path, monkeypatch):
    result, _commands, breaker = _cpu_gated_device(
        tmp_path, monkeypatch, RuntimeError("read timeout")
    )

    assert result.collection_error is not None
    assert "could not determine CPU utilization" in result.collection_error
    assert breaker.consecutive_failures == 0


# ---- port-channel summary gate ---------------------------------------------


def _quiet_config():
    config = Config()
    config.connection.jitter_min = 0.0
    config.connection.jitter_max = 0.0
    return config


HEALTHY_CPU_EOS = "%Cpu(s):  3.1 us,  1.2 sy,  0.0 ni, 94.2 id"

EOS_PLAIN_PORT = """Ethernet4/15 is up, line protocol is up (connected)
  Full-duplex, 10Gb/s, auto negotiation: off
"""

EOS_MEMBER_PORT = """Ethernet4/15 is up, line protocol is up (connected)
  Member of Port-Channel195
  Full-duplex, 10Gb/s, auto negotiation: off
"""

EOS_DENSE = """   Port-Channel       Protocol       Ports
   Po195(U)           LACP(a)        Et4/15(PG+) Et4/16(PG+)
"""


def _gate_device(tmp_path, monkeypatch, platform, interface, interface_output=""):
    """Run a first pass against a fake device; returns (result, commands)."""
    commands: list[str] = []

    class GateSession:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            pass

        def get(self, command):
            commands.append(command)
            if "processes cpu" in command or "processes top" in command:
                return HEALTHY_CPU if platform == "ios_xe" else HEALTHY_CPU_EOS
            if "port-channel dense" in command or "etherchannel summary" in command:
                return EOS_DENSE
            if command.startswith(("show interfaces ", "show interface ")) and (
                command.count(" ") == 2
            ):
                return interface_output
            return ""

        def disconnect(self):
            pass

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", GateSession)
    config = _quiet_config()
    config.platform_overrides = {"10.0.0.1": platform}
    result = CaseResult(case=_case("sw-a", interface))

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
    return result, commands


def test_portchannel_summary_is_skipped_for_an_unrelated_interface(
    tmp_path, monkeypatch
):
    result, commands = _gate_device(
        tmp_path, monkeypatch, "eos", "Et4/15", EOS_PLAIN_PORT
    )

    assert "show port-channel dense" not in commands
    assert result.stats is not None
    assert result.stats.port_channel_members is None


def test_portchannel_summary_runs_when_the_interface_is_a_member(tmp_path, monkeypatch):
    result, commands = _gate_device(
        tmp_path, monkeypatch, "eos", "Et4/15", EOS_MEMBER_PORT
    )

    assert commands.count("show port-channel dense") == 1
    assert result.stats is not None
    assert result.stats.member_of_portchannel == "Port-Channel195"
    assert result.stats.port_channel_members == {"Po195": ["Et4/15", "Et4/16"]}
    assert "portchannel" in result.raw_outputs


def test_portchannel_summary_runs_when_the_case_is_a_bundle(tmp_path, monkeypatch):
    _result, commands = _gate_device(tmp_path, monkeypatch, "eos", "Po195")

    assert commands.count("show port-channel dense") == 1


def test_ios_xe_always_sends_the_etherchannel_summary(tmp_path, monkeypatch):
    """IOS-XE `show interfaces` never names the channel-group, so the summary
    is the only way to learn membership and cannot be gated away."""
    result, commands = _gate_device(
        tmp_path, monkeypatch, "ios_xe", "Gi1/0/1", "GigabitEthernet1/0/1 is up\n"
    )

    assert commands.count("show etherchannel summary") == 1
    assert result.stats is not None
    assert result.stats.member_of_portchannel is None


# ---- port-channel member pass ----------------------------------------------


def _po_result(platform=Platform.IOS_XE, members=("Gi3/0/23", "Gi3/0/24")):
    result = CaseResult(case=_case("sw-a", "Po214"))
    result.platform = platform
    result.canonical_interface = "Port-channel214"
    result.stats = NormalizedInterfaceStats(
        port_channel_members={"Po214": list(members)}
    )
    return result


def test_resolve_group_validates_and_records_rejects():
    profile = get_profile(Platform.IOS_XE)
    result = _po_result(members=("Gi3/0/23", "Gi3/0/24", "bogus; reload"))

    parent, members = _resolve_portchannel_group(result, profile)

    assert parent is None  # the case IS the bundle
    assert members == ["GigabitEthernet3/0/23", "GigabitEthernet3/0/24"]
    assert "rejected" in result.member_errors["bogus; reload"]


def test_resolve_group_finds_the_parent_of_a_member_case():
    profile = get_profile(Platform.IOS_XE)
    result = CaseResult(case=_case("sw-a", "Gi3/0/23"))
    result.canonical_interface = "GigabitEthernet3/0/23"
    result.stats = NormalizedInterfaceStats(
        port_channel_members={"Po214": ["Gi3/0/23", "Gi3/0/24", "Gi3/0/25"]}
    )

    parent, members = _resolve_portchannel_group(result, profile)

    assert parent == "Po214"
    # Siblings only: the case itself was already sampled on pass 1.
    assert members == ["GigabitEthernet3/0/24", "GigabitEthernet3/0/25"]


def test_resolve_group_is_empty_for_unrelated_interfaces():
    profile = get_profile(Platform.IOS_XE)
    result = CaseResult(case=_case("sw-a", "Gi1/0/1"))
    result.canonical_interface = "GigabitEthernet1/0/1"
    result.stats = NormalizedInterfaceStats(
        port_channel_members={"Po214": ["Gi3/0/23"]}
    )

    assert _resolve_portchannel_group(result, profile) == (None, [])


def _member_pass_session(monkeypatch, connect_error=None):
    commands: list[str] = []

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            if connect_error is not None:
                raise connect_error

        def get(self, command):
            commands.append(command)
            return HEALTHY_CPU if "processes cpu" in command else ""

        def disconnect(self):
            pass

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", FakeSession)
    return commands


def test_collect_members_samples_each_validated_member(tmp_path, monkeypatch):
    commands = _member_pass_session(monkeypatch)
    result = _po_result()

    covered = collect_members(
        [result],
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    assert covered == 1
    assert set(result.member_stats) == {
        "GigabitEthernet3/0/23",
        "GigabitEthernet3/0/24",
    }
    assert "show interfaces GigabitEthernet3/0/23" in commands
    assert "show interfaces GigabitEthernet3/0/23 counters errors" in commands
    assert "show interfaces GigabitEthernet3/0/23 transceiver detail" in commands
    # Device-level commands stay out of the member pass.
    assert "show version" not in commands
    assert "show etherchannel summary" not in commands
    # Evidence is keyed per member.
    assert "GigabitEthernet3/0/23:interface" in result.raw_outputs


def test_members_inherit_the_devices_uptime(tmp_path, monkeypatch):
    # The member pass skips `show version` on purpose; members must inherit
    # the device-level fields from the parent case, or their interval
    # provenance degrades to host-side timestamps while the bundle keeps the
    # device clock.
    _member_pass_session(monkeypatch)
    result = _po_result()
    result.stats.uptime_minutes = 123_456.0
    result.stats.model = "C9410R"
    result.stats.os_version = "17.06.05"

    collect_members(
        [result],
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    for member_stats in result.member_stats.values():
        assert member_stats.uptime_minutes == 123_456.0
        assert member_stats.model == "C9410R"
        assert member_stats.os_version == "17.06.05"


def test_member_case_samples_its_siblings_not_itself(tmp_path, monkeypatch):
    commands = _member_pass_session(monkeypatch)
    result = CaseResult(case=_case("sw-a", "Gi3/0/23"))
    result.platform = Platform.IOS_XE
    result.canonical_interface = "GigabitEthernet3/0/23"
    result.stats = NormalizedInterfaceStats(
        port_channel_members={"Po214": ["Gi3/0/23", "Gi3/0/24", "Gi3/0/25"]}
    )

    covered = collect_members(
        [result],
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    assert covered == 1
    assert result.parent_portchannel == "Po214"
    assert set(result.member_stats) == {
        "GigabitEthernet3/0/24",
        "GigabitEthernet3/0/25",
    }
    # Pass 1 already sampled the reported port; the member pass must not redo it.
    assert "show interfaces GigabitEthernet3/0/23" not in commands


def test_member_case_with_only_rejected_siblings_is_still_marked_a_member(
    tmp_path, monkeypatch
):
    """Resolving records rejected member names even when nothing is left to
    sample. rules.py must still see this as a member case, or it would judge
    the port as if it were the bundle."""
    commands = _member_pass_session(monkeypatch)
    result = CaseResult(case=_case("sw-a", "Gi3/0/23"))
    result.platform = Platform.IOS_XE
    result.canonical_interface = "GigabitEthernet3/0/23"
    result.stats = NormalizedInterfaceStats(
        port_channel_members={"Po214": ["Gi3/0/23", "bogus; reload"]}
    )

    covered = collect_members(
        [result],
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    assert covered == 0
    assert commands == []  # nothing worth a second connection
    assert result.parent_portchannel == "Po214"
    assert "rejected" in result.member_errors["bogus; reload"]

    verdict = evaluate_case(
        case=result.case,
        stats=result.stats,
        baseline_stats=None,
        baseline_minutes=None,
        thresholds=Config().thresholds,
        member_errors=result.member_errors,
        parent_portchannel=result.parent_portchannel,
    )
    assert "port-channel Gi3/0/23" not in verdict.reason


def test_sibling_cases_of_one_bundle_sample_each_member_once(tmp_path, monkeypatch):
    commands = _member_pass_session(monkeypatch)
    members = ["Gi3/0/23", "Gi3/0/24", "Gi3/0/25"]
    results = []
    for name in ("Gi3/0/23", "Gi3/0/24"):
        result = CaseResult(case=_case("sw-a", name))
        result.platform = Platform.IOS_XE
        result.canonical_interface = f"GigabitEthernet{name[2:]}"
        result.stats = NormalizedInterfaceStats(
            port_channel_members={"Po214": list(members)}
        )
        results.append(result)

    collect_members(
        results,
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    # Gi3/0/25 is a sibling of both cases but is only polled once.
    assert commands.count("show interfaces GigabitEthernet3/0/25") == 1
    for result in results:
        assert "GigabitEthernet3/0/25" in result.member_stats


def test_collect_members_skips_cases_without_member_data(tmp_path, monkeypatch):
    commands = _member_pass_session(monkeypatch)
    plain = CaseResult(case=_case("sw-a", "Gi1/0/1"))
    plain.platform = Platform.IOS_XE
    plain.canonical_interface = "GigabitEthernet1/0/1"
    plain.stats = NormalizedInterfaceStats()

    covered = collect_members(
        [plain],
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    assert covered == 0
    assert commands == []  # no second connection at all


def test_member_pass_connection_failure_fails_all_members_closed(tmp_path, monkeypatch):
    _member_pass_session(monkeypatch, connect_error=RuntimeError("timed out"))
    result = _po_result()

    collect_members(
        [result],
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    assert result.member_stats == {}
    for member in ("GigabitEthernet3/0/23", "GigabitEthernet3/0/24"):
        assert result.member_errors[member].startswith("member collection failed:")
    assert result.collection_error is None  # the pass-1 sample is untouched


def test_member_pass_cpu_skip_fails_members_closed(tmp_path, monkeypatch):
    commands: list[str] = []

    class BusySession:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            pass

        def get(self, command):
            commands.append(command)
            return BUSY_CPU

        def disconnect(self):
            pass

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", BusySession)
    result = _po_result()

    collect_members(
        [result],
        _quiet_config(),
        Credentials(username="ops", password="pw"),
        AuditLog(tmp_path / "audit.log"),
        None,
    )

    assert result.member_stats == {}
    assert len(commands) == 1  # only the CPU reading was sent
    assert "CPU utilization" in result.member_errors["GigabitEthernet3/0/23"]
