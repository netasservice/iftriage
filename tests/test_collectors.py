"""Collector-side safety logic that needs no device access."""

from iftriage.collectors import (
    _AaaBreaker,
    _collect_device,
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
