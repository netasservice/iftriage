"""Collector-side safety logic that needs no device access."""

from iftriage.collectors import _AaaBreaker, mark_portchannel_duplicates
from iftriage.models import CaseResult, InterfaceCase, NormalizedInterfaceStats


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
