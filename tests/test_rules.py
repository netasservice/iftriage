"""Verdict engine tests — including the fail-closed PARSE_ERROR behavior."""

from iftriage.config import Thresholds
from iftriage.models import InterfaceCase, NormalizedInterfaceStats, VerdictCategory
from iftriage.rules import CounterClass, classify_counter, evaluate_case

T = Thresholds()


def make_case(counter="Rcv-Err", change=1000):
    return InterfaceCase(
        poll_time="2026-08-24T03:12:00",
        switch="sw-a",
        mgmt_ip="10.0.0.1",
        interface="Gi3/0/20",
        description="",
        status="up",
        protocol="up",
        counter=counter,
        prev_count=0,
        count=change,
        change=change,
        row_index=0,
    )


def make_stats(**kwargs):
    defaults = dict(
        link_status="up",
        protocol_status="up",
        duplex="full",
        input_packets=1_000_000,
        input_errors=0,
        crc_errors=0,
        late_collisions=0,
        discards_in=0,
        discards_out=0,
    )
    defaults.update(kwargs)
    return NormalizedInterfaceStats(**defaults)


def run(case, stats, repoll=None, minutes=None, error=None, parse_errors=()):
    return evaluate_case(
        case,
        stats,
        repoll,
        minutes,
        T,
        collection_error=error,
        parse_errors=parse_errors,
    )


# ---- classification --------------------------------------------------------


def test_counter_classification():
    assert classify_counter("Late-Col") is CounterClass.LATE_COLLISIONS
    assert classify_counter("Rcv-Err") is CounterClass.RECEIVE_ERRORS
    assert classify_counter("InDiscards") is CounterClass.IN_DISCARDS
    assert classify_counter("Rx") is CounterClass.TOTAL_TRAFFIC
    assert classify_counter("weird-thing") is CounterClass.GENERIC_ERRORS


# ---- fail-closed behavior (the most important tests in this file) ----------


def test_unreachable_device_is_unverified():
    verdict = run(make_case(), None, error="connection failed: timeout")
    assert verdict.category is VerdictCategory.UNVERIFIED


def test_missing_crc_is_parse_error_never_ignore():
    # crc=None must NEVER be treated as 0 -> false IGNORE.
    stats = make_stats(crc_errors=None)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.PARSE_ERROR
    assert "crc" in verdict.reason.lower()


def test_missing_duplex_on_late_col_is_parse_error():
    stats = make_stats(duplex=None, late_collisions=10)
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.PARSE_ERROR


def test_no_stats_at_all_is_parse_error():
    verdict = run(make_case(), None)
    assert verdict.category is VerdictCategory.PARSE_ERROR


# ---- late collisions -------------------------------------------------------


def test_late_col_on_full_duplex_is_config_issue():
    stats = make_stats(late_collisions=42, duplex="full")
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.CONFIG_ISSUE
    assert "duplex mismatch" in verdict.reason.lower()


def test_late_col_on_half_duplex_is_physical():
    stats = make_stats(late_collisions=42, duplex="half")
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA


def test_late_col_half_duplex_with_full_duplex_neighbor_is_config_issue():
    # Real fleet case: switch port fell back to half, IP phone reports full.
    stats = make_stats(
        late_collisions=38_445_916,
        duplex="half",
        neighbor_name="SEP001122AABB99",
        neighbor_duplex="full",
    )
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.CONFIG_ISSUE
    assert "mismatch confirmed" in verdict.reason.lower()


def test_late_col_half_duplex_with_logged_mismatch_is_config_issue():
    stats = make_stats(late_collisions=42, duplex="half", duplex_mismatch_logged=True)
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.CONFIG_ISSUE


def test_late_col_zero_on_device_is_ignore():
    stats = make_stats(late_collisions=0)
    verdict = run(make_case("Late-Col"), stats)
    assert verdict.category is VerdictCategory.IGNORE


# ---- receive errors --------------------------------------------------------


def test_high_crc_rate_is_physical_media():
    stats = make_stats(input_errors=3271, crc_errors=3271, input_packets=1_000_000)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA


def test_negligible_rate_is_ignore():
    stats = make_stats(input_errors=5, crc_errors=5, input_packets=1_000_000_000)
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.IGNORE


def test_flat_repoll_with_low_rate_is_ignore():
    stats = make_stats(input_errors=500, crc_errors=500, input_packets=100_000_000)
    repoll = make_stats(input_errors=500, crc_errors=500, input_packets=101_000_000)
    verdict = run(make_case("Rcv-Err"), stats, repoll, minutes=10)
    assert verdict.category is VerdictCategory.IGNORE
    assert "flat" in verdict.reason.lower()


def test_incrementing_repoll_at_meaningful_rate_is_physical():
    stats = make_stats(input_errors=1000, crc_errors=1000, input_packets=100_000_000)
    repoll = make_stats(input_errors=1600, crc_errors=1600, input_packets=101_000_000)
    # 600 errors / 1M packets in the window = 6e-4 >= rate_high
    verdict = run(make_case("Rcv-Err"), stats, repoll, minutes=10)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "incrementing" in verdict.reason.lower()


def test_dom_out_of_range_is_physical_media():
    stats = make_stats(
        input_errors=100,
        crc_errors=100,
        input_packets=1_000_000_000,
        dom_rx_power_dbm=-16.2,
    )
    verdict = run(make_case("Rcv-Err"), stats)
    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "dom" in verdict.reason.lower()


# ---- discards --------------------------------------------------------------


def test_indiscards_at_rate_is_capacity_not_physical():
    stats = make_stats(discards_in=388, input_packets=1_000_000)
    verdict = run(make_case("InDiscards"), stats)
    assert verdict.category is VerdictCategory.CAPACITY
    assert "not a physical error" in verdict.reason.lower()


def test_negligible_discards_is_ignore():
    stats = make_stats(discards_in=3, input_packets=1_000_000_000)
    verdict = run(make_case("InDiscards"), stats)
    assert verdict.category is VerdictCategory.IGNORE


# ---- total traffic ---------------------------------------------------------


def test_rx_counter_is_ignore():
    verdict = run(make_case("Rx"), make_stats())
    assert verdict.category is VerdictCategory.IGNORE
    assert "not an error" in verdict.reason.lower()


# ---- port-channel member triage --------------------------------------------


def po_case(counter="Rcv-Err"):
    case = make_case(counter=counter)
    case.interface = "Po214"
    return case


def run_po(
    case,
    stats,
    member_stats,
    member_errors=None,
    member_repoll=None,
    repoll=None,
    minutes=None,
):
    return evaluate_case(
        case,
        stats,
        repoll,
        minutes,
        T,
        member_stats=member_stats,
        member_repoll_stats=member_repoll or {},
        member_errors=member_errors or {},
    )


def test_po_fault_is_isolated_to_the_bad_member():
    """Bundle counters are sums across members: the bad member's rate is
    diluted below the noise threshold on the bundle, but not on the member."""
    bundle = make_stats(input_errors=1000, crc_errors=1000, input_packets=200_000_000)
    bad = make_stats(input_errors=1000, crc_errors=1000, input_packets=1_000_000)
    good = make_stats(input_packets=100_000_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet3/0/23": bad, "GigabitEthernet3/0/24": good},
    )

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "fault isolated to member GigabitEthernet3/0/23" in verdict.reason
    assert verdict.member_findings["GigabitEthernet3/0/24"].startswith("IGNORE")


def test_po_member_with_dom_out_of_range_is_physical_media():
    bundle = make_stats(input_errors=100, crc_errors=100, input_packets=200_000_000)
    bad_optic = make_stats(
        input_errors=100,
        crc_errors=100,
        input_packets=1_000_000,
        dom_rx_power_dbm=-18.0,
    )

    verdict = run_po(po_case(), bundle, {"Ethernet1/1": bad_optic})

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "Ethernet1/1" in verdict.reason
    assert "DOM receive power -18.0 dBm" in verdict.reason


def test_po_member_repoll_delta_confirms_live_errors():
    bundle = make_stats(input_errors=100, crc_errors=100, input_packets=200_000_000)
    first = make_stats(input_errors=100, crc_errors=100, input_packets=1_000_000)
    second = make_stats(input_errors=200, crc_errors=200, input_packets=1_050_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet1/0/1": first},
        member_repoll={"GigabitEthernet1/0/1": second},
        minutes=10,
    )

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "still incrementing" in verdict.reason


def test_po_missing_member_fails_closed_to_parse_error():
    bundle = make_stats()
    good = make_stats(input_packets=100_000_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet1/0/1": good},
        member_errors={"GigabitEthernet1/0/2": "member collection failed: timed out"},
    )

    assert verdict.category is VerdictCategory.PARSE_ERROR
    assert "GigabitEthernet1/0/2" in verdict.reason
    assert verdict.member_findings["GigabitEthernet1/0/2"].startswith("not evaluated")


def test_po_bundle_errors_with_clean_members_degrade_gracefully():
    bundle = make_stats(input_errors=5000, crc_errors=5000, input_packets=1_000_000)
    clean = make_stats(input_packets=100_000_000)

    verdict = run_po(
        po_case(),
        bundle,
        {"GigabitEthernet1/0/1": clean, "GigabitEthernet1/0/2": clean},
    )

    assert verdict.category is VerdictCategory.PHYSICAL_MEDIA
    assert "no current member" in verdict.reason
    assert "since-removed member" in verdict.reason


def test_po_all_clean_is_ignore_with_the_member_breakdown():
    bundle = make_stats(input_packets=100_000_000)
    clean = make_stats(input_packets=50_000_000)

    verdict = run_po(po_case(), bundle, {"GigabitEthernet1/0/1": clean})

    assert verdict.category is VerdictCategory.IGNORE
    assert verdict.member_findings["GigabitEthernet1/0/1"].startswith("IGNORE")


def test_po_with_traffic_counter_stays_ignore_even_with_member_data():
    verdict = run_po(
        po_case(counter="Rx"), make_stats(), {"GigabitEthernet1/0/1": make_stats()}
    )

    assert verdict.category is VerdictCategory.IGNORE
    assert "total traffic counter" in verdict.reason


def test_po_without_member_data_matches_the_single_interface_verdict():
    """Regression guard: an empty bundle / unparsed summary keeps today's path."""
    bundle = make_stats(input_errors=1000, crc_errors=1000, input_packets=1_000_000)

    plain = run(po_case(), bundle)
    with_empty_members = run_po(po_case(), bundle, {})

    assert with_empty_members.category is plain.category
    assert with_empty_members.reason == plain.reason
