"""Per-platform collection orchestration.

One device at a time by default: the AAA circuit breaker can only do what its
name promises when authentication attempts are sequential, and the operator
should be able to read a command and know how many devices it touches. Wider
fan-out is an explicit `--workers N` opt-in and pays for a pre-flight probe.

Also here: per-device timeouts, jitter between connection attempts, and
per-device try/except so one failed device never kills the run.
"""

from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

from .config import Config
from .history import History
from .models import (
    CaseResult,
    Credentials,
    InterfaceCase,
    NormalizedInterfaceStats,
    Platform,
)
from .normalize import InterfaceNameError
from .platforms import get_profile
from .platforms.base import COMMAND_KEYS, DEVICE_LEVEL_KEYS, REPOLL_KEYS
from .session import AuditLog, EnableRequired, ReadOnlySession, SafetyViolation


class RunAborted(Exception):
    """The whole run must stop (safety violation or AAA circuit breaker)."""


_STATS_FIELDS = set(NormalizedInterfaceStats.__dataclass_fields__)


def _is_auth_error(exc: Exception) -> bool:
    try:
        from netmiko.exceptions import NetmikoAuthenticationException
    except ImportError:  # pragma: no cover
        return "auth" in str(exc).lower()
    return isinstance(exc, NetmikoAuthenticationException) or (
        "auth" in str(exc).lower()
    )


def resolve_platform(
    mgmt_ip: str,
    hostname: str,
    config: Config,
    history: History | None,
    credentials: Credentials | None,
) -> Platform | None:
    """Override -> cache -> live autodetection (read-only)."""
    override = config.platform_overrides.get(mgmt_ip) or config.platform_overrides.get(
        hostname
    )
    if override:
        return Platform(override)
    if history is not None:
        cached = history.get_platform(mgmt_ip)
        if cached:
            return cached
    if credentials is None:
        return None
    detected = _autodetect(mgmt_ip, credentials, config.connection.timeout_seconds)
    if detected and history is not None:
        history.set_platform(mgmt_ip, detected)
    return detected


_DETECT_MAP = {
    "cisco_xe": Platform.IOS_XE,
    "cisco_ios": Platform.IOS_XE,
    "cisco_nxos": Platform.NXOS,
    "arista_eos": Platform.EOS,
}


def _autodetect(
    mgmt_ip: str, credentials: Credentials, timeout: int
) -> Platform | None:
    """Read-only platform autodetection via Netmiko SSHDetect."""
    from netmiko import SSHDetect

    guesser = SSHDetect(
        device_type="autodetect",
        host=mgmt_ip,
        username=credentials.username,
        password=credentials.password,
        secret=credentials.enable_secret or "",
        conn_timeout=timeout,
    )
    try:
        best = guesser.autodetect()
    finally:
        try:
            guesser.connection.disconnect()
        except Exception:
            pass
    return _DETECT_MAP.get(best or "")


class _AaaBreaker:
    """Abort the run after N consecutive authentication failures."""

    def __init__(self, limit: int):
        self._limit = limit
        self._consecutive = 0
        self._lock = threading.Lock()
        self.tripped = threading.Event()

    def record_failure(self) -> None:
        with self._lock:
            self._consecutive += 1
            if self._consecutive >= self._limit:
                self.tripped.set()

    def record_success(self) -> None:
        with self._lock:
            self._consecutive = 0

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._consecutive


# Lines kept from the head of an oversized output, so a truncated table still
# shows its header row.
_EVIDENCE_HEAD_LINES = 50


def _bounded_evidence(raw: str, max_lines: int) -> str:
    """Bound the copy of a command output that is persisted and reported.

    Head and tail are both kept: the head carries table headers (show
    interfaces, show port-channel summary), the tail carries the newest syslog
    lines. Parsing still runs on the full text, so bounding evidence never
    changes a verdict.
    """
    lines = raw.splitlines()
    if len(lines) <= max_lines or max_lines <= _EVIDENCE_HEAD_LINES:
        return raw
    tail_lines = max_lines - _EVIDENCE_HEAD_LINES
    elided = len(lines) - max_lines
    marker = (
        f"[iftriage: {elided} lines elided, kept first "
        f"{_EVIDENCE_HEAD_LINES} and last {tail_lines}]"
    )
    return "\n".join(lines[:_EVIDENCE_HEAD_LINES] + [marker] + lines[-tail_lines:])


def _merge_stats(parsed_by_key: dict[str, dict]) -> NormalizedInterfaceStats:
    merged: dict = {}
    for key in COMMAND_KEYS:  # later commands (counters table) win
        for field, value in parsed_by_key.get(key, {}).items():
            if field in _STATS_FIELDS and value is not None:
                merged[field] = value
    stats = NormalizedInterfaceStats(**merged)
    stats.collected_at = datetime.now(UTC)
    return stats


def _collect_device(
    mgmt_ip: str,
    device_cases: list[CaseResult],
    config: Config,
    credentials: Credentials,
    audit: AuditLog,
    history: History | None,
    breaker: _AaaBreaker,
    keys: tuple[str, ...],
) -> None:
    """Collect `keys` commands for every case on one device. Mutates results."""
    if breaker.tripped.is_set():
        for result in device_cases:
            result.collection_error = (
                result.collection_error
                or "run aborted by AAA circuit breaker before this device"
            )
        return

    time.sleep(
        random.uniform(config.connection.jitter_min, config.connection.jitter_max)
    )

    hostname = device_cases[0].case.switch
    try:
        platform = resolve_platform(mgmt_ip, hostname, config, history, credentials)
    except Exception as exc:
        if _is_auth_error(exc):
            breaker.record_failure()
        for result in device_cases:
            result.collection_error = f"platform detection failed: {exc}"
        return
    if platform is None:
        for result in device_cases:
            result.collection_error = "platform autodetection failed (unknown OS)"
        return

    profile = get_profile(platform)
    targets: list[CaseResult] = []
    for result in device_cases:
        result.platform = platform
        try:
            result.canonical_interface = profile.canonical_interface(
                result.case.interface
            )
            targets.append(result)
        except InterfaceNameError as exc:
            result.parse_errors.append(str(exc))

    if not targets:
        return

    canonicals = [
        result.canonical_interface for result in targets if result.canonical_interface
    ]
    allowed = profile.allowed_commands(canonicals)
    session = ReadOnlySession(
        host=mgmt_ip,
        device_type=profile.netmiko_device_type,
        credentials=credentials,
        allowed_commands=allowed,
        audit=audit,
        read_timeout=config.connection.timeout_seconds,
        max_output_bytes=config.limits.max_output_bytes,
    )
    try:
        session.connect()
    except SafetyViolation:
        raise
    except EnableRequired as exc:
        # Not a connection or credential failure: the run is simply missing an
        # optional secret this device insists on. Skip it, keep the run going.
        for result in targets:
            result.collection_error = f"device skipped: {exc}"
        return
    except Exception as exc:
        if _is_auth_error(exc):
            breaker.record_failure()
        for result in targets:
            result.collection_error = f"connection failed: {exc}"
        return
    breaker.record_success()

    device_level_raw: dict[str, str] = {}
    try:
        for result in targets:
            canonical = result.canonical_interface
            if canonical is None:  # unreachable: targets require it
                continue
            parsed_by_key: dict[str, dict] = {}
            commands = profile.render_commands(canonical)
            for key in keys:
                if key not in commands:
                    continue
                command = commands[key]
                try:
                    if key in DEVICE_LEVEL_KEYS and command in device_level_raw:
                        raw = device_level_raw[command]
                    else:
                        raw = session.get(command)
                        if key in DEVICE_LEVEL_KEYS:
                            device_level_raw[command] = raw
                    result.raw_outputs[key] = _bounded_evidence(
                        raw, config.limits.evidence_max_lines
                    )
                except SafetyViolation:
                    raise
                except Exception as exc:
                    result.parse_errors.append(f"{key}: command failed: {exc}")
                    continue
                try:
                    parsed_by_key[key] = profile.parse(key, raw, canonical)
                except Exception as exc:
                    result.parse_errors.append(f"{key}: parse failed: {exc}")
            stats = _merge_stats(parsed_by_key)
            if keys == REPOLL_KEYS:
                result.repoll_stats = stats
            else:
                result.stats = stats
    finally:
        session.disconnect()


def _run_pass(
    results_by_ip: dict[str, list[CaseResult]],
    config: Config,
    credentials: Credentials,
    audit: AuditLog,
    history: History | None,
    keys: tuple[str, ...],
    workers: int,
) -> None:
    breaker = _AaaBreaker(config.connection.aaa_failure_abort)
    safety_failure: list[Exception] = []
    remaining = dict(results_by_ip)

    # A parallel pass puts `workers` authentication attempts in flight before
    # the breaker can observe the first failure, so wrong credentials would cost
    # `workers` failed logins against centralized AAA. Probing one device
    # sequentially first caps that at one. Serial runs need no probe: there the
    # breaker already sees every failure before the next attempt starts.
    if workers > 1 and remaining:
        probe_ip = next(iter(remaining))
        try:
            _collect_device(
                probe_ip,
                remaining.pop(probe_ip),
                config,
                credentials,
                audit,
                history,
                breaker,
                keys,
            )
        except SafetyViolation as exc:
            raise RunAborted(f"SAFETY VIOLATION — run aborted: {exc}") from exc
        if breaker.consecutive_failures:
            raise RunAborted(
                f"authentication failed on the first device ({probe_ip}); "
                f"aborting before contacting {len(remaining)} more in parallel. "
                "Verify the credentials and re-run."
            )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _collect_device,
                ip,
                cases,
                config,
                credentials,
                audit,
                history,
                breaker,
                keys,
            ): ip
            for ip, cases in remaining.items()
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                future.result()
            except SafetyViolation as exc:
                safety_failure.append(exc)
                breaker.tripped.set()  # stop remaining devices
            except Exception as exc:  # defensive: never kill the run silently
                for result in remaining[ip]:
                    result.collection_error = (
                        result.collection_error or f"unexpected error: {exc}"
                    )
    if safety_failure:
        raise RunAborted(
            f"SAFETY VIOLATION — run aborted: {safety_failure[0]}"
        ) from safety_failure[0]
    if breaker.tripped.is_set():
        raise RunAborted(
            "AAA circuit breaker tripped: "
            f"{config.connection.aaa_failure_abort} consecutive authentication "
            "failures. Aborting to protect the account from lockout."
        )


def collect(
    cases: list[InterfaceCase],
    config: Config,
    credentials: Credentials,
    audit: AuditLog,
    history: History | None,
    workers: int = 1,
) -> list[CaseResult]:
    """First (full) collection pass. Returns one CaseResult per case."""
    results = [CaseResult(case=case) for case in cases]
    live = [result for result in results if not result.case.excluded]
    by_ip: dict[str, list[CaseResult]] = {}
    for result in live:
        by_ip.setdefault(result.case.mgmt_ip, []).append(result)
    try:
        _run_pass(by_ip, config, credentials, audit, history, COMMAND_KEYS, workers)
    except RunAborted:
        raise
    return results


def repoll_eligible(results: list[CaseResult]) -> list[CaseResult]:
    """Results whose interface was actually collected in the first pass."""
    return [
        result
        for result in results
        if not result.case.excluded
        and result.collection_error is None
        and result.stats is not None
    ]


def abort_if_nothing_collected(results: list[CaseResult]) -> None:
    """Fail fast when the first pass collected nothing at all.

    Wrong credentials on a run too small to trip the AAA breaker (a single
    device) would otherwise sit out the full repoll interval for a report
    that is already decided. Deliberate skips ("device skipped: ...") mean
    the device was reached and intentionally left alone — that outcome
    belongs in the report, so it never triggers the abort.
    """
    live = [result for result in results if not result.case.excluded]
    if not live or repoll_eligible(results):
        return
    if any(
        result.collection_error is not None
        and result.collection_error.startswith("device skipped:")
        for result in live
    ):
        return
    devices = {result.case.mgmt_ip for result in live}
    first_error = next(
        (result.collection_error for result in live if result.collection_error),
        None,
    ) or next(
        (result.parse_errors[0] for result in live if result.parse_errors),
        "no error recorded",
    )
    raise RunAborted(
        f"no device could be collected: all {len(devices)} device(s) failed "
        f"(first error: {first_error}). Verify credentials/reachability and re-run."
    )


def repoll(
    results: list[CaseResult],
    config: Config,
    credentials: Credentials,
    audit: AuditLog,
    history: History | None,
    minutes: float,
    workers: int = 1,
) -> None:
    """Second sample of the same interface counters (caller waits in between)."""
    eligible = repoll_eligible(results)
    by_ip: dict[str, list[CaseResult]] = {}
    for result in eligible:
        by_ip.setdefault(result.case.mgmt_ip, []).append(result)
        result.repoll_minutes = minutes
    _run_pass(by_ip, config, credentials, audit, history, REPOLL_KEYS, workers)


def mark_portchannel_duplicates(results: list[CaseResult]) -> None:
    """If the CSV lists a Po and one of its members on the same device,
    mark the member as a duplicate — same physical issue counted twice."""
    from .normalize import interface_matches_token

    by_switch: dict[str, list[CaseResult]] = {}
    for result in results:
        by_switch.setdefault(result.case.switch, []).append(result)

    for group in by_switch.values():
        for po_result in group:
            stats, canonical = po_result.stats, po_result.canonical_interface
            if stats is None or not stats.port_channel_members or canonical is None:
                continue
            if not canonical.lower().startswith(("po", "port-channel")):
                continue
            members: list[str] = []
            for name, member_list in stats.port_channel_members.items():
                if interface_matches_token(name, canonical):
                    members = member_list
                    break
            for other in group:
                other_canonical = other.canonical_interface
                if other is po_result or other_canonical is None:
                    continue
                for member in members:
                    if interface_matches_token(member, other_canonical):
                        other.duplicate_of = po_result.case.interface
