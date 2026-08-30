"""CLI dry-run: prints targets and exact commands, connects to nothing."""

import shutil
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from conftest import FIXTURES

from iftriage.cli import (
    CredentialError,
    _build_parser,
    _resolve_credentials,
    main,
)
from iftriage.config import load_config


def _never_prompt(label):
    raise AssertionError(f"unexpected prompt: {label!r}")


def test_dry_run_prints_commands_and_touches_no_network(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no config.yaml, no history db in cwd
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    rc = main(["run", str(csv), "--dry-run"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "DRY RUN" in out
    assert "No devices were contacted." in out
    # Exact commands for a case, rendered per candidate platform:
    assert "show interfaces GigabitEthernet3/0/20 counters errors" in out
    assert "show cdp neighbors GigabitEthernet3/0/20 detail" in out
    # Excluded data-quality rows are visibly excluded:
    assert "EXCLUDED" in out


def test_malformed_config_yields_error_message_not_traceback(tmp_path, capsys):
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)
    bad_config = tmp_path / "config.yaml"
    bad_config.write_text("thresholds: [unclosed\n  - :::")

    rc = main(["run", str(csv), "--dry-run", "--config", str(bad_config)])

    assert rc == 2
    assert "could not load configuration" in capsys.readouterr().err


def _clear_credential_env(monkeypatch):
    for name in ("IFTRIAGE_USER", "IFTRIAGE_PASS", "IFTRIAGE_ENABLE"):
        monkeypatch.delenv(name, raising=False)


def test_user_flag_wins_over_environment(monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("IFTRIAGE_USER", "from-env")
    monkeypatch.setenv("IFTRIAGE_PASS", "pw")
    monkeypatch.setenv("IFTRIAGE_ENABLE", "en")
    monkeypatch.setattr("builtins.input", _never_prompt)

    credentials = _resolve_credentials("from-flag")

    assert credentials.username == "from-flag"
    assert credentials.password == "pw"
    assert credentials.enable_secret == "en"


def test_environment_username_used_when_flag_absent(monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("IFTRIAGE_USER", "from-env")
    monkeypatch.setenv("IFTRIAGE_PASS", "pw")
    monkeypatch.setenv("IFTRIAGE_ENABLE", "en")
    monkeypatch.setattr("builtins.input", _never_prompt)

    assert _resolve_credentials(None).username == "from-env"


def test_secrets_are_prompted_when_environment_is_empty(monkeypatch):
    _clear_credential_env(monkeypatch)
    asked: list[str] = []

    def fake_getpass(label):
        asked.append(label)
        return "typed-secret"

    monkeypatch.setattr("iftriage.cli.getpass.getpass", fake_getpass)
    monkeypatch.setattr("builtins.input", _never_prompt)

    credentials = _resolve_credentials("jperez")

    assert credentials.password == "typed-secret"
    assert credentials.enable_secret == "typed-secret"
    assert "Password for jperez: " in asked[0]
    assert "Enable secret" in asked[1]


def test_username_is_prompted_when_neither_flag_nor_environment(monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("IFTRIAGE_PASS", "pw")
    monkeypatch.setenv("IFTRIAGE_ENABLE", "en")
    monkeypatch.setattr("builtins.input", lambda label: "typed-user")

    assert _resolve_credentials(None).username == "typed-user"


def test_blank_enable_answer_means_no_enable_secret(monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("IFTRIAGE_PASS", "pw")
    monkeypatch.setattr("iftriage.cli.getpass.getpass", lambda label: "")
    monkeypatch.setattr("builtins.input", _never_prompt)

    assert _resolve_credentials("jperez").enable_secret is None


def test_empty_enable_environment_variable_suppresses_the_prompt(monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("IFTRIAGE_PASS", "pw")
    monkeypatch.setenv("IFTRIAGE_ENABLE", "")
    monkeypatch.setattr(
        "iftriage.cli.getpass.getpass", lambda label: pytest.fail("prompted")
    )
    monkeypatch.setattr("builtins.input", _never_prompt)

    assert _resolve_credentials("jperez").enable_secret is None


def test_blank_username_answer_is_an_error_not_a_connection_attempt(monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda label: "")

    with pytest.raises(CredentialError):
        _resolve_credentials(None)


def test_resolved_credentials_never_expose_secrets(monkeypatch):
    _clear_credential_env(monkeypatch)
    monkeypatch.setenv("IFTRIAGE_PASS", "pw-secret")
    monkeypatch.setenv("IFTRIAGE_ENABLE", "enable-secret")
    monkeypatch.setattr("builtins.input", _never_prompt)

    text = repr(_resolve_credentials("jperez"))

    assert "pw-secret" not in text
    assert "enable-secret" not in text


def test_non_interactive_run_without_environment_errors_cleanly(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    _clear_credential_env(monkeypatch)

    def closed_stdin(label):
        raise EOFError

    monkeypatch.setattr("builtins.input", closed_stdin)
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    rc = main(["run", str(csv)])

    assert rc == 2
    assert "interactive terminal" in capsys.readouterr().err
    # No history database was created: the run aborted before opening one.
    assert not list(tmp_path.glob("*.db"))


def test_dry_run_never_asks_for_credentials(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _clear_credential_env(monkeypatch)
    monkeypatch.setattr(
        "iftriage.cli._resolve_credentials",
        lambda username_arg: pytest.fail("dry run must not need credentials"),
    )
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    assert main(["run", str(csv), "--dry-run", "--user", "jperez"]) == 0


@pytest.mark.parametrize("value", ["0", "-1"])
def test_non_positive_workers_is_a_usage_error(tmp_path, capsys, value):
    """`--workers 0` used to be silently discarded by a falsy check and
    `--workers -1` would have reached ThreadPoolExecutor."""
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    rc = main(["run", str(csv), "--workers", value])

    assert rc == 2
    assert "--workers must be at least 1" in capsys.readouterr().err


_CSV_HEADER = (
    "_time,switch,mgmt_ip,interface,description,status,protocol,"
    "counter,prev_count,count,change\n"
)


def _live_run_setup(tmp_path, monkeypatch, ips):
    """CSV + config + env credentials for an end-to-end main() run that will
    only ever touch a monkeypatched fake session."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IFTRIAGE_USER", "ops")
    monkeypatch.setenv("IFTRIAGE_PASS", "pw")
    monkeypatch.setenv("IFTRIAGE_ENABLE", "")
    monkeypatch.setattr("builtins.input", _never_prompt)

    rows = [
        f"2026-08-24T03:{index:02d}:00,sw-{index},{ip},Gi1/0/{index + 1},"
        f"desc,up,up,Rcv-Err,0,{100 + index * 7},{100 + index * 7}"
        for index, ip in enumerate(ips)
    ]
    csv = tmp_path / "top20.csv"
    csv.write_text(_CSV_HEADER + "\n".join(rows) + "\n")

    overrides = "\n".join(f'  "{ip}": ios_xe' for ip in ips)
    (tmp_path / "config.yaml").write_text(
        "connection:\n  jitter_min: 0\n  jitter_max: 0\n"
        f"platform_overrides:\n{overrides}\n"
    )
    return csv


def _fake_sessions(monkeypatch, fail_auth=(), fail_timeout=()):
    """Replace ReadOnlySession with a fake; returns the list of connect attempts."""
    attempts = []

    class FakeSession:
        def __init__(self, **kwargs):
            self.host = kwargs["host"]

        def connect(self):
            attempts.append(self.host)
            if self.host in fail_auth:
                raise RuntimeError(f"{self.host}: Authentication failed.")
            if self.host in fail_timeout:
                raise RuntimeError(f"{self.host}: connection timed out")

        def get(self, command):
            if "processes cpu" in command:  # keep the fail-closed CPU guard happy
                return (
                    "CPU utilization for five seconds: 5%/0%; "
                    "one minute: 5%; five minutes: 5%"
                )
            return ""

        def disconnect(self):
            pass

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", FakeSession)
    return attempts


def _record_sleeps(monkeypatch):
    """Record every wait the run path takes.

    Nothing in a run may block any more: the delta comes from a previous run,
    not from sitting on a timer. The live-run config sets both jitter bounds to
    zero, so the collectors' anti-hammering sleep(0) is the only permitted call
    and anything above zero is a regression.
    """
    calls = []
    monkeypatch.setattr(
        "iftriage.collectors.time.sleep",
        lambda seconds: calls.append(seconds) if seconds > 0 else None,
    )
    return calls


def test_single_device_bad_credentials_aborts_without_waiting(
    tmp_path, capsys, monkeypatch
):
    """One auth failure is below the AAA breaker limit (2), but with nothing
    collected the report is already decided: abort instead of reconnecting."""
    csv = _live_run_setup(tmp_path, monkeypatch, ["10.0.0.1"])
    attempts = _fake_sessions(monkeypatch, fail_auth={"10.0.0.1"})
    sleeps = _record_sleeps(monkeypatch)

    rc = main(["run", str(csv), "--output", str(tmp_path / "out")])

    err = capsys.readouterr().err
    assert rc == 3
    assert "RUN ABORTED" in err
    assert "no device could be collected" in err
    assert sleeps == []
    assert attempts == ["10.0.0.1"]
    assert not list((tmp_path / "out").glob("iftriage_report_*"))


def test_all_devices_failing_aborts_without_writing_a_report(
    tmp_path, capsys, monkeypatch
):
    """Non-auth failures never trip the AAA breaker, but an all-failed pass
    has nothing left to say and must not reconnect for the member pass."""
    csv = _live_run_setup(tmp_path, monkeypatch, ["10.0.0.1", "10.0.0.2"])
    _fake_sessions(monkeypatch, fail_timeout={"10.0.0.1", "10.0.0.2"})
    sleeps = _record_sleeps(monkeypatch)

    rc = main(["run", str(csv), "--output", str(tmp_path / "out")])

    err = capsys.readouterr().err
    assert rc == 3
    assert "all 2 device(s) failed" in err
    assert sleeps == []


def test_partial_failure_reports_survivors_without_waiting(
    tmp_path, capsys, monkeypatch
):
    csv = _live_run_setup(tmp_path, monkeypatch, ["10.0.0.1", "10.0.0.2"])
    attempts = _fake_sessions(monkeypatch, fail_timeout={"10.0.0.1"})
    sleeps = _record_sleeps(monkeypatch)

    rc = main(["run", str(csv), "--output", str(tmp_path / "out")])

    assert rc == 0
    assert sleeps == []
    # One connection per device, and no second visit to the survivor.
    assert attempts == ["10.0.0.1", "10.0.0.2"]
    report_txt = next((tmp_path / "out").glob("iftriage_report_*.txt")).read_text()
    assert "UNVERIFIED" in report_txt


def test_the_run_path_never_blocks_on_a_timer(tmp_path, monkeypatch):
    """The whole point of the change: `import time` is gone from the CLI, and
    no module in the run path spends a measurable second waiting."""
    import iftriage.cli

    assert not hasattr(iftriage.cli, "time")

    csv = _live_run_setup(tmp_path, monkeypatch, ["10.0.0.1"])
    _fake_sessions(monkeypatch)
    sleeps = _record_sleeps(monkeypatch)

    assert main(["run", str(csv), "--output", str(tmp_path / "out")]) == 0
    assert sleeps == []


def test_all_devices_cpu_skipped_still_reports_instead_of_aborting(
    tmp_path, capsys, monkeypatch
):
    """A CPU skip is a deliberate outcome the report must show, not an abort."""
    csv = _live_run_setup(tmp_path, monkeypatch, ["10.0.0.1"])

    class BusySession:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            pass

        def get(self, command):
            return (
                "CPU utilization for five seconds: 92%/45%; "
                "one minute: 90%; five minutes: 88%"
            )

        def disconnect(self):
            pass

    monkeypatch.setattr("iftriage.collectors.ReadOnlySession", BusySession)
    sleeps = _record_sleeps(monkeypatch)

    rc = main(["run", str(csv), "--output", str(tmp_path / "out")])

    assert rc == 0
    assert sleeps == []
    report_txt = next((tmp_path / "out").glob("iftriage_report_*.txt")).read_text()
    assert "UNVERIFIED" in report_txt
    assert "device skipped: CPU utilization 92% above 80% threshold" in report_txt


def test_cpu_threshold_is_configurable_with_a_default_of_eighty(tmp_path):
    without_key = tmp_path / "without_key.yaml"
    without_key.write_text("connection:\n  timeout_seconds: 30\n")
    assert load_config(without_key).connection.cpu_skip_threshold_percent == 80.0

    with_key = tmp_path / "with_key.yaml"
    with_key.write_text("connection:\n  cpu_skip_threshold_percent: 65\n")
    assert load_config(with_key).connection.cpu_skip_threshold_percent == 65.0


def test_threshold_percentages_are_read_as_fractions(tmp_path):
    """The percent-to-fraction conversion is where a factor of 100 would slip
    in unnoticed, so it is asserted rather than assumed."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "thresholds:\n  error_rate_percent: 0.5\n  discard_rate_percent: 2\n"
    )

    thresholds = load_config(config_path).thresholds

    assert thresholds.error_rate == pytest.approx(0.005)
    assert thresholds.discard_rate == pytest.approx(0.02)


def test_retired_threshold_keys_are_rejected_not_ignored(tmp_path):
    """A config still carrying the pre-0.6 keys must not be accepted in
    silence: the run would judge every interface by the built-in defaults."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("thresholds:\n  rate_high: 1.0e-4\n")

    with pytest.raises(ValueError) as excinfo:
        load_config(config_path)

    assert "rate_high" in str(excinfo.value)
    assert "error_rate_percent" in str(excinfo.value)


@pytest.mark.parametrize("percent", ["0", "-1", "150"])
def test_threshold_percentage_out_of_range_is_rejected(tmp_path, percent):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"thresholds:\n  error_rate_percent: {percent}\n")

    with pytest.raises(ValueError) as excinfo:
        load_config(config_path)

    assert "percentage" in str(excinfo.value)


def test_workers_defaults_to_one_session_at_a_time():
    args = _build_parser().parse_args(["run", "top20.csv"])
    assert args.workers == 1


def test_config_file_cannot_turn_on_parallelism(tmp_path):
    """Concurrency is a command-line decision only: a leftover `workers` key in
    config.yaml is ignored rather than silently widening the fan-out."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("connection:\n  workers: 10\n  timeout_seconds: 45\n")

    config = load_config(config_path)

    assert not hasattr(config.connection, "workers")
    assert config.connection.timeout_seconds == 45  # the rest still loads


def test_dry_run_notes_member_discovery_for_portchannel_cases(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    rc = main(["run", str(csv), "--dry-run"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "NOTE: port-channel — members are discovered" in out
    assert "No devices were contacted." in out


def _stored_run(tmp_path, monkeypatch, ips=("10.0.0.1", "10.0.0.2")):
    """One completed live run against fake sessions; returns the CSV path."""
    csv = _live_run_setup(tmp_path, monkeypatch, list(ips))
    _fake_sessions(monkeypatch)
    _record_sleeps(monkeypatch)
    assert main(["run", str(csv), "--no-baseline"]) == 0
    return csv


def _forbid_collection(monkeypatch):
    monkeypatch.setattr(
        "iftriage.collectors.ReadOnlySession",
        lambda **kwargs: pytest.fail("--from-history must contact no device"),
    )
    monkeypatch.setattr(
        "iftriage.cli._resolve_credentials",
        lambda username_arg: pytest.fail("--from-history must not need credentials"),
    )
    _clear_credential_env(monkeypatch)


def test_from_history_rebuilds_the_report_without_credentials_or_network(
    tmp_path, capsys, monkeypatch
):
    csv = _stored_run(tmp_path, monkeypatch)
    capsys.readouterr()
    _forbid_collection(monkeypatch)

    rc = main(["run", str(csv), "--from-history", "--output", str(tmp_path / "again")])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Rebuilt from stored collection: run #1" in out
    assert "no device was contacted" in out
    again = tmp_path / "again"
    assert len(list(again.glob("iftriage_report_*.html"))) == 1
    assert len(list(again.glob("iftriage_report_*.csv"))) == 1
    # No commands were sent, so there is nothing to audit.
    assert not list(again.glob("iftriage_audit_*.log"))


def test_from_history_writes_nothing_back_to_the_database(
    tmp_path, capsys, monkeypatch
):
    """A second archive of the same CSV would inflate every recurrence count."""
    csv = _stored_run(tmp_path, monkeypatch)
    _forbid_collection(monkeypatch)
    db = tmp_path / "iftriage_history.db"

    def counts():
        conn = sqlite3.connect(db)
        try:
            return tuple(
                conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("ingests", "ingest_rows", "runs", "case_results")
            )
        finally:
            conn.close()

    before = counts()
    assert main(["run", str(csv), "--from-history", "--output", str(tmp_path)]) == 0
    assert counts() == before


def test_from_history_and_dry_run_are_mutually_exclusive(tmp_path, capsys):
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    rc = main(["run", str(csv), "--from-history", "--dry-run"])

    assert rc == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_from_history_without_a_database_says_how_to_get_one(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    rc = main(["run", str(csv), "--from-history"])

    err = capsys.readouterr().err
    assert rc == 2
    assert "no history database" in err
    assert "run without --from-history first" in err


def test_from_history_refuses_when_a_case_was_never_collected(
    tmp_path, capsys, monkeypatch
):
    csv = _stored_run(tmp_path, monkeypatch)
    capsys.readouterr()
    _forbid_collection(monkeypatch)
    csv.write_text(
        csv.read_text()
        + "2026-08-24T09:00:00,sw-new,10.0.0.9,Gi1/0/9,desc,up,up,Rcv-Err,0,5,5\n"
    )

    rc = main(["run", str(csv), "--from-history", "--output", str(tmp_path)])

    err = capsys.readouterr().err
    assert rc == 2
    assert "no stored collection for 1 of 3 case(s)" in err
    assert "sw-new Gi1/0/9 (Rcv-Err)" in err


def test_from_history_says_which_collection_flags_it_ignores(
    tmp_path, capsys, monkeypatch
):
    csv = _stored_run(tmp_path, monkeypatch)
    capsys.readouterr()
    _forbid_collection(monkeypatch)

    rc = main(
        [
            "run",
            str(csv),
            "--from-history",
            "--no-baseline",
            "--user",
            "ops",
            "--output",
            str(tmp_path),
        ]
    )
    out = capsys.readouterr().out

    assert rc == 0
    assert "ignoring --no-baseline, --user" in out


# ---- comparing against an earlier stored sample -----------------------------


def _backdate(tmp_path, hours=18):
    """Move the stored run into the past so a real comparison window exists.

    Two runs in a test are milliseconds apart, which the minimum-window guard
    correctly refuses. Back-dating the run and the sample it took is how the
    guard stays under test instead of being configured away.
    """
    import json

    moved = datetime.now(UTC) - timedelta(hours=hours)
    conn = sqlite3.connect(tmp_path / "iftriage_history.db")
    conn.execute("UPDATE runs SET started_at=?", (moved.isoformat(),))
    for rowid, raw in conn.execute(
        "SELECT rowid, stats_json FROM case_results WHERE stats_json IS NOT NULL"
    ).fetchall():
        stats = json.loads(raw)
        stats["collected_at"] = moved.isoformat()
        conn.execute(
            "UPDATE case_results SET stats_json=? WHERE rowid=?",
            (json.dumps(stats), rowid),
        )
    conn.commit()
    conn.close()


def _first_run(tmp_path, monkeypatch, ips=("10.0.0.1",)):
    """One completed run, 18 h in the past, for a second one to compare with."""
    csv = _live_run_setup(tmp_path, monkeypatch, list(ips))
    _fake_sessions(monkeypatch)
    assert main(["run", str(csv), "--output", str(tmp_path / "first")]) == 0
    _backdate(tmp_path)
    return csv


def test_first_run_records_the_first_sample_and_does_not_ask(
    tmp_path, capsys, monkeypatch
):
    csv = _live_run_setup(tmp_path, monkeypatch, ["10.0.0.1"])
    _fake_sessions(monkeypatch)  # builtins.input already fails the test if called

    rc = main(["run", str(csv), "--output", str(tmp_path / "out")])
    out = capsys.readouterr().out

    assert rc == 0
    assert "records the first one" in out
    report = next((tmp_path / "out").glob("iftriage_report_*.txt")).read_text()
    assert "Baseline: 0 of 1 case(s)" in report


def test_accepting_the_offer_compares_against_the_earlier_sample(
    tmp_path, capsys, monkeypatch
):
    csv = _first_run(tmp_path, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("builtins.input", lambda label: "y")

    rc = main(["run", str(csv), "--output", str(tmp_path / "second")])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Stored earlier samples found for 1 of 1 case(s)" in out
    assert "Compared 1 of 1 case(s)" in out
    report = next((tmp_path / "second").glob("iftriage_report_*.txt")).read_text()
    assert (
        "Baseline: 1 of 1 case(s) compared against an earlier stored sample" in report
    )


def test_declining_the_offer_keeps_the_run_single_sample(tmp_path, capsys, monkeypatch):
    csv = _first_run(tmp_path, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("builtins.input", lambda label: "n")

    rc = main(["run", str(csv), "--output", str(tmp_path / "second")])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Single-sample run" in out
    report = next((tmp_path / "second").glob("iftriage_report_*.txt")).read_text()
    assert "Baseline: 0 of 1 case(s)" in report


def test_without_a_terminal_the_stored_sample_is_not_used(
    tmp_path, capsys, monkeypatch
):
    """Fail closed: a flat counter vetoes escalation, so a baseline is never
    applied to a run nobody is watching. Cron takes the default and never hangs."""
    csv = _first_run(tmp_path, monkeypatch)
    capsys.readouterr()

    def closed_stdin(label):
        # What a closed (not merely empty) stdin actually raises.
        raise ValueError("I/O operation on closed file")

    monkeypatch.setattr("builtins.input", closed_stdin)

    rc = main(["run", str(csv), "--output", str(tmp_path / "second")])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Single-sample run" in out
    report = next((tmp_path / "second").glob("iftriage_report_*.txt")).read_text()
    assert "Baseline: 0 of 1 case(s)" in report


def test_empty_stdin_takes_the_default_without_raising(tmp_path, capsys, monkeypatch):
    csv = _first_run(tmp_path, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("builtins.input", lambda label: (_ for _ in ()).throw(EOFError))

    assert main(["run", str(csv), "--output", str(tmp_path / "second")]) == 0
    assert "Single-sample run" in capsys.readouterr().out


@pytest.mark.parametrize("flag", ["--baseline", "--no-baseline"])
def test_baseline_flags_skip_the_question_entirely(tmp_path, monkeypatch, flag):
    csv = _first_run(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "builtins.input", lambda label: pytest.fail(f"{flag} must not prompt")
    )

    assert main(["run", str(csv), flag, "--output", str(tmp_path / "second")]) == 0


def test_baseline_and_no_baseline_cannot_be_combined(tmp_path, capsys):
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)

    with pytest.raises(SystemExit) as excinfo:
        main(["run", str(csv), "--baseline", "--no-baseline"])

    assert excinfo.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_dry_run_never_asks_about_baselines(tmp_path, monkeypatch):
    """A dry run contacts nothing and must stay non-interactive."""
    csv = _first_run(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "builtins.input", lambda label: pytest.fail("dry run must not prompt")
    )

    assert main(["run", str(csv), "--dry-run"]) == 0


def test_leftover_repoll_config_section_is_a_hard_error(tmp_path, capsys):
    """A file describing behavior that no longer exists must not be accepted in
    silence: the operator would believe the tool still waits and re-polls."""
    csv = tmp_path / "top20.csv"
    shutil.copy(FIXTURES / "sample_top20.csv", csv)
    config_path = tmp_path / "config.yaml"
    config_path.write_text("repoll:\n  default_minutes: 10\n")

    rc = main(["run", str(csv), "--dry-run", "--config", str(config_path)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "'repoll' section was removed" in err
    assert "baseline" in err


def test_crossed_baseline_bounds_are_rejected(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "baseline:\n  min_window_minutes: 60\n  max_window_days: 0.01\n"
    )

    with pytest.raises(ValueError, match="must be longer than"):
        load_config(config_path)


def test_unknown_baseline_key_is_rejected(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("baseline:\n  max_window_minutes: 10\n")

    with pytest.raises(ValueError, match="unknown key 'baseline.max_window_minutes'"):
        load_config(config_path)
