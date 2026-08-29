"""CLI dry-run: prints targets and exact commands, connects to nothing."""

import shutil

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

    rc = main(["run", str(csv), "--no-repoll"])

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
