"""CLI dry-run: prints targets and exact commands, connects to nothing."""

import shutil

from conftest import FIXTURES

from iftriage.cli import main


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
