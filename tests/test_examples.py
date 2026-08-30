"""The artifacts in docs/examples/ must match what the tool produces today.

They are documentation of real behavior — the command set, the audit trail and
the verdict wording — so a change that moves any of those has to regenerate
them in the same PR. Running the harness in a subprocess keeps the module-level
patching it does (fake transport, frozen clock) out of the rest of the suite.
No device is contacted: the harness replays sanitized fixtures.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_docs_examples_are_up_to_date():
    result = subprocess.run(
        [sys.executable, "scripts/regen_examples.py", "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"{result.stdout}{result.stderr}\n"
        "docs/examples is stale — run: python scripts/regen_examples.py"
    )
