from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


def load_fixture(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text()
