from pathlib import Path
from typing import Iterable
import pytest

UNIT_TEST_DIR = Path(__file__).parent


def pytest_collection_modifyitems(config, items: Iterable[pytest.Item]):
    for item in items:
        path = Path(item.fspath)
        if path.is_relative_to(UNIT_TEST_DIR):
            item.add_marker(pytest.mark.unit)
