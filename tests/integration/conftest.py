import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.fspath.dirname.endswith("integration"):
            item.add_marker(pytest.mark.integration)
