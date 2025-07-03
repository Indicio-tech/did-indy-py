"""Pytest fixtures and configuration."""

import subprocess
from pathlib import Path

import pytest
from pytest import Session

DEMO_DIR = Path(__file__).parents[2] / "demo"


class DemoFailedException(Exception):
    """Raised when an demo fails."""

    def __init__(self, message: str, exit_status: int):
        """Initialize DemoFailedException."""

        super().__init__(message)
        self.exit_status = exit_status


class DemoRunner:
    """Run the docker-compose of the demo."""

    def __init__(self, compose_file: str):
        """Initialize DemoRunner."""

        self.compose_file = compose_file

    def compose(self, *command: str) -> int:
        """Runs docker-compose using subprocess with the given command.

        Returns exit status and output.
        """
        try:
            subprocess.run(
                ["docker", "compose", "-f", self.compose_file, *command],
                check=True,
            )
            return 0
        except subprocess.CalledProcessError as e:
            return e.returncode

    def cleanup(self):
        """Runs docker-compose down -v for cleanup."""
        exit_status = self.compose("down", "-v")
        if exit_status != 0:
            raise DemoFailedException(
                f"Cleanup failed with exit status {exit_status}", exit_status
            )

    def handle_run(self, *command: str):
        """Handles the run of docker-compose/.

        raises exception if exit status is non-zero.
        """
        try:
            exit_status = self.compose(*command)
            if exit_status != 0:
                raise DemoFailedException(
                    f"Command failed with exit status: {exit_status}",
                    exit_status=exit_status,
                )
        finally:
            self.cleanup()


class DemoFile(pytest.File):
    """Pytest file for demo."""

    def collect(self):
        """Collect tests from demo file."""
        path = Path(self.fspath)
        print("DemoFile.collect", path)
        item = DemoItem.from_parent(
            self, name=path.name, compose_file=str(path / "docker-compose.yml")
        )
        item.add_marker(pytest.mark.e2e)
        yield item


class DemoItem(pytest.Item):
    """Demo item.

    Runs the docker-compose.yml file of the demo and reports failure if the
    exit status is non-zero.
    """

    def __init__(self, name: str, parent: pytest.File, compose_file: str):
        """Initialize DemoItem."""
        super().__init__(name, parent)
        self.compose_file = compose_file

    def runtest(self) -> None:
        """Run the test."""
        DemoRunner(self.compose_file).handle_run("run", "--rm", "demo")

    def repr_failure(self, excinfo, style=None):
        """Called when self.runtest() raises an exception."""
        if isinstance(excinfo.value, DemoFailedException):
            return "\n".join(
                [
                    "Demo failed!",
                    f"    {excinfo.value}",
                ]
            )
        return f"Some other exectpion happened: {excinfo.value}"

    def reportinfo(self):
        """Report info about the demo."""
        return self.fspath, 0, f"demo: {self.name}"


def pytest_collect_file(parent: Session, file_path: Path):
    """Pytest collection hook.

    This will collect the docker-compose.yml file from the demo and create
    a pytest item to run it.
    """
    if file_path == Path(__file__):
        return DemoFile.from_parent(parent, path=DEMO_DIR)


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.fspath.dirname.endswith("e2e"):
            item.add_marker(pytest.mark.e2e)
