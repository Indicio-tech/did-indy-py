"""Driver configuration."""

import logging
import os
import tomllib
from pathlib import Path
from typing import List
from pydantic import BaseModel


LOGGER = logging.getLogger(__name__)


class ConfigFileNotFoundError(Exception):
    """Raised on configuration file not found."""


class BaseLedgerConfig(BaseModel):
    """Ledger configuration."""

    namespace: str
    seed: str


class RemoteLedgerGenesis(BaseLedgerConfig):
    """Ledger configuration where genesis info is remote."""

    url: str


class LocalLedgerGenesis(BaseLedgerConfig):
    """Ledger configuration where genesis info is local."""

    path: str


class LedgerConfig(BaseModel):
    """Ledgers config."""

    ledgers: List[RemoteLedgerGenesis | LocalLedgerGenesis]

    @staticmethod
    def search_default_config_locations():
        user = os.getuid()
        for path in (
            "/run/secrets/ledgers.toml",
            "/run/ledgers.toml",
            "/ledgers.toml",
            "/etc/driver-did-indy/ledgers.toml",
        ):
            path = Path(path)
            if not path.exists():
                continue
            if not path.is_file():
                continue
            if path.stat().st_uid != user and not (path.stat().st_mode & 0o004):
                continue

            LOGGER.debug("Loading ledger config from %s", path)
            return path

        raise ConfigFileNotFoundError("Could not find ledgers.toml")

    @classmethod
    def from_config_file(cls, path: Path | str | None) -> "LedgerConfig":
        """Load from a config file."""
        if isinstance(path, str):
            path = Path(path)
        elif isinstance(path, Path):
            pass
        elif path is None:
            path = cls.search_default_config_locations()

        with path.open("rb") as f:
            raw = tomllib.load(f)

        return cls.model_validate(raw)
