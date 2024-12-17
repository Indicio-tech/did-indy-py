"""Driver configuration."""

import tomllib
from pathlib import Path
from typing import List
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    """Driver configuration."""

    model_config = SettingsConfigDict(env_file=".env")

    passphrase: str
    ledger_config: str = "/run/secrets/ledgers.toml"


class LedgerConfig(BaseModel):
    """Ledger configuration."""

    namespace: str
    seed: str


class RemoteLedgerGenesis(LedgerConfig):
    """Ledger configuration where genesis info is remote."""

    url: str


class LocalLedgerGenesis(LedgerConfig):
    """Ledger configuration where genesis info is local."""

    path: str


class LedgersConfig(BaseModel):
    """Ledgers config."""

    ledgers: List[RemoteLedgerGenesis | LocalLedgerGenesis]

    @classmethod
    def from_config_file(cls, path: Path | str) -> "LedgersConfig":
        """Load from a config file."""
        if isinstance(path, str):
            path = Path(path)

        with path.open("rb") as f:
            raw = tomllib.load(f)

        return cls.model_validate(raw)
