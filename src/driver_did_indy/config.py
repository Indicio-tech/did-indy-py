"""Driver configuration."""

import logging
from pydantic_settings import BaseSettings, SettingsConfigDict


LOGGER = logging.getLogger(__name__)


class ConfigError(Exception):
    """Configuration error."""


class Config(BaseSettings):
    """Driver configuration."""

    model_config = SettingsConfigDict(env_file=".env")

    passphrase: str
    ledger_config: str | None = None
