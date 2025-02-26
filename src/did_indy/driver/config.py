"""Driver configuration."""

import logging
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


LOGGER = logging.getLogger(__name__)


class ConfigError(Exception):
    """Configuration error."""


class Config(BaseSettings):
    """Driver configuration."""

    model_config = SettingsConfigDict(env_file=".env")

    issuer: str
    passphrase: str
    auth: Literal["insecure", "api-key", "client-tokens"]
    ledger_config: str | None = None
    admin_api_key: str | None = None
    client_api_key: str | None = None
    client_token_secret: str | None = None
