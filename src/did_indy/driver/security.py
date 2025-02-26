"""API Security."""

from fastapi import Depends, HTTPException
from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBearer,
    SecurityScopes,
)
import jwt
from pydantic import BaseModel, ConfigDict

from did_indy.driver.auto_endorse import ClientAutoEndorseRules, derive_scopes
from did_indy.driver.config import Config, ConfigError
from did_indy.driver.depends import StoreDep, get_config


class InsecureMode:
    """No authentication mode.

    This is for testing only; do not use this.
    """

    async def admin(
        self,
    ):
        """Check validity of API Key for admin operations."""
        return

    async def client(self):
        """Check validity of API Key for client operations."""
        return


class APIKey:
    """Secure the API by API Key.

    This mode might be useful for simple deployments where only a single client
    is expected.
    """

    HEADER = APIKeyHeader(name="x-api-key")

    def __init__(self, admin_key: str, client_key: str | None = None):
        """API Key auth."""
        self.admin_key = admin_key
        self.client_key = client_key if client_key is not None else admin_key

    async def admin(
        self,
        key: str = Depends(HEADER),
    ):
        """Check validity of API Key for admin operations."""
        if key != self.admin_key:
            raise HTTPException(401)

    async def client(self, key: str = Depends(HEADER)):
        """Check validity of API Key for client operations."""
        if key != self.client_key:
            raise HTTPException(401)


class ClientToken(BaseModel):
    """Client token payload."""

    model_config = ConfigDict(extra="ignore")

    jti: str
    client_id: str
    nonce: str


class AdminAPIKeyClientToken:
    """Secure the API with a combination of Admin API Key and Client Tokens.

    This mode might be useful for deployments where only a single admin is expected
    but many clients.
    """

    API_KEY = APIKeyHeader(name="x-api-key")
    BEARER = HTTPBearer()

    def __init__(self, admin_key: str, secret: str):
        """API Key auth."""
        self.admin_key = admin_key
        self.secret = secret

    async def admin(
        self,
        key: str = Depends(API_KEY),
    ):
        """Check validity of API Key for admin operations."""
        if key != self.admin_key:
            raise HTTPException(401)

    async def client(
        self,
        security_scopes: SecurityScopes,
        store: StoreDep,
        token: HTTPAuthorizationCredentials = Depends(BEARER),
    ):
        """Check client tokens for client operations."""
        try:
            payload = jwt.decode(
                token.credentials,
                self.secret,
                algorithms=["HS256"],
            )
        except Exception as error:
            raise HTTPException(401) from error

        parsed = ClientToken.model_validate(payload)

        async with store.session() as session:
            entry = await session.fetch(category="clients", name=parsed.client_id)
            if not entry:
                raise HTTPException(401)

            jti = entry.value_json["jti"]
            rules = ClientAutoEndorseRules.model_validate(entry.value_json["rules"])

        if not jti == parsed.jti:
            raise HTTPException(403, "Revoked token")

        scopes = derive_scopes(rules)
        for scope in security_scopes.scopes:
            if scope not in scopes:
                raise HTTPException(403, "Insufficient scope")


def auth_provider(config: Config):
    """Provide authentication mechanism based on config."""
    if config.auth == "insecure":
        return InsecureMode()
    elif config.auth == "api-key":
        if config.admin_api_key is None:
            raise ConfigError("auth mode is api-key but admin_api_key is not set")
        return APIKey(config.admin_api_key, config.client_api_key)
    elif config.auth == "client-tokens":
        if config.admin_api_key is None:
            raise ConfigError("auth mode is client-tokens but admin_api_key is not set")
        if config.client_token_secret is None:
            raise ConfigError(
                "auth mode is client-tokens but client_token_secret is not set"
            )
        return AdminAPIKeyClientToken(config.admin_api_key, config.client_token_secret)
    else:
        raise ConfigError(f"Invalid auth mode {config.auth}")


try:
    Auth = auth_provider(get_config())
except RuntimeError:
    # This is to enable importing models from api modules from the client
    Auth = InsecureMode()
