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

from driver_did_indy.depends import StoreDep


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
    scope: str
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

        scan = store.scan(
            category="client",
            tag_filter={
                "client_id": parsed.client_id,
                "jti": parsed.jti,
            },
            limit=1,
        )
        clients = await scan.fetch_all()
        if not clients:
            raise HTTPException(403, "Revoked token")

        scopes = parsed.scope.split(" ")
        for scope in security_scopes.scopes:
            if scope not in scopes:
                raise HTTPException(403, "Insufficient scope")
