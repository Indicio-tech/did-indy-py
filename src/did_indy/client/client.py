"""Client to did:indy driver."""

from base64 import urlsafe_b64encode
from datetime import date, datetime, timezone
import logging
from typing import Any, List, Optional

from did_indy.models.taa import TAAInfo, TaaAcceptance
from driver_did_indy.api.clients import ClientCreateResponse
from driver_did_indy.api.txns import (
    EndorseResponse,
    NymResponse,
    SchemaSubmitResponse,
    TxnToSignResponse,
)

from .http import HTTPClient

LOGGER = logging.getLogger(__name__)


class IndyDriverClientError(Exception):
    """Raised on errors in indy client."""


class IndyDriverAdminClient(HTTPClient):
    """Client to admin endpoints of did:indy driver."""

    def __init__(
        self,
        base_url: str,
        admin_api_key: str | None = None,
        *,
        headers: dict[str, str] | None = None,
    ):
        """Init the client."""
        headers = headers or {}
        if admin_api_key:
            headers["X-API-Key"] = admin_api_key
        super().__init__(base_url, headers)

    async def create_client(
        self,
        name: str,
        *,
        new_nyms: int = 1,
        nym_updates: bool = True,
        nym_role_changes: bool = False,
        schemas: bool = False,
        cred_defs: bool = False,
        rev_reg_defs: bool = True,
        rev_reg_entries: bool = True,
    ) -> ClientCreateResponse:
        """Create a new client."""
        response = await self.post(
            "/clients",
            json={
                "name": name,
                "auto_endorse": {
                    "new_nyms": new_nyms,
                    "nym_updates": nym_updates,
                    "nym_role_changes": nym_role_changes,
                    "schemas": schemas,
                    "cred_defs": cred_defs,
                    "rev_reg_defs": rev_reg_defs,
                    "rev_reg_entries": rev_reg_entries,
                },
            },
            response=ClientCreateResponse,
        )
        return response

    async def refresh_token(self, client_id: str) -> ClientCreateResponse:
        """Refresh the token, revoking the old."""
        response = await self.get(
            f"/clients/{client_id}/token",
            response=ClientCreateResponse,
        )
        return response


class IndyDriverClient(HTTPClient):
    """Client to the did:indy driver."""

    def __init__(
        self,
        base_url: str,
        client_api_key: str | None = None,
        client_token: str | None = None,
        *,
        headers: dict[str, str] | None = None,
    ):
        """Init the client."""
        headers = headers or {}
        if client_token:
            headers["Authorization"] = f"Bearer {client_token}"
        if client_api_key:
            headers["X-API-Key"] = client_api_key
        super().__init__(base_url, headers)

    async def get_namespaces(self) -> List[str]:
        """Get namespaces."""
        result = await self.get("/namespace")
        return result["namespaces"]

    async def get_taa(self, namespace: str) -> TAAInfo:
        """Get TAA Info."""
        result = await self.get(f"/taa/{namespace}", response=TAAInfo)
        return result

    def taa_rough_timestamp(self) -> int:
        """Get a timestamp accurate to the day.

        Anything more accurate is a privacy concern.
        """
        return int(
            datetime.combine(
                date.today(), datetime.min.time(), timezone.utc
            ).timestamp()
        )

    async def accept_taa(
        self, info: TAAInfo, mechanism: str, accept_time: Optional[int] = None
    ) -> TaaAcceptance | None:
        """Generate TAA Acceptance object."""
        if not accept_time:
            accept_time = self.taa_rough_timestamp()

        if info.required is False or info.taa is None:
            return None

        return TaaAcceptance(
            taaDigest=info.taa.digest,
            mechanism=mechanism,
            time=accept_time,
        )

    async def create_nym(
        self,
        namespace: str,
        verkey: str,
        nym: str | None = None,
        role: str | None = None,
        diddoc_content: str | None = None,
        version: int | None = None,
        taa: TaaAcceptance | None = None,
    ) -> NymResponse:
        """Create a new nym on the ledger."""
        result = await self.post(
            url="/txn/nym",
            json={
                "namespace": namespace,
                "verkey": verkey,
                "nym": nym,
                "role": role,
                "diddocContent": diddoc_content,
                "version": version,
                "taa": taa.for_request() if taa else None,
            },
            response=NymResponse,
        )
        return result

    async def create_schema(
        self,
        schema: dict | str | Any,
        taa: TaaAcceptance | None = None,
    ) -> TxnToSignResponse:
        """Create a schema."""
        result = await self.post(
            url="/txn/schema",
            json={
                "schema": schema,
                "taa": taa.for_request() if taa else None,
            },
            response=TxnToSignResponse,
        )
        return result

    async def submit_schema(
        self,
        submitter: str,
        request: str,
        signature: str | bytes,
    ) -> SchemaSubmitResponse:
        """Submit a signed txn."""
        if isinstance(signature, bytes):
            signature = urlsafe_b64encode(signature).decode()

        result = await self.post(
            url="/txn/schema/submit",
            json={
                "submitter": submitter,
                "request": request,
                "signature": signature,
            },
            response=SchemaSubmitResponse,
        )
        return result

    async def endorse_schema(
        self,
        submitter: str,
        request: str,
    ) -> EndorseResponse:
        """Submit a signed txn."""
        result = await self.post(
            url="/txn/schema/endorse",
            json={
                "submitter": submitter,
                "request": request,
            },
            response=EndorseResponse,
        )
        return result

    async def create_cred_def(
        self,
        cred_def: dict | str,
        taa: TaaAcceptance | None = None,
    ) -> TxnToSignResponse:
        """Create a cred def."""
        result = await self.post(
            url="/txn/cred-def",
            json={
                "cred_def": cred_def,
                "taa": taa.for_request() if taa else None,
            },
            response=TxnToSignResponse,
        )
        return result

    async def submit_cred_def(
        self,
        submitter: str,
        request: str,
        signature: str | bytes,
    ):
        """Submit a signed txn."""
        if isinstance(signature, bytes):
            signature = urlsafe_b64encode(signature).decode()

        result = await self.post(
            url="/txn/cred-def/submit",
            json={
                "submitter": submitter,
                "request": request,
                "signature": signature,
            },
        )
        return result

    async def endorse_cred_def(
        self,
        submitter: str,
        request: str,
    ) -> EndorseResponse:
        """Submit a signed txn."""
        result = await self.post(
            url="/txn/cred-def/endorse",
            json={
                "submitter": submitter,
                "request": request,
            },
            response=EndorseResponse,
        )
        return result
