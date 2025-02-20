"""Client to did:indy driver."""

from base64 import urlsafe_b64encode
from datetime import date, datetime, timezone
import logging
from typing import Any, List, Optional

from did_indy.models.taa import TAAInfo, TaaAcceptance
from did_indy_client.http import HTTPClient
from driver_did_indy.api.txns import (
    EndorseResponse,
    NymResponse,
    SchemaSubmitResponse,
    TxnToSignResponse,
)

LOGGER = logging.getLogger(__name__)


class IndyDriverClientError(Exception):
    """Raised on errors in indy client."""


class IndyDriverClient(HTTPClient):
    """Client to the did:indy driver."""

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
