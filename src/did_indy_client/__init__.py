"""Client to did:indy driver."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
import logging
from typing import (
    Any,
    List,
    Mapping,
    Optional,
)

from did_indy_client.http_client import HTTPClient, Serde

LOGGER = logging.getLogger(__name__)


@dataclass
class TAARecord:
    text: str
    version: str
    digest: str


@dataclass
class TAAInfo(Serde):
    aml: dict
    taa: TAARecord | None
    required: bool

    def serialize(self) -> Mapping[str, Any]:
        return asdict(self)

    @classmethod
    def deserialize(cls, value: Mapping[str, Any]) -> "TAAInfo":
        value = dict(value)
        record = value.pop("taa", None)
        if record:
            record = TAARecord(**record)

        return TAAInfo(
            **value,
            taa=record,
        )


@dataclass
class TaaAcceptance:
    taaDigest: str
    mechanism: str
    time: int


@dataclass
class CreateNymResult:
    """Result of a nym create operation."""

    seqNo: int
    nym: str
    verkey: str
    did: str
    did_sov: str
    role: str | None = None
    diddocContent: Mapping[str, Any] | None = None


@dataclass
class TxnToSignResponse:
    """Response capturing a request that needs to be signed."""

    request: str
    signature_input: str

    def get_signature_input_bytes(self):
        """Get signature input as bytes."""
        return urlsafe_b64decode(self.signature_input)


@dataclass
class SchemaSubmitResponse:
    """Response to schema submission."""

    schema_id: str
    indy_schema_id: str
    registration_metadata: dict
    schema_metadata: dict


@dataclass
class CredDefSubmitResponse:
    """Response to cred def submission."""

    cred_def_id: str
    indy_cred_def_id: str
    registration_metadata: dict
    schema_metadata: dict


class IndyClientError(Exception):
    """Raised on errors in indy client."""


class IndyClient(HTTPClient):
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
    ) -> CreateNymResult:
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
                "taa": asdict(taa) if taa else None,
            },
            response=CreateNymResult,
        )
        return result

    async def create_schema(
        self,
        schema: dict | str,
        taa: TaaAcceptance | None = None,
    ) -> TxnToSignResponse:
        """Create a schema."""
        result = await self.post(
            url="/txn/schema",
            json={
                "schema": schema,
                "taa": asdict(taa) if taa else None,
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

    async def create_cred_def(
        self,
        cred_def: dict | str,
        taa: TaaAcceptance | None = None,
    ) -> TxnToSignResponse:
        """Create a cred def."""
        result = await self.post(
            url="/txn/credential-definition",
            json={
                "cred_def": cred_def,
                "taa": asdict(taa) if taa else None,
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
            url="/txn/credential-definition/submit",
            json={
                "submitter": submitter,
                "request": request,
                "signature": signature,
            },
        )
        return result
