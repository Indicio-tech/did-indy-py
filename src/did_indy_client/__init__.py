"""Client to did:indy driver."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from httpx import AsyncClient


@dataclass
class TAARecord:
    text: str
    version: str
    digest: str


@dataclass
class TAAInfo:
    aml: dict
    taa: TAARecord | None
    required: bool

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> "TAAInfo":
        record = response.pop("taa", None)
        if record:
            record = TAARecord(**record)

        return TAAInfo(
            **response,
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


class IndyClient:
    """Client to the did:indy driver."""

    def __init__(self, base_url: str):
        """Init the client."""
        self.base_url = base_url

    async def get_namespaces(self) -> List[str]:
        """Get namespaces."""
        async with AsyncClient(base_url=self.base_url) as session:
            resp = await session.get(url="/namespace")
            resp.raise_for_status()
            body = resp.json()

        return body["namespaces"]

    async def get_taa(self, namespace: str) -> TAAInfo:
        """Get TAA Info."""
        async with AsyncClient(base_url=self.base_url) as session:
            resp = await session.get(url=f"/taa/{namespace}")
            resp.raise_for_status()
            result = TAAInfo.from_response(resp.json())

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

        async with AsyncClient(base_url=self.base_url) as session:
            resp = await session.post(
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
            )
            resp.raise_for_status()
            result = CreateNymResult(**resp.json())

        return result

    async def create_schema(
        self,
        issuer_id: str,
        attr_names: List[str],
        name: str,
        version: str,
        taa: TaaAcceptance | None = None,
    ) -> TxnToSignResponse:
        """Create a schema."""
        async with AsyncClient(base_url=self.base_url) as session:
            resp = await session.post(
                url="/txn/schema",
                json={
                    "issuer_id": issuer_id,
                    "attr_names": attr_names,
                    "name": name,
                    "version": version,
                    "taa": asdict(taa) if taa else None,
                },
            )
            resp.raise_for_status()
            result = TxnToSignResponse(**resp.json())
        return result

    async def submit(
        self,
        submitter: str,
        request: str,
        signature: str | bytes,
    ):
        """Submit a signed txn."""
        if isinstance(signature, bytes):
            signature = urlsafe_b64encode(signature).decode()

        async with AsyncClient(base_url=self.base_url) as session:
            resp = await session.post(
                url="/txn/submit",
                json={
                    "submitter": submitter,
                    "request": request,
                    "signature": signature,
                },
            )
            resp.raise_for_status()
            return resp.json()
