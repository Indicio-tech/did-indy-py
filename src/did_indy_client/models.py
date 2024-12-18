"""Client to did:indy driver."""

from base64 import urlsafe_b64decode
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from did_indy_client.http_client import Serde


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
class EndorseResponse:
    """Response to an endorse request."""

    request: str


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
