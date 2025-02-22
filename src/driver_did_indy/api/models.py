"""API Request and Response models."""

import base64
from typing import Any, Mapping

from pydantic import BaseModel, Field

from did_indy.models.anoncreds import CredDef, Schema
from did_indy.models.taa import TaaAcceptance
from did_indy.models.txn import TxnMetadata, TxnResult


class NymRequest(BaseModel):
    """Nym Request."""

    namespace: str
    verkey: str
    nym: str | None = None
    role: str | None = None
    diddocContent: str | Mapping[str, Any] | None = None
    version: int | None = None
    taa: TaaAcceptance | None = None


class NymResponse(BaseModel):
    seqNo: int
    nym: str
    verkey: str
    did: str
    did_sov: str
    role: str | None = None
    diddocContent: Mapping[str, Any] | None = None


class SchemaRequest(BaseModel):
    """Schema Create Request."""

    schema_value: Schema | str = Field(alias="schema")
    taa: TaaAcceptance | None = None


class TxnToSignResponse(BaseModel):
    """Schema Create Response."""

    request: str
    signature_input: str

    def get_signature_input_bytes(self):
        """Get signature input as bytes."""
        return base64.urlsafe_b64decode(self.signature_input)


class SubmitRequest(BaseModel):
    """Txn Submit Request."""

    submitter: str
    request: str
    signature: str


class EndorseRequest(BaseModel):
    """Endorse request."""

    submitter: str
    request: str


class EndorseResponse(BaseModel):
    """Endorse response."""

    nym: str
    signature: str

    def get_signature_bytes(self):
        """Get signature as bytes."""
        return base64.urlsafe_b64decode(self.signature)


class SchemaSubmitResponse(BaseModel):
    """Schema submit response."""

    schema_id: str
    indy_schema_id: str
    registration_metadata: TxnResult
    schema_metadata: TxnMetadata


class CredDefRequest(BaseModel):
    """Credential Definition create request."""

    cred_def: CredDef | str
    taa: TaaAcceptance | None = None


class CredDefSubmitResponse(BaseModel):
    """Credential Definition submit response."""

    cred_def_id: str
    indy_cred_def_id: str
    registration_metadata: TxnResult
    cred_def_metadata: TxnMetadata


__all__ = [
    "NymRequest",
    "NymResponse",
    "SchemaRequest",
    "TxnToSignResponse",
    "SubmitRequest",
    "EndorseRequest",
    "EndorseResponse",
    "SchemaSubmitResponse",
    "CredDefRequest",
    "CredDefSubmitResponse",
]
