"""Models capturing results of dereferencing a DID URL pointing to ledger artifact.

These are effectively the "get" operations.
"""

from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel

from .data import (
    CredDefTxnDataData,
    RevRegDefTxnData,
    SchemaTxnDataData,
)


class GetSchemaReply(BaseModel):
    """Get schema reply."""

    data: SchemaTxnDataData
    dest: str
    identifier: str
    reqId: int
    seqNo: int
    state_proof: Any
    txnTime: int
    type: str


class GetCredDefReply(BaseModel):
    """Get cred def reply."""

    data: CredDefTxnDataData
    identifier: str
    origin: str
    ref: int
    reqId: int
    seqNo: int
    signature_type: Literal["CL"]
    state_proof: Any
    tag: str
    txnTime: int
    type: str


class GetRevRegDefReply(BaseModel):
    """Get revocation registry definition reply."""

    data: RevRegDefTxnData
    id: str
    identifier: str
    reqId: int
    seqNo: int
    state_proof: Any
    txnTime: int
    type: str


Reply = TypeVar("Reply", bound=BaseModel)


class NodeResponse(BaseModel, Generic[Reply]):
    """Node response object."""

    op: Literal["REPLY"] | str
    result: Reply


class DerefContentMetadata(BaseModel, Generic[Reply]):
    """Content metadata in deref result."""

    nodeResponse: NodeResponse[Reply]
    objectType: Literal["SCHEMA", "CRED_DEF"] | str


ContentStream = TypeVar("ContentStream", bound=BaseModel)
ContentMetadata = TypeVar("ContentMetadata", bound=BaseModel)


class DereferenceResult(BaseModel, Generic[ContentStream, ContentMetadata]):
    """Result of a dereference."""

    dereferencingMetadata: Any
    contentStream: ContentStream
    contentMetadata: DerefContentMetadata[ContentMetadata]


SchemaDeref = DereferenceResult[SchemaTxnDataData, GetSchemaReply]
CredDefDeref = DereferenceResult[CredDefTxnDataData, GetCredDefReply]
RevRegDefDeref = DereferenceResult[RevRegDefTxnData, GetRevRegDefReply]
