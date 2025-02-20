from dataclasses import dataclass
from typing import Any, Dict, Generic, List, Literal, TypeVar

from pydantic import BaseModel, Field

from .taa import TaaAcceptance


class SchemaTxnDataData(BaseModel):
    """Schema Transaction txn.data.data."""

    attr_names: List[str]
    name: str
    version: str


class SchemaTxnData(BaseModel):
    """Schema Transaction txn.data."""

    data: SchemaTxnDataData


class CredDefTxnDataData(BaseModel):
    """Cred Def Transaction txn.data.data."""

    primary: Dict[str, Any]


class CredDefTxnData(BaseModel):
    """Cred Def Transaction txn.data."""

    data: CredDefTxnDataData
    ref: int
    signature_type: Literal["CL"]
    tag: str


TxnData = TypeVar("TxnData", bound=BaseModel)


class TxnTxnMetadata(BaseModel):
    """Transaction metadata."""

    frm: str = Field(alias="from")
    reqId: int
    taaAcceptance: TaaAcceptance
    digest: str
    payloadDigest: str
    endorser: str | None = None


class Transaction(BaseModel, Generic[TxnData]):
    """Transaction details."""

    type: str
    data: TxnData
    protocolVersion: int
    metadata: TxnTxnMetadata


class TxnMetadata(BaseModel):
    """Transaction metadata (outer object)."""

    txnId: str
    txnTime: int
    seqNo: int


class ReqSig(BaseModel):
    """Individual request signature."""

    frm: str = Field(alias="from")
    value: str


class ReqSignature(BaseModel):
    """Request Signatures."""

    type: Literal["ED25519"]
    values: List[ReqSig]


class TxnResult(BaseModel, Generic[TxnData]):
    """Transaction submission result."""

    txn: Transaction[TxnData]
    txnMetadata: TxnMetadata
    reqSignature: ReqSignature
    ver: Literal["1"]
    rootHash: str
    auditPath: List[str]


class GetReply(BaseModel, Generic[TxnData]):
    """Get txn reply."""

    data: TxnData
    dest: str
    identifier: str
    reqId: int
    seqNo: int
    state_proof: Any
    txnTime: int
    type: str


class NodeResponse(BaseModel, Generic[TxnData]):
    """Node response object."""

    op: Literal["REPLY"] | str
    result: GetReply[TxnData]


class DerefContentMetadata(BaseModel, Generic[TxnData]):
    """Content metadata in deref result."""

    nodeResponse: NodeResponse
    objectType: Literal["SCHEMA"] | str


class DereferenceResult(BaseModel, Generic[TxnData]):
    """Result of a dereference."""

    dereferencingMetadata: Any
    contentStream: TxnData
    contentMetadata: DerefContentMetadata


@dataclass
class Endorsement:
    nym: str
    signature: bytes
