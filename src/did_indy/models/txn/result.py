"""Txn models for results of operations."""

from typing import Generic, List, Literal, TypeVar

from pydantic import BaseModel, Field

from did_indy.models.taa import TaaAcceptance

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
