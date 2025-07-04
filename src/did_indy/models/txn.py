from dataclasses import dataclass
from typing import Any, Dict, Generic, List, Literal, Mapping, TypeVar, Optional

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
    revocation: Optional[Dict[str, Any]] = None


class CredDefTxnData(BaseModel):
    """Cred Def Transaction txn.data."""

    data: CredDefTxnDataData
    ref: int
    signature_type: Literal["CL"]
    tag: str


class RevRegDefTxnDataValue(BaseModel):
    """Rev Reg Def Transaction txn.data.value."""

    issuance_type: Literal["ISSUANCE_BY_DEFAULT"] = Field(alias="issuanceType")
    max_cred_num: int = Field(alias="maxCredNum")
    public_keys: Any = Field(alias="publicKeys")
    tails_hash: str = Field(alias="tailsHash")
    tails_location: str = Field(alias="tailsLocation")


class RevRegDefTxnData(BaseModel):
    """Rev Reg Def Transaction txn.data."""

    cred_def_id: str = Field(alias="credDefId")
    id: str
    revoc_def_type: Literal["CL_ACCUM"] = Field(alias="revocDefType")
    tag: str
    value: RevRegDefTxnDataValue


class RevRegEntryTxnDataValue(BaseModel):
    """Rev Reg Entry Value."""

    accum: str
    prev_accum: str | None = Field(None, alias="prevAccum")
    revoked: list[int] | None = None


class RevRegEntryTxnData(BaseModel):
    """Rev Reg Entry Transaction txn.data."""

    revoc_def_type: Literal["CL_ACCUM"] = Field(alias="revocDefType")
    revoc_reg_def_id: str = Field(alias="revocRegDefId")
    value: RevRegEntryTxnDataValue


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


SchemaDeref = DereferenceResult[SchemaTxnDataData, GetSchemaReply]


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


CredDefDeref = DereferenceResult[CredDefTxnDataData, GetCredDefReply]


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


RevRegDefDeref = DereferenceResult[RevRegDefTxnData, GetRevRegDefReply]


@dataclass
class Endorsement:
    nym: str
    signature: bytes


class NymOperation(BaseModel):
    """Transaction Requst operation for Nym."""

    dest: str
    type: Literal["1"]
    verkey: str
    version: Literal[0, 1, 2]


class SchemaOperation(SchemaTxnData):
    """Operation data for Schema transaction request."""

    type: Literal["101"]


class CredDefOperation(CredDefTxnData):
    """Operation data for Cred Def transaction request."""

    type: Literal["102"]


class RevRegDefOperation(RevRegDefTxnData):
    """Operation data for Rev Reg Def transaction request."""

    type: Literal["113"]


class RevRegEntryOperation(RevRegEntryTxnData):
    """Operation data for Rev Reg Entry transaction request."""

    type: Literal["114"]


Op = TypeVar("Op", bound=BaseModel)


class TxnRequest(BaseModel, Generic[Op]):
    """Transaction Request."""

    identifier: str
    operation: Op
    protocolVersion: Literal[2]
    reqId: int
    endorser: str | None = None
    signature: str | None = None
    signatures: Mapping[str, str] | None = None
    taaAcceptanc: TaaAcceptance | None = None
