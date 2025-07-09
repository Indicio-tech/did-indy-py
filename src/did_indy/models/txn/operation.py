"""Txn requests for operations."""

from typing import Generic, Literal, Mapping, TypeVar

from pydantic import BaseModel

from did_indy.models.taa import TaaAcceptance

from .data import CredDefTxnData, RevRegDefTxnData, RevRegEntryTxnData, SchemaTxnData


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
