"""Core data of txns.

These are the values that go inside of transaction requests and results.
"""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class NymTxnData(BaseModel):
    """Nym Transaction txn.data."""

    dest: str
    verkey: str
    version: int


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
