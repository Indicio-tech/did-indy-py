"""AnonCreds models."""

from typing import Any, Dict, List, Literal
from pydantic import AliasChoices, BaseModel, Field


class Schema(BaseModel):
    """Schema Create Model."""

    issuer_id: str = Field(
        validation_alias=AliasChoices("issuerId", "issuer_id"),
        serialization_alias="issuerId",
    )
    attr_names: List[str] = Field(
        validation_alias=AliasChoices("attrNames", "attr_names"),
        serialization_alias="attrNames",
    )
    name: str
    version: str


class CredDef(BaseModel):
    """Cred Def Model."""

    issuer_id: str = Field(
        validation_alias=AliasChoices("issuerId", "issuer_id"),
        serialization_alias="issuerId",
    )
    schema_id: str = Field(
        validation_alias=AliasChoices("schemaId", "schema_id"),
        serialization_alias="schemaId",
    )
    type: Literal["CL"]
    tag: str
    value: Dict[str, Any]
