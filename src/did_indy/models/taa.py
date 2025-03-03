"""TAA Models."""

from pydantic import AliasChoices, BaseModel, Field


class TAARecord(BaseModel):
    text: str
    version: str
    digest: str


class TAAInfo(BaseModel):
    aml: dict
    taa: TAARecord | None
    required: bool


class TaaAcceptance(BaseModel):
    """TAA Acceptance data."""

    taaDigest: str = Field(
        validation_alias=AliasChoices("taa_digest", "digest", "taaDigest"),
        serialization_alias="taaDigest",
    )
    mechanism: str
    time: int

    def for_request(self):
        """Return TAA Acceptance for use in a request."""
        return self.model_dump()
