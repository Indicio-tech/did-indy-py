"""TAA Models."""

from pydantic import BaseModel


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

    taaDigest: str
    mechanism: str
    time: int

    def for_request(self):
        """Return TAA Acceptance for use in a request."""
        return self.model_dump()
