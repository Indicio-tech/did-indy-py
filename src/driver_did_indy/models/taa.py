from dataclasses import dataclass


@dataclass
class TAARecord:
    text: str
    version: str
    digest: str


@dataclass
class TAAInfo:
    aml: dict
    taa: TAARecord | None
    required: bool


@dataclass
class TaaAcceptance:
    """TAA Acceptance data."""

    taaDigest: str
    mechanism: str
    time: int
