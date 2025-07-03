"""Models for representing endorsement."""

from dataclasses import dataclass


@dataclass
class Endorsement:
    nym: str
    signature: bytes
