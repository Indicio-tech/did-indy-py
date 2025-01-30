"""DID Parsing and DID/Nym utils."""

from dataclasses import dataclass
from hashlib import sha256

from base58 import b58decode, b58encode


@dataclass
class DidIndy:
    """Parsed did:indy DID."""

    namespace: str
    nym: str


def parse_did_indy(did: str) -> DidIndy:
    """Extract info from a did:indy DID."""
    method_and_namespace, nym = did.rsplit(":", maxsplit=1)
    namespace = method_and_namespace.removeprefix("did:indy:")
    return DidIndy(namespace, nym)


def nym_from_verkey(verkey: str, version: int = 2) -> str:
    """Generate a nym from a verkey."""
    key = b58decode(verkey)
    if version == 2:
        nym = b58encode(sha256(key).digest()[:16]).decode()
    else:
        nym = b58encode(key[:16]).decode()
    return nym
