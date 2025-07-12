"""DID Parsing and DID/Nym utils."""

import re
from dataclasses import dataclass
from hashlib import sha256

from base58 import b58decode, b58encode


@dataclass
class DidIndy:
    """Parsed did:indy DID."""

    namespace: str
    nym: str
    did: str


def parse_namespace_from_did(did: str) -> str:
    """Extract namespace from did."""
    if not did.startswith("did:indy:"):
        raise ValueError(f"{did} is not a did:indy")

    method_and_namespace, _ = did.rsplit(":", maxsplit=1)
    namespace = method_and_namespace.removeprefix("did:indy:")
    return namespace


def strip_url(did_url: str) -> str:
    """Extract did portion of a did url."""
    did, _ = re.split(r"/|\?|#", did_url, maxsplit=1)
    return did


def parse_namespace_from_did_url(did_url: str) -> str:
    """Extract namespace from did url."""
    if not did_url.startswith("did:indy:"):
        raise ValueError(f"{did_url} is not a did:indy URL")

    did = strip_url(did_url)
    return parse_namespace_from_did(did)


def parse_did_indy(did: str) -> DidIndy:
    """Extract info from a did:indy DID."""
    if not did.startswith("did:indy:"):
        raise ValueError(f"{did} is not a did:indy")

    method_and_namespace, nym = did.rsplit(":", maxsplit=1)
    namespace = method_and_namespace.removeprefix("did:indy:")
    return DidIndy(namespace, nym, did)


def parse_did_indy_from_url(did_url: str) -> DidIndy:
    """Extract did:indy DID from url."""
    if not did_url.startswith("did:indy:"):
        raise ValueError(f"{did_url} is not a did:indy URL")

    did = strip_url(did_url)
    method_and_namespace, nym = did.rsplit(":", maxsplit=1)
    namespace = method_and_namespace.removeprefix("did:indy:")
    return DidIndy(namespace, nym, did)


def nym_from_verkey(verkey: str, version: int = 2) -> str:
    """Generate a nym from a verkey."""
    key = b58decode(verkey)
    if version == 2:
        nym = b58encode(sha256(key).digest()[:16]).decode()
    else:
        nym = b58encode(key[:16]).decode()
    return nym
