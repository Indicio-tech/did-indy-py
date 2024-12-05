"""Demo script."""

import asyncio

from dataclasses import dataclass
from os import getenv
from secrets import token_bytes
from hashlib import sha256

from aries_askar import Key, KeyAlg
from base58 import b58encode
from did_indy_client import IndyClient


DRIVER = getenv("DRIVER", "http://driver-did-indy")


@dataclass
class Nym:
    seed: bytes
    key: Key
    nym1: str
    nym2: str
    verkey: str


def generate_nym():
    """Generate a new nym."""
    seed = token_bytes(32)
    key = Key.from_secret_bytes(KeyAlg.ED25519, seed)
    pub = key.get_public_bytes()
    nym1 = b58encode(pub[:16]).decode()
    nym2 = b58encode(sha256(pub).digest()[:16]).decode()
    verkey = b58encode(pub).decode()

    return Nym(seed, key, nym1, nym2, verkey)


async def main():
    """Demo script main entrypoint."""
    NAMESPACE = "indicio:test"
    client = IndyClient(DRIVER)
    taa_info = await client.get_taa(NAMESPACE)
    taa = await client.accept_taa(taa_info, "on_file")
    nym = generate_nym()
    result = await client.create_nym(NAMESPACE, nym.verkey, taa=taa)
    print(result)
    did = result.did
    result = await client.create_schema(
        did, ["firstname", "lastname"], "test", "1.0", taa
    )
    print(result)
    sig = nym.key.sign_message(result.get_signature_input_bytes())
    result = await client.submit(did, result.request, sig)
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
