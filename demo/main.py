"""Demo script."""

import sys
import asyncio

from dataclasses import dataclass
import logging
from os import getenv
from secrets import token_bytes
from hashlib import sha256

from anoncreds import CredentialDefinition, Schema
from aries_askar import Key, KeyAlg
from base58 import b58encode
from indy_vdr import ledger
from did_indy_client.client import IndyClient


DRIVER = getenv("DRIVER", "http://driver")
LOG_LEVEL = getenv("LOG_LEVEL", "info")


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


def logging_to_stdout():
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.WARNING,
        format="[%(levelname)s] %(name)s %(message)s",
    )
    logging.getLogger("did_indy_client").setLevel(LOG_LEVEL.upper())


async def thin():
    """Demo a thin client."""
    logging_to_stdout()

    NAMESPACE = "indicio:test"
    client = IndyClient(DRIVER)
    taa_info = await client.get_taa(NAMESPACE)
    taa = await client.accept_taa(taa_info, "on_file")

    nym = generate_nym()
    result = await client.create_nym(NAMESPACE, nym.verkey, taa=taa)
    did = result.did

    schema = Schema.create(
        name="test", version="1.0", issuer_id=did, attr_names=["firstname", "lastname"]
    )
    result = await client.create_schema(schema.to_json(), taa)
    sig = nym.key.sign_message(result.get_signature_input_bytes())
    result = await client.submit_schema(did, result.request, sig)

    cred_def, private, proof = CredentialDefinition.create(
        schema_id=result.schema_id,
        schema=schema,
        issuer_id=did,
        tag="test",
        signature_type="CL",
    )
    result = await client.create_cred_def(cred_def.to_json(), taa=taa)
    sig = nym.key.sign_message(result.get_signature_input_bytes())
    result = await client.submit_cred_def(did, result.request, sig)


async def thick():
    """Demo a thick client."""
    logging_to_stdout()

    NAMESPACE = "indicio:test"
    client = IndyClient(DRIVER)
    taa_info = await client.get_taa(NAMESPACE)
    taa = await client.accept_taa(taa_info, "on_file")

    nym = generate_nym()
    result = await client.create_nym(NAMESPACE, nym.verkey, taa=taa)
    did = result.did

    schema = {
        "ver": "1.0",
        "id": f"{nym.nym2}:2:test:1.0",
        "name": "test",
        "version": "1.0",
        "attrNames": ["firstname", "lastname"],
        "seqNo": None,
    }
    request = ledger.build_schema_request(nym.nym1, schema)
    sig = nym.key.sign_message(request.signature_input)
    result = await client.endorse_schema(did, request.body, sig)

    cred_def, private, proof = CredentialDefinition.create(
        schema_id=f"{nym.nym2}:2:test:1.0",
        schema=schema,
        issuer_id=did,
        tag="test",
        signature_type="CL",
    )
    cred_def = {
        "id": f"{nym.nym2}:3:CL:1000:default",
        "schemaId": "1000",
        "tag": "default",
        "type": "CL",
        "value": cred_def.to_dict(),
        "ver": "1.0",
    }
    request = ledger.build_cred_def_request(nym.nym2, cred_def)
    print(request.body)
    return
    result = await client.create_cred_def(cred_def.to_json(), taa=taa)
    sig = nym.key.sign_message(result.get_signature_input_bytes())
    result = await client.submit_cred_def(did, result.request, sig)


if __name__ == "__main__":
    # asyncio.run(thin())
    asyncio.run(thick())
