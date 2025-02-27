"""Demo script."""

import asyncio
from dataclasses import dataclass
from hashlib import sha256
import logging
from os import getenv
from secrets import token_bytes
import sys

from anoncreds import (
    CredentialDefinition,
    RevocationRegistryDefinition,
    RevocationStatusList,
    Schema,
)
from aries_askar import Key, KeyAlg
from base58 import b58encode

from did_indy.client.client import IndyDriverAdminClient, IndyDriverClient
from did_indy.anoncreds import (
    indy_cred_def_request,
    indy_schema_request,
    make_schema_id_from_schema,
)


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
    logging.getLogger("did_indy").setLevel(LOG_LEVEL.upper())


async def thin():
    """Demo a thin client."""
    logging_to_stdout()

    admin = IndyDriverAdminClient(DRIVER, admin_api_key="insecure-api-key")
    token = (
        await admin.create_client(
            "test",
            schemas=True,
            cred_defs=True,
        )
    ).token
    client = IndyDriverClient(DRIVER, client_token=token)

    NAMESPACE = "indicio:test"
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
        support_revocation=True,
    )
    result = await client.create_cred_def(cred_def.to_json(), taa=taa)
    sig = nym.key.sign_message(result.get_signature_input_bytes())
    result = await client.submit_cred_def(did, result.request, sig)

    rev_reg_def, private = RevocationRegistryDefinition.create(
        cred_def_id=result.cred_def_id,
        cred_def=cred_def,
        issuer_id=did,
        tag="0",
        registry_type="CL_ACCUM",
        max_cred_num=1000,
    )
    result = await client.create_rev_reg_def(rev_reg_def.to_json(), taa=taa)
    sig = nym.key.sign_message(result.get_signature_input_bytes())
    result = await client.submit_rev_reg_def(did, result.request, sig)

    revocation_list = RevocationStatusList.create(
        cred_def=cred_def,
        rev_reg_def_id=result.rev_reg_def_id,
        rev_reg_def=rev_reg_def,
        rev_reg_def_private=private,
        issuer_id=did,
    )
    result = await client.create_rev_status_list(revocation_list.to_dict(), taa=taa)
    sig = nym.key.sign_message(result.get_signature_input_bytes())
    result = await client.submit_rev_status_list(did, result.request, sig)
    print(result)


async def thick():
    """Demo a thick client."""
    logging_to_stdout()

    admin = IndyDriverAdminClient(DRIVER, admin_api_key="insecure-api-key")
    token = (
        await admin.create_client(
            "test",
            schemas=True,
            cred_defs=True,
        )
    ).token
    client = IndyDriverClient(DRIVER, client_token=token)

    NAMESPACE = "indicio:test"
    taa_info = await client.get_taa(NAMESPACE)
    taa = await client.accept_taa(taa_info, "on_file")

    nym = generate_nym()
    result = await client.create_nym(NAMESPACE, nym.verkey, taa=taa)
    did = result.did

    schema = Schema.create(
        name="test",
        version="1.0",
        attr_names=["firstname", "lastname"],
        issuer_id=did,
    )
    request = indy_schema_request(schema)
    if taa:
        request.set_txn_author_agreement_acceptance(taa.for_request())

    endorsement = await client.endorse_schema(did, request.body)
    request.set_endorser(endorsement.nym)

    sig = nym.key.sign_message(request.signature_input)
    request.set_signature(sig)
    request.set_multi_signature(endorsement.nym, endorsement.get_signature_bytes())

    schema_id = make_schema_id_from_schema(schema)
    cred_def, private, proof = CredentialDefinition.create(
        schema_id=schema_id,
        schema=schema,
        issuer_id=did,
        tag="test",
        signature_type="CL",
    )
    request = indy_cred_def_request(1000, cred_def)
    if taa:
        request.set_txn_author_agreement_acceptance(taa.for_request())

    endorsement = await client.endorse_schema(did, request.body)
    request.set_endorser(endorsement.nym)

    sig = nym.key.sign_message(request.signature_input)
    request.set_signature(sig)
    request.set_multi_signature(endorsement.nym, endorsement.get_signature_bytes())


if __name__ == "__main__":
    asyncio.run(thin())
    asyncio.run(thick())
