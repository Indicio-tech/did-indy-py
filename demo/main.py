"""Demo script."""

import asyncio
from dataclasses import dataclass
from time import time
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

from did_indy.author.author import Author, AuthorDependencies
from did_indy.author.lite import AuthorLite
from did_indy.cache import BasicCache
from did_indy.client.client import IndyDriverAdminClient, IndyDriverClient
from did_indy.ledger import LedgerPool, fetch_genesis_transactions
from did_indy.signer import Signer


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
    author = AuthorLite(client, nym.key.sign_message)
    result = await author.create_nym(NAMESPACE, nym.verkey, taa=taa)
    did = result.did

    schema = Schema.create(
        name="test", version="1.0", issuer_id=did, attr_names=["firstname", "lastname"]
    )
    result = await author.register_schema(schema, taa)

    cred_def, private, proof = CredentialDefinition.create(
        schema_id=result.schema_id,
        schema=schema,
        issuer_id=did,
        tag="test",
        signature_type="CL",
        support_revocation=True,
    )
    result = await author.register_cred_def(cred_def, taa)

    rev_reg_def, private = RevocationRegistryDefinition.create(
        cred_def_id=result.cred_def_id,
        cred_def=cred_def,
        issuer_id=did,
        tag="0",
        registry_type="CL_ACCUM",
        max_cred_num=1000,
    )
    result = await author.register_rev_reg_def(rev_reg_def, taa)

    rev_reg_def_id = result.rev_reg_def_id
    revocation_list = RevocationStatusList.create(
        cred_def=cred_def,
        rev_reg_def_id=rev_reg_def_id,
        rev_reg_def=rev_reg_def,
        rev_reg_def_private=private,
        issuer_id=did,
    )
    result = await author.register_rev_status_list(revocation_list, taa)

    next_list = revocation_list.update(
        cred_def=cred_def,
        rev_reg_def=rev_reg_def,
        rev_reg_def_private=private,
        issued=None,
        revoked=[1],
        timestamp=int(time()),
    )

    result = await author.update_rev_status_list(
        prev_list=revocation_list,
        curr_list=next_list,
        revoked=[1],
        taa=taa,
    )


class AuthorDependenciesBasic(AuthorDependencies):
    def __init__(self, key: Key, pool: LedgerPool):
        self.key = key
        self.pool = pool

    async def get_signer(self, did: str) -> Signer:
        return self.key.sign_message

    async def get_pool(self, namespace: str) -> LedgerPool:
        return self.pool


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
    pool = LedgerPool(
        NAMESPACE,
        genesis_transactions=await fetch_genesis_transactions(
            "https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_testnet_genesis"
        ),
        cache=BasicCache(),
    )

    author = Author(client, AuthorDependenciesBasic(nym.key, pool))
    result = await author.create_nym(NAMESPACE, nym.verkey, taa=taa)
    did = result.did

    schema = Schema.create(
        name="test",
        version="1.0",
        attr_names=["firstname", "lastname"],
        issuer_id=did,
    )
    result = await author.register_schema(schema, taa)

    cred_def, private, proof = CredentialDefinition.create(
        schema_id=result.schema_id,
        schema=schema,
        issuer_id=did,
        tag="test",
        signature_type="CL",
        support_revocation=True,
    )
    result = await author.register_cred_def(cred_def, taa)

    rev_reg_def, private = RevocationRegistryDefinition.create(
        cred_def_id=result.cred_def_id,
        cred_def=cred_def,
        issuer_id=did,
        tag="0",
        registry_type="CL_ACCUM",
        max_cred_num=1000,
    )
    result = await author.register_rev_reg_def(rev_reg_def, taa)

    rev_reg_def_id = result.rev_reg_def_id
    revocation_list = RevocationStatusList.create(
        cred_def=cred_def,
        rev_reg_def_id=rev_reg_def_id,
        rev_reg_def=rev_reg_def,
        rev_reg_def_private=private,
        issuer_id=did,
    )
    result = await author.register_rev_status_list(revocation_list, taa)

    next_list = revocation_list.update(
        cred_def=cred_def,
        rev_reg_def=rev_reg_def,
        rev_reg_def_private=private,
        issued=None,
        revoked=[1],
        timestamp=int(time()),
    )

    result = await author.update_rev_status_list(
        prev_list=revocation_list,
        curr_list=next_list,
        revoked=[1],
        taa=taa,
    )


if __name__ == "__main__":
    asyncio.run(thin())
    asyncio.run(thick())
