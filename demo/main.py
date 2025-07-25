"""Demo script."""

import asyncio
import logging
import sys
from dataclasses import dataclass
from hashlib import sha256
from os import getenv
from secrets import token_bytes
from time import time

from anoncreds import (
    CredentialDefinition,
    RevocationRegistryDefinition,
    RevocationStatusList,
    Schema,
)
from aries_askar import Key, KeyAlg
from base58 import b58encode

from did_indy.author.author import Author, AuthorDependencies
from did_indy.author.lite import AuthorLite, AuthorLiteDependencies
from did_indy.author.resolver_lite import ResolverLite
from did_indy.cache import BasicCache
from did_indy.client.client import IndyDriverAdminClient, IndyDriverClient
from did_indy.ledger import LedgerPool, fetch_genesis_transactions
from did_indy.models.taa import TaaAcceptance
from did_indy.resolver import Resolver
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


def get_signer(key: Key):
    """Return a signer."""

    async def _signer(signature_input: bytes) -> bytes:
        """Signer protocol implementer for key."""
        return key.sign_message(signature_input)

    return _signer


class AuthorLiteDependenciesBasic(AuthorLiteDependencies):
    def __init__(self, key: Key, taa: TaaAcceptance | None = None):
        self.key = key
        self.taa = taa

    async def get_signer(self, did: str) -> Signer:
        return self.key.sign_message  # type: ignore

    async def get_taa(self, namespace: str) -> TaaAcceptance | None:
        return self.taa


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
    author = AuthorLite(client, AuthorLiteDependenciesBasic(nym.key, taa))
    resolver = ResolverLite(client)

    result = await author.create_nym(NAMESPACE, nym.verkey)
    did = result.did
    await resolver.resolve_did(did)

    schema = Schema.create(
        name="test", version="1.0", issuer_id=did, attr_names=["firstname", "lastname"]
    )
    result = await author.register_schema(schema)
    await resolver.get_schema(result.schema_id)

    cred_def, private, proof = CredentialDefinition.create(
        schema_id=result.schema_id,
        schema=schema,
        issuer_id=did,
        tag="test",
        signature_type="CL",
        support_revocation=True,
    )
    result = await author.register_cred_def(cred_def)
    await resolver.get_cred_def(result.cred_def_id)

    rev_reg_def, private = RevocationRegistryDefinition.create(
        cred_def_id=result.cred_def_id,
        cred_def=cred_def,
        issuer_id=did,
        tag="0",
        registry_type="CL_ACCUM",
        max_cred_num=1000,
    )
    result = await author.register_rev_reg_def(rev_reg_def)
    await resolver.get_rev_reg_def(result.rev_reg_def_id)

    rev_reg_def_id = result.rev_reg_def_id
    revocation_list = RevocationStatusList.create(
        cred_def=cred_def,
        rev_reg_def_id=rev_reg_def_id,
        rev_reg_def=rev_reg_def,
        rev_reg_def_private=private,
        issuer_id=did,
    )
    result = await author.register_rev_status_list(revocation_list)
    await resolver.get_rev_status_list(rev_reg_def_id)

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
    )
    await resolver.get_rev_status_list(rev_reg_def_id)


class AuthorDependenciesBasic(AuthorDependencies):
    def __init__(self, key: Key, pool: LedgerPool, taa: TaaAcceptance | None = None):
        self.key = key
        self.pool = pool
        self.taa = taa

    async def get_signer(self, did: str) -> Signer:
        return self.key.sign_message  # type: ignore

    async def get_pool(self, namespace: str) -> LedgerPool:
        return self.pool

    async def get_taa(self, namespace: str) -> TaaAcceptance | None:
        return self.taa


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

    deps = AuthorDependenciesBasic(nym.key, pool, taa)
    author = Author(client, deps)
    resolver = Resolver(deps)
    result = await author.create_nym(NAMESPACE, nym.verkey)
    did = result.did
    await resolver.resolve_did(did)

    schema = Schema.create(
        name="test",
        version="1.0",
        attr_names=["firstname", "lastname"],
        issuer_id=did,
    )
    result = await author.register_schema(schema)
    await resolver.get_schema(result.schema_id)

    cred_def, private, proof = CredentialDefinition.create(
        schema_id=result.schema_id,
        schema=schema,
        issuer_id=did,
        tag="test",
        signature_type="CL",
        support_revocation=True,
    )
    result = await author.register_cred_def(cred_def)
    await resolver.get_cred_def(result.cred_def_id)

    rev_reg_def, private = RevocationRegistryDefinition.create(
        cred_def_id=result.cred_def_id,
        cred_def=cred_def,
        issuer_id=did,
        tag="0",
        registry_type="CL_ACCUM",
        max_cred_num=1000,
    )
    result = await author.register_rev_reg_def(rev_reg_def)
    await resolver.get_rev_reg_def(result.rev_reg_def_id)

    rev_reg_def_id = result.rev_reg_def_id
    revocation_list = RevocationStatusList.create(
        cred_def=cred_def,
        rev_reg_def_id=rev_reg_def_id,
        rev_reg_def=rev_reg_def,
        rev_reg_def_private=private,
        issuer_id=did,
    )
    result = await author.register_rev_status_list(revocation_list)
    await resolver.get_rev_status_list(rev_reg_def_id)

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
    )
    await resolver.get_rev_status_list(rev_reg_def_id)


if __name__ == "__main__":
    asyncio.run(thin())
    asyncio.run(thick())
