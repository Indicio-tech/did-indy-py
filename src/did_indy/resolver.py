"""Resolver interfaces."""

import json
from typing import (
    Any,
    Awaitable,
    Mapping,
    Protocol,
)

from indy_vdr import VdrError
from indy_vdr.bindings import resolve

from did_indy.anoncreds import (
    make_cred_def_id_from_indy,
    make_indy_rev_reg_def_id_from_did_url,
    make_schema_id,
)
from did_indy.did import (
    parse_did_indy_from_url,
    parse_namespace_from_did,
    parse_namespace_from_did_url,
)
from did_indy.ledger import ClosedPoolError, LedgerPool, ReadOnlyLedger
from did_indy.models.anoncreds import (
    CredDef,
    RevRegDef,
    RevRegDefValue,
    RevStatusList,
    Schema,
)
from did_indy.models.txn.deref import CredDefDeref, RevRegDefDeref, SchemaDeref


class ResolverError(Exception):
    """Raised on error in resolver."""


class ResolverProto(Protocol):
    """Resolver protocol."""

    async def resolve_did(self, did: str) -> Mapping[str, Any]:
        """Resolve a did:indy DID."""
        ...

    async def get_schema(self, schema_id: str) -> tuple[Schema, SchemaDeref]:
        """Retrieve schema by ID (DID URL)."""
        ...

    async def get_cred_def(self, cred_def_id: str) -> tuple[CredDef, CredDefDeref]:
        """Retrieve cred def by ID (DID URL)."""
        ...

    async def get_rev_reg_def(
        self, rev_reg_def_id: str
    ) -> tuple[RevRegDef, RevRegDefDeref]:
        """Retrieve a rev reg def by ID (DID URL)."""
        ...

    async def get_rev_status_list(
        self,
        rev_reg_def_id: str,
        timestamp_from: int | None = 0,
        timestamp_to: int | None = None,
    ) -> RevStatusList:
        """Retrieve a rev status list by rev reg def id and time range."""
        ...


class PoolProvider(Protocol):
    """Pool provider protocol."""

    def get_pool(self, namespace: str) -> LedgerPool | Awaitable[LedgerPool]:
        """Retrieve the pool for a namespace."""
        ...


class Resolver(ResolverProto):
    """DID Indy Resolver."""

    def __init__(self, pool_provider: PoolProvider):
        """Init resolver provider."""
        self.pool_provider = pool_provider

    async def get_pool(self, namespace: str) -> LedgerPool:
        """Get pool for namespace."""
        pool = self.pool_provider.get_pool(namespace)
        if not isinstance(pool, LedgerPool):
            pool = await pool

        return pool

    async def resolve_did(self, did: str) -> Mapping[str, Any]:
        """Resolve a did:indy DID."""
        pool = await self.get_pool(parse_namespace_from_did(did))
        async with PoolResolver(pool) as resolver:
            return await resolver.resolve_did(did)

    async def get_schema(self, schema_id: str) -> tuple[Schema, SchemaDeref]:
        """Retrieve schema by ID (DID URL)."""
        pool = await self.get_pool(parse_namespace_from_did_url(schema_id))
        async with PoolResolver(pool) as resolver:
            return await resolver.get_schema(schema_id)

    async def get_cred_def(self, cred_def_id: str) -> tuple[CredDef, CredDefDeref]:
        """Retrieve cred def by ID (DID URL)."""
        pool = await self.get_pool(parse_namespace_from_did_url(cred_def_id))
        async with PoolResolver(pool) as resolver:
            return await resolver.get_cred_def(cred_def_id)

    async def get_rev_reg_def(
        self, rev_reg_def_id: str
    ) -> tuple[RevRegDef, RevRegDefDeref]:
        """Retrieve a rev reg def by ID (DID URL)."""
        pool = await self.get_pool(parse_namespace_from_did_url(rev_reg_def_id))
        async with PoolResolver(pool) as resolver:
            return await resolver.get_rev_reg_def(rev_reg_def_id)

    async def get_rev_status_list(
        self,
        rev_reg_def_id: str,
        timestamp_from: int | None = 0,
        timestamp_to: int | None = None,
    ) -> RevStatusList:
        """Retrieve a rev status list by rev reg def id and time range."""
        pool = await self.get_pool(parse_namespace_from_did_url(rev_reg_def_id))
        async with PoolResolver(pool) as resolver:
            return await resolver.get_rev_status_list(
                rev_reg_def_id, timestamp_from, timestamp_to
            )


class PoolResolver(ResolverProto):
    """Resolver interface for a specific LedgerPool."""

    def __init__(self, pool: LedgerPool):
        self.pool = pool

    async def __aenter__(self: "PoolResolver") -> "PoolResolver":
        """Context manager entry.

        Returns:
            The current instance

        """
        await self.pool.context_open()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit."""
        await self.pool.context_close()

    async def resolve_did(self, did: str) -> Mapping[str, Any]:
        """Resolve a did:indy DID."""
        if not self.pool.handle or not self.pool.handle.handle:
            raise ClosedPoolError(f"Cannot resolve from closed pool '{self.pool.name}'")

        try:
            result = json.loads(await resolve(self.pool.handle.handle, did))  # pyright: ignore
        except VdrError as err:
            raise ResolverError("Ledger request error") from err
        return result

    async def get_schema(self, schema_id: str) -> tuple[Schema, SchemaDeref]:
        """Retrieve schema by ID (DID URL)."""
        ledger = ReadOnlyLedger(self.pool)  # pool should already be open
        deref = await ledger.deref_schema(schema_id)
        did_indy = parse_did_indy_from_url(schema_id)
        return Schema(
            issuer_id=did_indy.did,
            attr_names=deref.contentStream.attr_names,
            name=deref.contentStream.name,
            version=deref.contentStream.version,
        ), deref

    async def _get_or_fetch_schema_id_by_seq_no(
        self, ledger: ReadOnlyLedger, namespace: str, seq_no: int
    ) -> str:
        """Retrieve schema id by seqNo from cache or ledger."""
        cache = self.pool.cache
        cache_key = f"schema_id_by_seq_no::{namespace}::{seq_no}"

        schema_id = await cache.get(cache_key)
        if schema_id:
            return schema_id

        schema_ish = await ledger.get_schema_by_seq_no(seq_no)

        schema_nym = schema_ish.identifier
        schema_data = schema_ish.data.txn.data.data
        schema_issuer_id = f"did:indy:{namespace}:{schema_nym}"

        schema_id = make_schema_id(
            issuer_id=schema_issuer_id,
            name=schema_data.name,
            version=schema_data.version,
        )
        return schema_id

    async def get_cred_def(self, cred_def_id: str) -> tuple[CredDef, CredDefDeref]:
        """Retrieve cred def by ID (DID URL).

        Returning a CredDef is complicated because of needing to determine the full
        schema_id when only the seqNo of the schema is found in the cred def dereference
        result as `ref`. It is further complicated by the data structure of the result of
        retrieving a txn by seqNo is very different from the structure of a dereferenced
        schema. So lots of shuffling and mapping pieces onto each other is required.
        """
        did_indy = parse_did_indy_from_url(cred_def_id)
        ledger = ReadOnlyLedger(self.pool)  # pool should already be open
        deref = await ledger.deref_cred_def(cred_def_id)
        schema_id = await self._get_or_fetch_schema_id_by_seq_no(
            ledger, did_indy.namespace, deref.contentMetadata.nodeResponse.result.ref
        )

        return CredDef(
            issuer_id=did_indy.did,
            schema_id=schema_id,
            type="CL",
            tag=deref.contentMetadata.nodeResponse.result.tag,
            value=deref.contentMetadata.nodeResponse.result.data.model_dump(),
        ), deref

    async def get_rev_reg_def(
        self, rev_reg_def_id: str
    ) -> tuple[RevRegDef, RevRegDefDeref]:
        """Retrieve a rev reg def by ID (DID URL)."""
        ledger = ReadOnlyLedger(self.pool)  # pool should already be open
        deref = await ledger.deref_rev_reg_def(rev_reg_def_id)
        did_indy = parse_did_indy_from_url(rev_reg_def_id)
        cred_def_id = make_cred_def_id_from_indy(
            did_indy.namespace, deref.contentStream.cred_def_id
        )
        value = deref.contentStream.value
        return RevRegDef(
            issuer_id=did_indy.did,
            revoc_def_type="CL_ACCUM",
            cred_def_id=cred_def_id,
            tag=deref.contentStream.tag,
            value=RevRegDefValue(
                max_cred_num=value.max_cred_num,
                public_keys=value.public_keys,
                tails_hash=value.tails_hash,
                tails_location=value.tails_location,
            ),
        ), deref

    def _indexes_to_bit_array(self, indexes: list[int], size: int) -> list[int]:
        """Turn a sequence of indexes into a full state bit array."""
        return [1 if index in indexes else 0 for index in range(0, size + 1)]

    async def get_rev_status_list(
        self,
        rev_reg_def_id: str,
        timestamp_from: int | None = 0,
        timestamp_to: int | None = None,
    ) -> RevStatusList:
        """Retrieve a rev status list by rev reg def id and time range."""
        indy_rev_reg_def_id = make_indy_rev_reg_def_id_from_did_url(rev_reg_def_id)
        ledger = ReadOnlyLedger(self.pool)
        delta, timestamp = await ledger.get_revoc_reg_delta(
            indy_rev_reg_def_id=indy_rev_reg_def_id,
            timestamp_from=timestamp_from,
            timestamp_to=timestamp_to,
        )

        max_cred_num = await ledger.get_or_fetch_rev_reg_def_max_cred_num(
            indy_rev_reg_def_id
        )
        revocation_list_from_indexes = self._indexes_to_bit_array(
            delta["value"]["revoked"], max_cred_num
        )
        did_indy = parse_did_indy_from_url(rev_reg_def_id)
        return RevStatusList(
            issuer_id=did_indy.did,
            rev_reg_def_id=rev_reg_def_id,
            revocation_list=revocation_list_from_indexes,
            current_accumulator=delta["value"]["accum"],
            timestamp=timestamp,
        )
