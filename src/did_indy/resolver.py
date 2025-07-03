"""Resolver interfaces."""

import json

from indy_vdr import VdrError
from indy_vdr.bindings import dereference, resolve

from did_indy.ledger import ClosedPoolError, LedgerPool
from did_indy.models.txn import CredDefDeref, RevRegDefDeref, SchemaDeref


class ResolverError(Exception):
    """Raised on error in resolver."""


class Resolver:
    """Resolver interface."""

    def __init__(self, pool: LedgerPool):
        self.pool = pool

    async def __aenter__(self: "Resolver") -> "Resolver":
        """Context manager entry.

        Returns:
            The current instance

        """
        await self.pool.context_open()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit."""
        await self.pool.context_close()

    async def resolve(self, did: str) -> dict:
        """Resolve a did:indy DID."""
        if not self.pool.handle or not self.pool.handle.handle:
            raise ClosedPoolError(
                f"Cannot sign and submit request to closed pool '{self.pool.name}'"
            )

        try:
            result = json.loads(await resolve(self.pool.handle.handle, did))  # pyright: ignore
        except VdrError as err:
            raise ResolverError("Ledger request error") from err
        return result

    async def dereference(self, did_url: str) -> dict:
        """Dereference a DID URL to an object."""
        if not self.pool.handle or not self.pool.handle.handle:
            raise ClosedPoolError(
                f"Cannot sign and submit request to closed pool '{self.pool.name}'"
            )

        try:
            result = json.loads(await dereference(self.pool.handle.handle, did_url))
        except VdrError as err:
            raise ResolverError("Ledger request error") from err
        return result

    async def get_schema(self, schema_id: str) -> SchemaDeref:
        """Retrieve schema by ID (DID URL)."""
        result = await self.dereference(schema_id)
        schema_result = SchemaDeref.model_validate(result)
        return schema_result

    async def get_cred_def(self, cred_def_id: str) -> CredDefDeref:
        """Retrieve cred def by ID (DID URL)."""
        result = await self.dereference(cred_def_id)
        cred_def_result = CredDefDeref.model_validate(result)
        return cred_def_result

    async def get_rev_reg_def(self, rev_reg_def_id: str) -> RevRegDefDeref:
        """Retrieve a rev reg def by ID (DID URL)."""
        result = await self.dereference(rev_reg_def_id)
        rev_reg_def_result = RevRegDefDeref.model_validate(result)
        return rev_reg_def_result
