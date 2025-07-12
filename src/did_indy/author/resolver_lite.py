"""Lite resolver implementation."""

from collections.abc import Mapping
from typing import Any

from did_indy.client.client import IndyDriverClient
from did_indy.models.anoncreds import CredDef, RevRegDef, RevStatusList, Schema
from did_indy.resolver import ResolverProto


class ResolverLite(ResolverProto):
    """Lite resolver.

    This resolver relies on a driver for resolving and dereferencing objects.
    This is a very simple class which exists primarily to mirror the full resolver
    interface.
    """

    def __init__(self, client: IndyDriverClient):
        """Init the resolver."""
        self.client = client

    async def resolve_did(self, did: str) -> Mapping[str, Any]:
        """Resolve a DID."""
        return await self.client.resolve_did(did)

    async def get_schema(self, schema_id: str) -> Schema:
        """Dereference a schema."""
        return await self.client.dereference_schema(schema_id)

    async def get_cred_def(self, cred_def_id: str) -> CredDef:
        """Dereference a cred def."""
        return await self.client.dereference_cred_def(cred_def_id)

    async def get_rev_reg_def(self, rev_reg_def_id: str) -> RevRegDef:
        """Dereference a rev reg def."""
        return await self.client.dereference_rev_reg_def(rev_reg_def_id)

    async def get_rev_status_list(
        self,
        rev_reg_def_id: str,
        timestamp_from: int | None = 0,
        timestamp_to: int | None = None,
    ) -> RevStatusList:
        """Resolve a revocation status list."""
        return await self.client.resolve_rev_status_list(
            rev_reg_def_id, timestamp_from, timestamp_to
        )
