"""Author Base Protocol definition."""

from typing import Protocol

from did_indy.anoncreds import (
    CredDefTypes,
    RevRegDefTypes,
    RevStatusListTypes,
    SchemaTypes,
)
from did_indy.driver.api.txns import (
    CredDefSubmitResponse,
    NymResponse,
    RevRegDefSubmitResponse,
    RevStatusListSubmitResponse,
    SchemaSubmitResponse,
)
from did_indy.models.taa import TaaAcceptance


class BaseAuthor(Protocol):
    """Base protocol for Author classes."""

    async def create_nym(
        self,
        namespace: str,
        verkey: str,
        nym: str | None = None,
        diddoc_content: str | None = None,
        version: int | None = None,
        taa: TaaAcceptance | None = None,
    ) -> NymResponse:
        """Publish a DID, generated from a verkey, with additional DID Doc content."""
        ...

    async def register_schema(
        self,
        schema: SchemaTypes,
        taa: TaaAcceptance | None = None,
    ) -> SchemaSubmitResponse:
        """Register a schema."""
        ...

    async def register_cred_def(
        self,
        cred_def: CredDefTypes,
        taa: TaaAcceptance | None = None,
    ) -> CredDefSubmitResponse:
        """Register a credential definition."""
        ...

    async def register_rev_reg_def(
        self,
        rev_reg_def: RevRegDefTypes,
        taa: TaaAcceptance | None = None,
    ) -> RevRegDefSubmitResponse:
        """Register a revocation registry definition."""
        ...

    async def register_rev_status_list(
        self,
        rev_status_list: RevStatusListTypes,
        taa: TaaAcceptance | None = None,
    ) -> RevStatusListSubmitResponse:
        """Register a revocation status list."""
        ...

    async def update_rev_status_list(
        self,
        prev_list: RevStatusListTypes,
        curr_list: RevStatusListTypes,
        revoked: list[int],
        taa: TaaAcceptance | None = None,
    ) -> RevStatusListSubmitResponse:
        """Update a revocation status list."""
        ...
