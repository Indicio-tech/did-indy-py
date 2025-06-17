"""Lite Author implementation."""

from did_indy.author.base import BaseAuthor
from did_indy.anoncreds import (
    CredDefTypes,
    RevRegDefTypes,
    RevStatusListTypes,
    SchemaTypes,
    normalize_cred_def_representation,
    normalize_rev_reg_def_representation,
    normalize_rev_status_list_representation,
    normalize_schema_representation,
)
from did_indy.client.client import IndyDriverClient
from did_indy.driver.api.txns import (
    CredDefSubmitResponse,
    NymResponse,
    RevRegDefSubmitResponse,
    RevStatusListSubmitResponse,
    SchemaSubmitResponse,
)
from did_indy.signer import Signer, sign_message
from did_indy.models.taa import TaaAcceptance


class AuthorLite(BaseAuthor):
    """Lite Author.

    This Author relies on the driver for building, endorsing, and submitting transactions.
    """

    def __init__(self, client: IndyDriverClient, signer: Signer):
        """Init the author."""
        self.client = client
        self.signer = signer

    async def create_nym(
        self,
        namespace: str,
        verkey: str,
        diddoc_content: str | None = None,
        taa: TaaAcceptance | None = None,
    ) -> NymResponse:
        """Publish a DID, generated from a verkey, with additional DID Doc content."""
        return await self.client.create_nym(
            namespace, verkey, diddoc_content=diddoc_content, taa=taa
        )

    async def register_schema(
        self,
        schema: SchemaTypes,
        taa: TaaAcceptance | None = None,
    ) -> SchemaSubmitResponse:
        """Register a schema."""
        schema = normalize_schema_representation(schema)
        txn = await self.client.create_schema(schema.model_dump(), taa)
        sig = await sign_message(self.signer, txn.get_signature_input_bytes())
        result = await self.client.submit_schema(schema.issuer_id, txn.request, sig)
        return result

    async def register_cred_def(
        self,
        cred_def: CredDefTypes,
        taa: TaaAcceptance | None = None,
    ) -> CredDefSubmitResponse:
        """Register a credential definition."""
        cred_def = normalize_cred_def_representation(cred_def)
        txn = await self.client.create_cred_def(cred_def.model_dump(), taa)
        sig = await sign_message(self.signer, txn.get_signature_input_bytes())
        result = await self.client.submit_cred_def(cred_def.issuer_id, txn.request, sig)
        return result

    async def register_rev_reg_def(
        self,
        rev_reg_def: RevRegDefTypes,
        taa: TaaAcceptance | None = None,
    ) -> RevRegDefSubmitResponse:
        """Register a revocation registry definition."""
        rev_reg_def = normalize_rev_reg_def_representation(rev_reg_def)
        txn = await self.client.create_rev_reg_def(rev_reg_def.model_dump(), taa)
        sig = await sign_message(self.signer, txn.get_signature_input_bytes())
        result = await self.client.submit_rev_reg_def(
            rev_reg_def.issuer_id, txn.request, sig
        )
        return result

    async def register_rev_status_list(
        self,
        rev_status_list: RevStatusListTypes,
        taa: TaaAcceptance | None = None,
    ) -> RevStatusListSubmitResponse:
        """Register a revocation status list."""
        rev_status_list = normalize_rev_status_list_representation(rev_status_list)
        txn = await self.client.create_rev_status_list(
            rev_status_list.model_dump(), taa
        )
        sig = await sign_message(self.signer, txn.get_signature_input_bytes())
        result = await self.client.submit_rev_status_list(
            rev_status_list.issuer_id, txn.request, sig
        )
        return result

    async def update_rev_status_list(
        self,
        prev_list: RevStatusListTypes,
        curr_list: RevStatusListTypes,
        revoked: list[int],
        taa: TaaAcceptance | None = None,
    ) -> RevStatusListSubmitResponse:
        """Update a revocation status list."""
        prev_list = normalize_rev_status_list_representation(prev_list)
        curr_list = normalize_rev_status_list_representation(curr_list)
        txn = await self.client.update_rev_status_list(
            prev_list.current_accumulator, curr_list.model_dump(), revoked, taa
        )
        sig = await sign_message(self.signer, txn.get_signature_input_bytes())
        result = await self.client.submit_rev_status_list_update(
            curr_list.issuer_id, txn.request, sig
        )
        return result
