"""Ledger capable author."""

import logging
from typing import Protocol


from did_indy.anoncreds import (
    CredDefTypes,
    RevRegDefTypes,
    RevStatusListTypes,
    SchemaTypes,
    indy_cred_def_request,
    indy_rev_reg_def_request,
    indy_rev_reg_entry_request,
    indy_rev_reg_initial_entry_request,
    indy_schema_request,
    make_cred_def_id_from_result,
    make_indy_rev_reg_def_id,
    make_indy_schema_id_from_schema,
    make_rev_reg_def_id_from_result,
    make_schema_id_from_schema,
    normalize_cred_def_representation,
    normalize_rev_reg_def_representation,
    normalize_rev_status_list_representation,
    normalize_schema_representation,
)
from did_indy.author.base import BaseAuthor
from did_indy.client.client import IndyDriverClient
from did_indy.did import parse_did_indy
from did_indy.driver.api.txns import (
    CredDefSubmitResponse,
    NymResponse,
    RevRegDefSubmitResponse,
    RevStatusListSubmitResponse,
    SchemaSubmitResponse,
    make_indy_cred_def_id_from_result,
)
from did_indy.signer import Signer
from did_indy.ledger import Ledger, LedgerPool, LedgerTransactionError
from did_indy.models.anoncreds import Schema
from did_indy.models.taa import TaaAcceptance
from did_indy.models.txn import (
    CredDefTxnData,
    RevRegDefTxnData,
    RevRegEntryTxnData,
    SchemaTxnData,
    TxnResult,
)


LOGGER = logging.getLogger(__name__)


class AuthorError(Exception):
    """Error during author operation."""


class UnknownNamespace(AuthorError):
    """Raised when the namespace is not known."""


class UnknownAuthorDID(AuthorError):
    """Raised when unable to find signer by author DID."""


class AuthorDependencies(Protocol):
    """Retrieve author info."""

    async def get_signer(self, did: str) -> Signer:
        """Retrieve the signer for a did."""
        ...

    async def get_pool(self, namespace: str) -> LedgerPool:
        """Retrieve the pool for a namespace."""
        ...


class Author(BaseAuthor):
    """Ledger capable author implementation.

    This author will only use the indy driver to endorse transactions.
    """

    def __init__(
        self,
        client: IndyDriverClient,
        depends: AuthorDependencies,
    ):
        """Init the author."""
        self.client = client
        self.depends = depends

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
        submitter = parse_did_indy(schema.issuer_id)

        try:
            pool = await self.depends.get_pool(submitter.namespace)
        except Exception as err:
            LOGGER.exception("Failed to get ledger pool")
            raise UnknownNamespace(
                f"Failed to get pool for namespace {submitter.namespace}"
            ) from err

        try:
            signer = await self.depends.get_signer(schema.issuer_id)
        except Exception as err:
            LOGGER.exception("Failed to get signer")
            raise UnknownAuthorDID(
                f"Failed to get signer for DID {schema.issuer_id}"
            ) from err

        request = indy_schema_request(schema)
        if taa:
            request.set_txn_author_agreement_acceptance(taa.for_request())

        endorsement = await self.client.endorse_schema(schema.issuer_id, request.body)

        async with Ledger(pool) as ledger:
            result = await ledger.submit(request, signer, endorsement=endorsement)

        result = TxnResult[SchemaTxnData].model_validate(result)
        schema = Schema(
            issuer_id=schema.issuer_id,
            attr_names=result.txn.data.data.attr_names,
            name=result.txn.data.data.name,
            version=result.txn.data.data.version,
        )

        return SchemaSubmitResponse(
            schema_id=make_schema_id_from_schema(schema),
            indy_schema_id=make_indy_schema_id_from_schema(schema),
            registration_metadata=result,
            schema_metadata=result.txnMetadata,
        )

    async def register_cred_def(
        self,
        cred_def: CredDefTypes,
        taa: TaaAcceptance | None = None,
    ) -> CredDefSubmitResponse:
        """Register a credential definition."""
        cred_def = normalize_cred_def_representation(cred_def)
        submitter = parse_did_indy(cred_def.issuer_id)

        try:
            pool = await self.depends.get_pool(submitter.namespace)
        except Exception as err:
            LOGGER.exception("Failed to get ledger pool")
            raise UnknownNamespace(
                f"Failed to get pool for namespace {submitter.namespace}"
            ) from err

        try:
            signer = await self.depends.get_signer(cred_def.issuer_id)
        except Exception as err:
            LOGGER.exception("Failed to get signer")
            raise UnknownAuthorDID(
                f"Failed to get signer for DID {cred_def.issuer_id}"
            ) from err

        async with Ledger(pool) as ledger:
            try:
                schema_deref = await ledger.deref_schema(cred_def.schema_id)
            except LedgerTransactionError as error:
                LOGGER.exception("Failed to retrieve schema")
                raise AuthorError(f"Cannot retrieve schema: {error}") from error

            schema_seq_no = schema_deref.contentMetadata.nodeResponse.result.seqNo
            request = indy_cred_def_request(schema_seq_no, cred_def)
            if taa:
                request.set_txn_author_agreement_acceptance(taa.for_request())

            endorsement = await self.client.endorse_cred_def(
                cred_def.issuer_id, request.body
            )
            result = await ledger.submit(request, signer, endorsement=endorsement)
            result = TxnResult[CredDefTxnData].model_validate(result)

        return CredDefSubmitResponse(
            cred_def_id=make_cred_def_id_from_result(
                cred_def.issuer_id, result.txn.data
            ),
            indy_cred_def_id=make_indy_cred_def_id_from_result(
                submitter.nym, result.txn.data
            ),
            registration_metadata=result,
            cred_def_metadata=result.txnMetadata,
        )

    async def register_rev_reg_def(
        self,
        rev_reg_def: RevRegDefTypes,
        taa: TaaAcceptance | None = None,
    ) -> RevRegDefSubmitResponse:
        """Register a revocation registry definition."""
        rev_reg_def = normalize_rev_reg_def_representation(rev_reg_def)
        submitter = parse_did_indy(rev_reg_def.issuer_id)

        try:
            pool = await self.depends.get_pool(submitter.namespace)
        except Exception as err:
            LOGGER.exception("Failed to get ledger pool")
            raise UnknownNamespace(
                f"Failed to get pool for namespace {submitter.namespace}"
            ) from err

        try:
            signer = await self.depends.get_signer(rev_reg_def.issuer_id)
        except Exception as err:
            LOGGER.exception("Failed to get signer")
            raise UnknownAuthorDID(
                f"Failed to get signer for DID {rev_reg_def.issuer_id}"
            ) from err

        request = indy_rev_reg_def_request(rev_reg_def)
        if taa:
            request.set_txn_author_agreement_acceptance(taa.for_request())

        endorsement = await self.client.endorse_rev_reg_def(
            rev_reg_def.issuer_id, request.body
        )

        async with Ledger(pool) as ledger:
            result = await ledger.submit(request, signer, endorsement=endorsement)
            result = TxnResult[RevRegDefTxnData].model_validate(result)

        return RevRegDefSubmitResponse(
            rev_reg_def_id=make_rev_reg_def_id_from_result(
                rev_reg_def.issuer_id, result.txn.data
            ),
            indy_rev_reg_def_id=make_indy_rev_reg_def_id(
                submitter.nym,
                result.txn.data.cred_def_id,
                "CL_ACCUM",
                result.txn.data.tag,
            ),
            registration_metadata=result,
            rev_reg_def_metadata=result.txnMetadata,
        )

    async def register_rev_status_list(
        self,
        rev_status_list: RevStatusListTypes,
        taa: TaaAcceptance | None = None,
    ) -> RevStatusListSubmitResponse:
        """Register a revocation status list."""
        rev_status_list = normalize_rev_status_list_representation(rev_status_list)
        submitter = parse_did_indy(rev_status_list.issuer_id)

        try:
            pool = await self.depends.get_pool(submitter.namespace)
        except Exception as err:
            LOGGER.exception("Failed to get ledger pool")
            raise UnknownNamespace(
                f"Failed to get pool for namespace {submitter.namespace}"
            ) from err

        try:
            signer = await self.depends.get_signer(rev_status_list.issuer_id)
        except Exception as err:
            LOGGER.exception("Failed to get signer")
            raise UnknownAuthorDID(
                f"Failed to get signer for DID {rev_status_list.issuer_id}"
            ) from err

        request = indy_rev_reg_initial_entry_request(rev_status_list)
        if taa:
            request.set_txn_author_agreement_acceptance(taa.for_request())

        endorsement = await self.client.endorse_rev_status_list(
            rev_status_list.issuer_id, request.body
        )

        async with Ledger(pool) as ledger:
            result = await ledger.submit(request, signer, endorsement=endorsement)
            result = TxnResult[RevRegEntryTxnData].model_validate(result)

        return RevStatusListSubmitResponse(
            registration_metadata=result,
            rev_status_list_metadata=result.txnMetadata,
        )

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
        if prev_list.rev_reg_def_id != curr_list.rev_reg_def_id:
            raise AuthorError("Previous and current list are not for same rev reg")

        submitter = parse_did_indy(curr_list.issuer_id)

        try:
            pool = await self.depends.get_pool(submitter.namespace)
        except Exception as err:
            LOGGER.exception("Failed to get ledger pool")
            raise UnknownNamespace(
                f"Failed to get pool for namespace {submitter.namespace}"
            ) from err

        try:
            signer = await self.depends.get_signer(curr_list.issuer_id)
        except Exception as err:
            LOGGER.exception("Failed to get signer")
            raise UnknownAuthorDID(
                f"Failed to get signer for DID {curr_list.issuer_id}"
            ) from err

        request = indy_rev_reg_entry_request(
            prev_list.current_accumulator, curr_list, revoked
        )
        if taa:
            request.set_txn_author_agreement_acceptance(taa.for_request())

        endorsement = await self.client.endorse_rev_status_list_update(
            curr_list.issuer_id, request.body
        )

        async with Ledger(pool) as ledger:
            result = await ledger.submit(request, signer, endorsement=endorsement)
            result = TxnResult[RevRegEntryTxnData].model_validate(result)

        return RevStatusListSubmitResponse(
            registration_metadata=result,
            rev_status_list_metadata=result.txnMetadata,
        )
