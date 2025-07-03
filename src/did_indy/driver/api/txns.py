"""Transaction API."""

import base64
import json
import logging
from typing import Any, Mapping

from fastapi import APIRouter, HTTPException, Security
from indy_vdr import VdrError
from indy_vdr.error import VdrErrorCode
from indy_vdr.ledger import build_nym_request
from pydantic import BaseModel, Field

from did_indy.anoncreds import (
    indy_cred_def_request,
    indy_rev_reg_def_request,
    indy_rev_reg_entry_request,
    indy_rev_reg_initial_entry_request,
    indy_schema_request,
    make_cred_def_id_from_result,
    make_indy_cred_def_id_from_result,
    make_indy_rev_reg_def_id,
    make_indy_schema_id_from_schema,
    make_rev_reg_def_id_from_result,
    make_schema_id_from_schema,
)
from did_indy.did import nym_from_verkey, parse_did_indy
from did_indy.driver.auto_endorse import (
    SCOPE_CRED_DEF,
    SCOPE_NYM_NEW,
    SCOPE_REV_REG_DEF,
    SCOPE_REV_REG_ENTRY,
    SCOPE_SCHEMA,
)
from did_indy.driver.depends import LedgersDep, StoreDep
from did_indy.driver.ledgers import NymNotFoundError, get_nym_and_key
from did_indy.driver.security import client
from did_indy.driver.taa import get_latest_txn_author_acceptance
from did_indy.ledger import (
    Ledger,
    LedgerTransactionError,
)
from did_indy.models.anoncreds import CredDef, RevRegDef, RevStatusList, Schema
from did_indy.models.taa import TaaAcceptance
from did_indy.models.txn import (
    CredDefOperation,
    CredDefTxnData,
    RevRegDefOperation,
    RevRegDefTxnData,
    RevRegEntryOperation,
    RevRegEntryTxnData,
    SchemaOperation,
    SchemaTxnData,
    TxnMetadata,
    TxnRequest,
    TxnResult,
)
from did_indy.resolver import Resolver

router = APIRouter(prefix="/txn")
LOGGER = logging.getLogger(__name__)


class NymRequest(BaseModel):
    """Nym Request."""

    namespace: str
    verkey: str
    nym: str | None = None
    role: str | None = None
    diddocContent: str | Mapping[str, Any] | None = None
    version: int | None = None
    taa: TaaAcceptance | None = None


class NymResponse(BaseModel):
    seqNo: int
    nym: str
    verkey: str
    did: str
    did_sov: str
    role: str | None = None
    diddocContent: str | None = None


@router.post("/nym", tags=["Nym"], summary="Create a new nym")
async def post_nym(
    req: NymRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_NYM_NEW]),
) -> NymResponse:
    """Create a new nym."""

    pool = ledgers.get(req.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {req.namespace} is unknown")

    nym, key = await get_nym_and_key(store, req.namespace)
    taa = await get_latest_txn_author_acceptance(pool, store)
    async with Ledger(pool) as ledger:
        try:
            await ledger.validate_taa_acceptance(req.taa)
        except LedgerTransactionError as error:
            raise HTTPException(400, detail=str(error))

        version = req.version if req.version is not None else 2
        if version > 2 or version < 0:
            raise HTTPException(400, detail="Invalid version; must be 0, 1, 2")

        if req.nym is not None:
            dest = req.nym
        else:
            dest = nym_from_verkey(req.verkey, version)

        if isinstance(req.diddocContent, str):
            diddoc_content = req.diddocContent
        elif req.diddocContent:
            diddoc_content = json.dumps(req.diddocContent)
        else:
            diddoc_content = None

        request = build_nym_request(
            submitter_did=nym,
            dest=dest,
            verkey=req.verkey,
            role=req.role,  # pyright: ignore
            diddoc_content=diddoc_content,  # pyright: ignore
            version=version,
        )
        try:
            result = await ledger.submit(request, key.sign_message, taa)  # pyright: ignore[reportArgumentType]
        except VdrError as error:
            if error.code == VdrErrorCode.POOL_REQUEST_FAILED:
                raise HTTPException(400, detail=str(error))
            raise error

        nym = result["txn"]["data"]["dest"]
        return NymResponse(
            seqNo=result["txnMetadata"]["seqNo"],
            nym=nym,
            verkey=result["txn"]["data"]["verkey"],
            role=result["txn"]["data"].get("role"),
            did=f"did:indy:{ledger.pool.name}:{nym}",
            did_sov=f"did:sov:{nym}",
            diddocContent=result["txn"]["data"].get("diddocContent"),
        )


class SchemaRequest(BaseModel):
    """Schema Create Request."""

    schema_value: Schema | str = Field(alias="schema")
    taa: TaaAcceptance | None = None


class TxnToSignResponse(BaseModel):
    """Schema Create Response."""

    request: str
    signature_input: str

    def get_signature_input_bytes(self):
        """Get signature input as bytes."""
        return base64.urlsafe_b64decode(self.signature_input)


@router.post(
    "/schema",
    tags=["Transaction"],
    summary="Create a schema transaction ready for signing",
)
async def post_schema(
    req: SchemaRequest,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_SCHEMA]),
) -> TxnToSignResponse:
    """Create a schema transaction for the client to sign and later submit."""
    schema = req.schema_value
    if isinstance(schema, str):
        schema = Schema.model_validate_json(schema)

    submitter = parse_did_indy(schema.issuer_id)
    try:
        nym, _ = await get_nym_and_key(store, submitter.namespace)
    except NymNotFoundError as error:
        raise HTTPException(
            404, f"No nym found for namespace {submitter.namespace}"
        ) from error

    request = indy_schema_request(schema)
    request.set_endorser(nym)
    if req.taa:
        request.set_txn_author_agreement_acceptance(req.taa.for_request())

    return TxnToSignResponse(
        request=request.body,
        signature_input=base64.urlsafe_b64encode(request.signature_input).decode(),
    )


class SubmitRequest(BaseModel):
    """Txn Submit Request."""

    submitter: str
    request: str
    signature: str


class SchemaSubmitResponse(BaseModel):
    """Schema submit response."""

    schema_id: str
    indy_schema_id: str
    registration_metadata: TxnResult[SchemaTxnData]
    schema_metadata: TxnMetadata


@router.post(
    "/schema/submit",
    tags=["Transaction"],
    summary="Endorse and submit a schema transaction",
)
async def post_schema_submit(
    req: SubmitRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_SCHEMA]),
) -> SchemaSubmitResponse:
    """Endorse and submit a schema transaction.

    The did:indy driver will both endorse and submit the transaction to the network on
    behalf of the author.
    """
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)

    request = TxnRequest[SchemaOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        result = await ledger.endorse_and_submit(
            request=req.request,
            submitter=submitter.nym,
            submitter_signature=req.signature,
            nym=nym,
            signer=key.sign_message,  # pyright: ignore[reportArgumentType]
        )

    result = TxnResult[SchemaTxnData].model_validate(result)
    schema = Schema(
        issuer_id=req.submitter,
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


class EndorseRequest(BaseModel):
    """Endorse request."""

    submitter: str
    request: str


class EndorseResponse(BaseModel):
    """Endorse response."""

    nym: str
    signature: str

    def get_signature_bytes(self):
        """Get signature as bytes."""
        return base64.urlsafe_b64decode(self.signature)


@router.post(
    "/schema/endorse",
    tags=["Endorse"],
    summary="Request endorsement of a schema transaction",
)
async def post_schema_endorse(
    req: EndorseRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_SCHEMA]),
) -> EndorseResponse:
    """Request endorsement of a schema transaction request."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[SchemaOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        endorsement = await ledger.endorse(req.request, nym, key.sign_message)  # pyright: ignore[reportArgumentType]

    return EndorseResponse(
        nym=endorsement.nym,
        signature=base64.urlsafe_b64encode(endorsement.signature).decode(),
    )


class CredDefRequest(BaseModel):
    """Credential Definition create request."""

    cred_def: CredDef | str
    taa: TaaAcceptance | None = None


class CredDefSubmitResponse(BaseModel):
    """Credential Definition submit response."""

    cred_def_id: str
    indy_cred_def_id: str
    registration_metadata: TxnResult[CredDefTxnData]
    cred_def_metadata: TxnMetadata


@router.post(
    "/cred-def",
    tags=["Transaction"],
    summary="Create a cred def transaction ready for signing",
)
async def post_cred_def(
    req: CredDefRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_CRED_DEF]),
) -> TxnToSignResponse:
    """Create a cred def transaction and return for client to sign and later submit."""
    if isinstance(req.cred_def, str):
        req.cred_def = CredDef.model_validate_json(req.cred_def)

    submitter = parse_did_indy(req.cred_def.issuer_id)
    try:
        nym, _ = await get_nym_and_key(store, submitter.namespace)
    except NymNotFoundError as error:
        raise HTTPException(
            404, f"Unrecognized namespace {submitter.namespace}"
        ) from error

    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No ledger known for namespace {submitter.namespace}")

    async with Resolver(pool) as resolver:
        try:
            schema_deref = await resolver.get_schema(req.cred_def.schema_id)
        except LedgerTransactionError as error:
            raise HTTPException(400, f"Cannot retrieve schema: {error}") from error

    schema_seq_no = schema_deref.contentMetadata.nodeResponse.result.seqNo
    request = indy_cred_def_request(schema_seq_no, req.cred_def)
    request.set_endorser(nym)
    if req.taa:
        request.set_txn_author_agreement_acceptance(req.taa.for_request())

    return TxnToSignResponse(
        request=request.body,
        signature_input=base64.urlsafe_b64encode(request.signature_input).decode(),
    )


@router.post(
    "/cred-def/submit",
    tags=["Transaction"],
    summary="Endorse and submit a cred def transaction",
)
async def post_cred_def_submit(
    req: SubmitRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_CRED_DEF]),
) -> CredDefSubmitResponse:
    """Endorse and submit a cred def transaction."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)

    request = TxnRequest[CredDefOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        result = await ledger.endorse_and_submit(
            request=req.request,
            submitter=submitter.nym,
            submitter_signature=req.signature,
            nym=nym,
            signer=key.sign_message,  # pyright: ignore[reportArgumentType]
        )
        result = TxnResult[CredDefTxnData].model_validate(result)

    return CredDefSubmitResponse(
        cred_def_id=make_cred_def_id_from_result(req.submitter, result.txn.data),
        indy_cred_def_id=make_indy_cred_def_id_from_result(
            submitter.nym, result.txn.data
        ),
        registration_metadata=result,
        cred_def_metadata=result.txnMetadata,
    )


@router.post(
    "/cred-def/endorse",
    tags=["Endorse"],
    summary="Request endorsement of a cred def transaction",
)
async def post_cred_def_endorse(
    req: EndorseRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_CRED_DEF]),
) -> EndorseResponse:
    """Request endorsement of a Credential Definition transaction request."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)

    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[CredDefOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        endorsement = await ledger.endorse(req.request, nym, key.sign_message)  # pyright: ignore[reportArgumentType]

    return EndorseResponse(
        nym=endorsement.nym,
        signature=base64.urlsafe_b64encode(endorsement.signature).decode(),
    )


class RevRegDefRequest(BaseModel):
    """Revocation Registry Definition create request."""

    rev_reg_def: RevRegDef | str
    taa: TaaAcceptance | None = None


@router.post(
    "/rev-reg-def",
    tags=["Transaction"],
    summary="Create a rev reg def transaction ready for signing",
)
async def post_rev_reg_def(
    req: RevRegDefRequest,
    store: StoreDep,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_REV_REG_DEF]),
) -> TxnToSignResponse:
    """Create a rev reg def transaction and return for client to sign and later submit."""
    if isinstance(req.rev_reg_def, str):
        req.rev_reg_def = RevRegDef.model_validate_json(req.rev_reg_def)

    submitter = parse_did_indy(req.rev_reg_def.issuer_id)
    try:
        nym, _ = await get_nym_and_key(store, submitter.namespace)
    except NymNotFoundError as error:
        raise HTTPException(
            404, f"Unrecognized namespace {submitter.namespace}"
        ) from error

    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No ledger known for namespace {submitter.namespace}")

    request = indy_rev_reg_def_request(req.rev_reg_def)
    request.set_endorser(nym)
    if req.taa:
        request.set_txn_author_agreement_acceptance(req.taa.for_request())

    return TxnToSignResponse(
        request=request.body,
        signature_input=base64.urlsafe_b64encode(request.signature_input).decode(),
    )


class RevRegDefSubmitResponse(BaseModel):
    """Rev Reg Definition submit response."""

    rev_reg_def_id: str
    indy_rev_reg_def_id: str
    registration_metadata: TxnResult[RevRegDefTxnData]
    rev_reg_def_metadata: TxnMetadata


@router.post(
    "/rev-reg-def/submit",
    tags=["Transaction"],
    summary="Endorse and submit a rev reg def transaction",
)
async def post_rev_reg_def_submit(
    req: SubmitRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_REV_REG_DEF]),
) -> RevRegDefSubmitResponse:
    """Endorse and submit a rev reg def transaction."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[RevRegDefOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        result = await ledger.endorse_and_submit(
            request=req.request,
            submitter=submitter.nym,
            submitter_signature=req.signature,
            nym=nym,
            signer=key.sign_message,  # pyright: ignore[reportArgumentType]
        )
        result = TxnResult[RevRegDefTxnData].model_validate(result)

    return RevRegDefSubmitResponse(
        rev_reg_def_id=make_rev_reg_def_id_from_result(req.submitter, result.txn.data),
        indy_rev_reg_def_id=make_indy_rev_reg_def_id(
            submitter.nym, result.txn.data.cred_def_id, "CL_ACCUM", result.txn.data.tag
        ),
        registration_metadata=result,
        rev_reg_def_metadata=result.txnMetadata,
    )


@router.post(
    "/rev-reg-def/endorse",
    tags=["Endorse"],
    summary="Request endorsement of a rev reg def transaction",
)
async def post_rev_reg_def_endorse(
    req: EndorseRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_REV_REG_DEF]),
) -> EndorseResponse:
    """Endorse a Revocation Registry Definition transaction request."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)

    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[RevRegDefOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        endorsement = await ledger.endorse(req.request, nym, key.sign_message)  # pyright: ignore[reportArgumentType]

    return EndorseResponse(
        nym=endorsement.nym,
        signature=base64.urlsafe_b64encode(endorsement.signature).decode(),
    )


class RevStatusListRequest(BaseModel):
    """Revocation Status List create request."""

    rev_status_list: RevStatusList | str
    taa: TaaAcceptance | None = None


@router.post(
    "/rev-status-list",
    tags=["Transaction"],
    summary="Create a revocation status list transaction ready for signing",
)
async def post_rev_status_list(
    req: RevStatusListRequest,
    store: StoreDep,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_REV_REG_ENTRY]),
) -> TxnToSignResponse:
    """Create a rev status list and return a txn for the client to sign and submit.

    In indy terms, this will create a rev reg entry transaction.
    """
    if isinstance(req.rev_status_list, str):
        req.rev_status_list = RevStatusList.model_validate_json(req.rev_status_list)

    submitter = parse_did_indy(req.rev_status_list.issuer_id)
    try:
        nym, _ = await get_nym_and_key(store, submitter.namespace)
    except NymNotFoundError as error:
        raise HTTPException(
            404, f"Unrecognized namespace {submitter.namespace}"
        ) from error

    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No ledger known for namespace {submitter.namespace}")

    request = indy_rev_reg_initial_entry_request(req.rev_status_list)
    request.set_endorser(nym)
    if req.taa:
        request.set_txn_author_agreement_acceptance(req.taa.for_request())

    return TxnToSignResponse(
        request=request.body,
        signature_input=base64.urlsafe_b64encode(request.signature_input).decode(),
    )


class RevStatusListSubmitResponse(BaseModel):
    """Response to rev status list submit."""

    registration_metadata: TxnResult[RevRegEntryTxnData]
    rev_status_list_metadata: TxnMetadata


@router.post(
    "/rev-status-list/submit",
    tags=["Transaction"],
    summary="Endorse and submit a rev status list transaction",
)
async def post_rev_status_list_submit(
    req: SubmitRequest,
    store: StoreDep,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_REV_REG_ENTRY]),
) -> RevStatusListSubmitResponse:
    """Submit and endorse a revocation status list."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[RevRegEntryOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        result = await ledger.endorse_and_submit(
            request=req.request,
            submitter=submitter.nym,
            submitter_signature=req.signature,
            nym=nym,
            signer=key.sign_message,  # pyright: ignore[reportArgumentType]
        )
        result = TxnResult[RevRegEntryTxnData].model_validate(result)

    return RevStatusListSubmitResponse(
        registration_metadata=result,
        rev_status_list_metadata=result.txnMetadata,
    )


@router.post(
    "/rev-status-list/endorse",
    tags=["Endorse"],
    summary="Request endorsement of a rev status list transaction",
)
async def post_rev_status_list_endorse(
    req: EndorseRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_REV_REG_ENTRY]),
) -> EndorseResponse:
    """Endorse a Revocation Status List transaction request."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)

    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[RevRegEntryOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        endorsement = await ledger.endorse(req.request, nym, key.sign_message)  # pyright: ignore[reportArgumentType]

    return EndorseResponse(
        nym=endorsement.nym,
        signature=base64.urlsafe_b64encode(endorsement.signature).decode(),
    )


class RevStatusListUpdateRequest(BaseModel):
    """Revocation Status List update request."""

    prev_accum: str
    curr_list: RevStatusList | str
    revoked: list[int]
    taa: TaaAcceptance | None = None


@router.post(
    "/rev-status-list/update",
    tags=["Transaction"],
    summary="Create a rev status list update transaction ready for signing",
)
async def post_rev_status_list_update(
    req: RevStatusListUpdateRequest,
    store: StoreDep,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_REV_REG_ENTRY]),
) -> TxnToSignResponse:
    """Update a rev status list, generate a txn, and return for sign and submit."""
    if isinstance(req.curr_list, str):
        req.curr_list = RevStatusList.model_validate_json(req.curr_list)

    submitter = parse_did_indy(req.curr_list.issuer_id)
    try:
        nym, _ = await get_nym_and_key(store, submitter.namespace)
    except NymNotFoundError as error:
        raise HTTPException(
            404, f"Unrecognized namespace {submitter.namespace}"
        ) from error

    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No ledger known for namespace {submitter.namespace}")

    request = indy_rev_reg_entry_request(req.prev_accum, req.curr_list, req.revoked)
    request.set_endorser(nym)
    if req.taa:
        request.set_txn_author_agreement_acceptance(req.taa.for_request())

    return TxnToSignResponse(
        request=request.body,
        signature_input=base64.urlsafe_b64encode(request.signature_input).decode(),
    )


@router.post(
    "/rev-status-list/update/submit",
    tags=["Transaction"],
    summary="Endorse and submit a rev status list update transaction",
)
async def post_rev_status_list_update_submit(
    req: SubmitRequest,
    store: StoreDep,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_REV_REG_ENTRY]),
) -> RevStatusListSubmitResponse:
    """Submit and endorse an update to a revocation status list."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[RevRegEntryOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        result = await ledger.endorse_and_submit(
            request=req.request,
            submitter=submitter.nym,
            submitter_signature=req.signature,
            nym=nym,
            signer=key.sign_message,  # pyright: ignore[reportArgumentType]
        )
        result = TxnResult[RevRegEntryTxnData].model_validate(result)

    return RevStatusListSubmitResponse(
        registration_metadata=result,
        rev_status_list_metadata=result.txnMetadata,
    )


@router.post(
    "/rev-status-list/update/endorse",
    tags=["Endorse"],
    summary="Request endorsement of a rev status list update transaction",
)
async def post_rev_status_list_update_endorse(
    req: EndorseRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(client, scopes=[SCOPE_REV_REG_ENTRY]),
) -> EndorseResponse:
    """Endorse a Revocation Status List update transaction request."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)

    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    request = TxnRequest[RevRegEntryOperation].model_validate_json(req.request)
    if request.endorser and request.endorser != nym:
        raise HTTPException(400, detail="Incorrect endorser nym on request")

    async with Ledger(pool) as ledger:
        endorsement = await ledger.endorse(req.request, nym, key.sign_message)  # pyright: ignore[reportArgumentType]

    return EndorseResponse(
        nym=endorsement.nym,
        signature=base64.urlsafe_b64encode(endorsement.signature).decode(),
    )
