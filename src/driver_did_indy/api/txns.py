"""Transaction API."""

import base64
import json
from typing import Any, Mapping

from fastapi import APIRouter, HTTPException, Security
from indy_vdr import VdrError
from indy_vdr.error import VdrErrorCode
from indy_vdr.ledger import build_nym_request
from pydantic import BaseModel, Field

from did_indy.did import nym_from_verkey, parse_did_indy
from did_indy.models.anoncreds import CredDef, Schema
from did_indy.models.taa import TaaAcceptance
from did_indy.models.txn import CredDefTxnData, SchemaTxnData, TxnMetadata, TxnResult
from did_indy.anoncreds import indy_cred_def_request, indy_schema_request
from driver_did_indy.auto_endorse import SCOPE_CRED_DEF, SCOPE_NYM_NEW, SCOPE_SCHEMA
from driver_did_indy.depends import LedgersDep, StoreDep
from did_indy.ledger import (
    Ledger,
    LedgerTransactionError,
)
from driver_did_indy.ledgers import NymNotFoundError, get_nym_and_key
from driver_did_indy.security import Auth
from driver_did_indy.taa import get_latest_txn_author_acceptance

router = APIRouter(prefix="/txn", tags=["txn"])


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
    diddocContent: Mapping[str, Any] | None = None


@router.post("/nym")
async def post_nym(
    req: NymRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(Auth.client, scopes=[SCOPE_NYM_NEW]),
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
            result = await ledger.submit(request, key, taa)
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


def make_indy_schema_id(nym: str, schema: Schema) -> str:
    """Derive the indy schema ID for a schema."""
    return f"{nym}:2:{schema.name}:{schema.version}"


def make_schema_id(schema: Schema) -> str:
    """Derive the DID Url for a schema."""
    return f"{schema.issuer_id}/anoncreds/v0/SCHEMA/{schema.name}/{schema.version}"


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


@router.post("/schema")
async def post_schema(
    req: SchemaRequest,
    store: StoreDep,
    _=Security(Auth.client, scopes=[SCOPE_SCHEMA]),
) -> TxnToSignResponse:
    """Create a schema and return a txn for the client to sign and later submit."""
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
    registration_metadata: TxnResult
    schema_metadata: TxnMetadata


@router.post("/schema/submit")
async def post_schema_submit(
    req: SubmitRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(Auth.client, scopes=[SCOPE_SCHEMA]),
) -> SchemaSubmitResponse:
    """Endorse and submit a txn."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    async with Ledger(pool) as ledger:
        result = await ledger.endorse_and_submit(
            request=req.request,
            submitter=submitter.nym,
            submitter_signature=req.signature,
            nym=nym,
            key=key,
        )

    result = TxnResult[SchemaTxnData].model_validate(result)
    schema = Schema(
        issuer_id=req.submitter,
        attr_names=result.txn.data.data.attr_names,
        name=result.txn.data.data.name,
        version=result.txn.data.data.version,
    )

    return SchemaSubmitResponse(
        schema_id=make_schema_id(schema),
        indy_schema_id=make_indy_schema_id(submitter.nym, schema),
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


@router.post("/schema/endorse")
async def post_schema_endorse(
    req: EndorseRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(Auth.client, scopes=[SCOPE_SCHEMA]),
) -> EndorseResponse:
    """Endorse a schema."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    async with Ledger(pool) as ledger:
        # TODO Make sure it's a schema
        endorsement = await ledger.endorse(req.request, nym, key)

    return EndorseResponse(
        nym=endorsement.nym,
        signature=base64.urlsafe_b64encode(endorsement.signature).decode(),
    )


def make_indy_cred_def_id_from_result(nym: str, cred_def: CredDefTxnData) -> str:
    """Make cred def ID."""
    return f"{nym}:3:{cred_def.signature_type}:{cred_def.ref}:{cred_def.tag}"


def make_indy_cred_def_id(nym: str, cred_def: CredDef, schema_seq_no: int) -> str:
    """Make cred def ID."""
    return f"{nym}:3:{cred_def.type}:{schema_seq_no}:{cred_def.tag}"


def make_cred_def_id(did: str, cred_def: CredDefTxnData) -> str:
    """Make cred def ID."""
    return f"{did}/anoncreds/v0/CLAIM_DEF/{cred_def.ref}/{cred_def.tag}"


class CredDefRequest(BaseModel):
    """Credential Definition create request."""

    cred_def: CredDef | str
    taa: TaaAcceptance | None = None


class CredDefSubmitResponse(BaseModel):
    """Credential Definition submit response."""

    cred_def_id: str
    indy_cred_def_id: str
    registration_metadata: TxnResult
    cred_def_metadata: TxnMetadata


@router.post("/cred-def")
async def post_cred_def(
    req: CredDefRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(Auth.client, scopes=[SCOPE_CRED_DEF]),
) -> TxnToSignResponse:
    """Create a schema and return a txn for the client to sign and later submit."""
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

    async with Ledger(pool) as ledger:
        try:
            schema_deref = await ledger.get_schema(req.cred_def.schema_id)
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


@router.post("/cred-def/submit")
async def post_cred_def_submit(
    req: SubmitRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(Auth.client, scopes=[SCOPE_CRED_DEF]),
) -> CredDefSubmitResponse:
    """Endorse and submit a txn."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    async with Ledger(pool) as ledger:
        result = await ledger.endorse_and_submit(
            request=req.request,
            submitter=submitter.nym,
            submitter_signature=req.signature,
            nym=nym,
            key=key,
        )

    result = TxnResult[CredDefTxnData].model_validate(result)

    return CredDefSubmitResponse(
        cred_def_id=make_cred_def_id(req.submitter, result.txn.data),
        indy_cred_def_id=make_indy_cred_def_id_from_result(
            submitter.nym, result.txn.data
        ),
        registration_metadata=result,
        cred_def_metadata=result.txnMetadata,
    )


@router.post("/cred-def/endorse")
async def post_cred_def_endorse(
    req: SubmitRequest,
    ledgers: LedgersDep,
    store: StoreDep,
    _=Security(Auth.client, scopes=[SCOPE_CRED_DEF]),
) -> EndorseResponse:
    """Endorse a Credential Definition transaction request."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)

    if not pool:
        raise HTTPException(404, f"Unrecognized namespace {submitter.namespace}")

    nym, key = await get_nym_and_key(store, submitter.namespace)
    async with Ledger(pool) as ledger:
        # TODO Make sure it's a Cred Def
        endorsement = await ledger.endorse(req.request, nym, key)

    return EndorseResponse(
        nym=endorsement.nym,
        signature=base64.urlsafe_b64encode(endorsement.signature).decode(),
    )
