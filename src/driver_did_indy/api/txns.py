import base64
from dataclasses import asdict
import json
from typing import Any, Mapping

from fastapi import APIRouter, HTTPException
from indy_vdr import VdrError
from indy_vdr.error import VdrErrorCode
from indy_vdr.ledger import (
    build_cred_def_request,
    build_nym_request,
    build_schema_request,
)
from pydantic import BaseModel, Field

from driver_did_indy.depends import LedgersDep, StoreDep
from driver_did_indy.ledgers import Ledger, LedgerTransactionError, TaaAcceptance
from driver_did_indy.models.anoncreds import CredDef, Schema
from driver_did_indy.models.txn import (
    CredDefTxnData,
    SchemaTxnData,
    TxnMetadata,
    TxnResult,
)
from driver_did_indy.utils import (
    NymNotFoundError,
    get_nym_and_key,
    nym_from_verkey,
    parse_did_indy,
)

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
    req: NymRequest, ledgers: LedgersDep, store: StoreDep
) -> NymResponse:
    """Create a new nym."""

    pool = ledgers.get(req.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {req.namespace} is unknown")

    async with Ledger(pool, store) as ledger:
        nym, key = await ledger.get_nym_and_key()
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
            result = await ledger.submit(request, key)
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


def make_indy_schema_id(nym: str, schema: Schema) -> str:
    """Derive the indy schema ID for a schema."""
    return f"{nym}:2:{schema.name}:{schema.version}"


def make_schema_id(schema: Schema) -> str:
    """Derive the DID Url for a schema."""
    return f"{schema.issuer_id}/anoncreds/v0/SCHEMA/{schema.name}/{schema.version}"


@router.post("/schema")
async def post_schema(req: SchemaRequest, store: StoreDep) -> TxnToSignResponse:
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

    schema_id = make_indy_schema_id(submitter.nym, schema)
    indy_schema = {
        "ver": "1.0",
        "id": schema_id,
        "name": schema.name,
        "version": schema.version,
        "attrNames": schema.attr_names,
        "seqNo": None,
    }
    request = build_schema_request(submitter_did=submitter.nym, schema=indy_schema)
    request.set_endorser(nym)
    if req.taa:
        request.set_txn_author_agreement_acceptance(asdict(req.taa))

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
    req: SubmitRequest, ledgers: LedgersDep, store: StoreDep
) -> SchemaSubmitResponse:
    """Endorse and submit a txn."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No pool for namespace {submitter.namespace}")

    async with Ledger(pool, store) as ledger:
        result = await ledger.endorse_and_submit(
            req.request, submitter.nym, req.signature
        )
        print(result)
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


class CredDefRequest(BaseModel):
    """Credential Definition create request."""

    cred_def: CredDef | str
    taa: TaaAcceptance | None = None


def make_indy_cred_def_id_from_result(nym: str, cred_def: CredDefTxnData) -> str:
    """Make cred def ID."""
    return f"{nym}:3:{cred_def.signature_type}:{cred_def.ref}:{cred_def.tag}"


def make_indy_cred_def_id(nym: str, cred_def: CredDef, schema_seq_no: int) -> str:
    """Make cred def ID."""
    return f"{nym}:3:{cred_def.type}:{schema_seq_no}:{cred_def.tag}"


def make_cred_def_id(did: str, cred_def: CredDefTxnData) -> str:
    """Make cred def ID."""
    return f"{did}/anoncreds/v0/CLAIM_DEF/{cred_def.ref}/{cred_def.tag}"


@router.post("/credential-definition")
async def post_credential_definition(
    req: CredDefRequest, ledgers: LedgersDep, store: StoreDep
) -> TxnToSignResponse:
    """Create a schema and return a txn for the client to sign and later submit."""
    if isinstance(req.cred_def, str):
        req.cred_def = CredDef.model_validate_json(req.cred_def)

    submitter = parse_did_indy(req.cred_def.issuer_id)
    try:
        nym, _ = await get_nym_and_key(store, submitter.namespace)
    except NymNotFoundError as error:
        raise HTTPException(
            404, f"No nym found for namespace {submitter.namespace}"
        ) from error

    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No ledger known for namespace {submitter.namespace}")

    async with Ledger(pool, store) as ledger:
        try:
            schema_deref = await ledger.get_schema(req.cred_def.schema_id)
        except LedgerTransactionError as error:
            raise HTTPException(400, f"Cannot retrieve schema: {error}") from error

    schema_seq_no = schema_deref.contentMetadata.nodeResponse.result.seqNo
    cred_def_id = make_indy_cred_def_id(submitter.nym, req.cred_def, schema_seq_no)

    indy_cred_def = {
        "id": cred_def_id,
        "schemaId": str(schema_seq_no),
        "tag": req.cred_def.tag,
        "type": req.cred_def.type,
        "value": req.cred_def.value,
        "ver": "1.0",
    }

    request = build_cred_def_request(
        submitter_did=submitter.nym, cred_def=indy_cred_def
    )
    request.set_endorser(nym)
    if req.taa:
        request.set_txn_author_agreement_acceptance(asdict(req.taa))

    return TxnToSignResponse(
        request=request.body,
        signature_input=base64.urlsafe_b64encode(request.signature_input).decode(),
    )


class CredDefSubmitResponse(BaseModel):
    """Credential Definition submit response."""

    cred_def_id: str
    indy_cred_def_id: str
    registration_metadata: TxnResult
    cred_def_metadata: TxnMetadata


@router.post("/credential-definition/submit")
async def post_credential_definition_submit(
    req: SubmitRequest, ledgers: LedgersDep, store: StoreDep
) -> CredDefSubmitResponse:
    """Endorse and submit a txn."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No pool for namespace {submitter.namespace}")

    async with Ledger(pool, store) as ledger:
        result = await ledger.endorse_and_submit(
            req.request, submitter.nym, req.signature
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
