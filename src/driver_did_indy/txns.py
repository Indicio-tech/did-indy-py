from dataclasses import asdict
import json
from typing import Any, List, Mapping
import base64

from fastapi import APIRouter, HTTPException
from indy_vdr import VdrError
from pydantic import BaseModel
from indy_vdr.ledger import (
    build_nym_request,
    build_schema_request,
)
from indy_vdr.error import VdrErrorCode

from driver_did_indy.depends import LedgersDep, StoreDep
from driver_did_indy.ledgers import Ledger, LedgerTransactionError, TaaAcceptance
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

    issuer_id: str
    attr_names: List[str]
    name: str
    version: str
    taa: TaaAcceptance


class SchemaResponse(BaseModel):
    """Schema Create Response."""

    request: str
    signature_input: str


def make_schema_id(nym: str, schema: SchemaRequest) -> str:
    """Derive the ID for a schema."""
    return f"{nym}:2:{schema.name}:{schema.version}"


@router.post("/schema")
async def post_schema(req: SchemaRequest, store: StoreDep):
    """Create a schema and return a txn for the client to sign and later submit."""
    submitter = parse_did_indy(req.issuer_id)
    try:
        nym, _ = await get_nym_and_key(store, submitter.namespace)
    except NymNotFoundError as error:
        raise HTTPException(
            404, f"No nym found for namespace {submitter.namespace}"
        ) from error

    schema_id = make_schema_id(submitter.nym, req)
    indy_schema = {
        "ver": "1.0",
        "id": schema_id,
        "name": req.name,
        "version": req.version,
        "attrNames": req.attr_names,
        "seqNo": None,
    }
    request = build_schema_request(submitter_did=submitter.nym, schema=indy_schema)
    request.set_endorser(nym)
    request.set_txn_author_agreement_acceptance(asdict(req.taa))
    return SchemaResponse(
        request=request.body,
        signature_input=base64.urlsafe_b64encode(request.signature_input).decode(),
    )


class SubmitRequest(BaseModel):
    """Txn Submit Request."""

    submitter: str
    request: str
    signature: str


@router.post("/submit")
async def post_submit(req: SubmitRequest, ledgers: LedgersDep, store: StoreDep):
    """Endorse and submit a txn."""
    submitter = parse_did_indy(req.submitter)
    pool = ledgers.get(submitter.namespace)
    if not pool:
        raise HTTPException(404, f"No pool for namespace {submitter.namespace}")

    async with Ledger(pool, store) as ledger:
        result = await ledger.endorse_and_submit(
            req.request, submitter.nym, req.signature
        )
        return result
