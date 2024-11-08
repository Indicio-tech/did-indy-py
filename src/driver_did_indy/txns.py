import json
from typing import Any, Mapping

from fastapi import APIRouter, HTTPException
from indy_vdr import VdrError
from pydantic import BaseModel
from indy_vdr.ledger import build_nym_request
from indy_vdr.error import VdrErrorCode

from driver_did_indy.depends import LedgersDep, StoreDep
from driver_did_indy.ledgers import Ledger

router = APIRouter(prefix="/txn", tags=["txn"])


class NymRequest(BaseModel):
    """Nym Request."""

    namespace: str
    nym: str
    verkey: str
    role: str | None = None
    diddocContent: str | Mapping[str, Any] | None = None
    version: int | None = None


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

        if isinstance(req.diddocContent, str):
            diddoc_content = req.diddocContent
        elif req.diddocContent:
            diddoc_content = json.dumps(req.diddocContent)
        else:
            diddoc_content = None

        request = build_nym_request(
            submitter_did=nym,
            dest=req.nym,
            verkey=req.verkey,
            role=req.role,
            diddoc_content=diddoc_content,
            version=2,
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
