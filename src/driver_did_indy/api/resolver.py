"""Resolver API."""

from fastapi import APIRouter, HTTPException

from driver_did_indy.depends import LedgersDep
from driver_did_indy.ledgers import ReadOnlyLedger
from driver_did_indy.did import parse_did_indy

router = APIRouter(tags=["Resolver"])


@router.get("/resolve/{did}")
async def get_resolve_did(did: str, ledgers: LedgersDep):
    """Resolve a did:indy DID."""
    parsed = parse_did_indy(did)

    pool = ledgers.get(parsed.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {parsed.namespace} is unknown")

    ledger = ReadOnlyLedger(pool)
    result = await ledger.resolve(did)
    return result
