"""Transaction Author Agreement endpoints."""

from typing import List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from driver_did_indy.depends import LedgersDep
from driver_did_indy.ledgers import ReadOnlyLedger, TAAInfo


router = APIRouter()


class NamespaceList(BaseModel):
    """Namespace list."""

    namespaces: List[str]


@router.get("/namespace")
async def get_namespace(ledgers: LedgersDep) -> NamespaceList:
    """Return loaded namespaces."""
    return NamespaceList(namespaces=list(ledgers.ledgers.keys()))


@router.get("/taa/{namespace}", tags=["taa"])
async def get_taa(namespace: str, ledgers: LedgersDep) -> TAAInfo:
    """Get TAA for namespace."""
    pool = ledgers.get(namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {namespace} is unknown")

    async with ReadOnlyLedger(pool) as ledger:
        result = await ledger.get_txn_author_agreement()

    return result
