"""Transaction Author Agreement endpoints."""

from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from did_indy.models.taa import TAAInfo
from driver_did_indy.depends import LedgersDep, StoreDep
from did_indy.ledger import ReadOnlyLedger
from driver_did_indy.ledgers import get_nym_and_key


router = APIRouter()


class NamespaceInfo(BaseModel):
    """Namespace info"""

    namespace: str
    nym: str
    did: str


class NamespaceList(BaseModel):
    """Namespace list."""

    namespaces: List[NamespaceInfo]


@router.get("/info")
async def get_info(ledgers: LedgersDep, store: StoreDep) -> NamespaceList:
    """Return loaded namespaces."""
    results = []
    for namespace in ledgers.ledgers.keys():
        nym, _ = await get_nym_and_key(store, namespace)
        results.append(
            NamespaceInfo(
                namespace=namespace,
                nym=nym,
                did=f"did:indy:{namespace}:{nym}",
            )
        )
    return NamespaceList(namespaces=results)


@router.get("/taa/{namespace}", tags=["taa"])
async def get_taa(namespace: str, ledgers: LedgersDep) -> TAAInfo:
    """Get TAA for namespace."""
    pool = ledgers.get(namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {namespace} is unknown")

    async with ReadOnlyLedger(pool) as ledger:
        result = await ledger.get_txn_author_agreement()

    return result
