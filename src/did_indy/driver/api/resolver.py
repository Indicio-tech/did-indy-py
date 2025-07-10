"""Resolver API."""

from fastapi import APIRouter, HTTPException, Security
from pydantic import BaseModel

from did_indy.did import parse_did_indy, parse_did_indy_from_url
from did_indy.driver.auto_endorse import SCOPE_RESOLVE
from did_indy.driver.depends import LedgersDep
from did_indy.driver.security import client
from did_indy.models.anoncreds import CredDef, RevRegDef, RevStatusList, Schema
from did_indy.resolver import Resolver

router = APIRouter(tags=["Resolver"])


@router.get("/resolve/{did}")
async def get_resolve_did(
    did: str,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
):
    """Resolve a did:indy DID."""
    parsed = parse_did_indy(did)

    pool = ledgers.get(parsed.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {parsed.namespace} is unknown")

    async with Resolver(pool) as resolver:
        result = await resolver.resolve_did(did)

    return result


class ResolveRequest(BaseModel):
    """Resolve request."""

    did: str


@router.post("/resolve")
async def post_resolve(
    req: ResolveRequest,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
):
    """Resolve a did:indy DID.

    This does exactly the same resolution as `GET /resolve/{did}` but uses the
    request body to send the DID to avoid having to encode the did.
    """
    parsed = parse_did_indy(req.did)

    pool = ledgers.get(parsed.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {parsed.namespace} is unknown")

    async with Resolver(pool) as resolver:
        result = await resolver.resolve_did(req.did)

    return result


class SchemaDerefRequest(BaseModel):
    """Dereference request."""

    schema_id: str


@router.post("/dereference/schema")
async def post_dereference_schema(
    req: SchemaDerefRequest,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> Schema:
    """Dereference a DID URL."""
    parsed = parse_did_indy_from_url(req.schema_id)

    pool = ledgers.get(parsed.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {parsed.namespace} is unknown")

    async with Resolver(pool) as resolver:
        result = await resolver.get_schema(req.schema_id)

    return result


class CredDefDerefRequest(BaseModel):
    """Dereference request."""

    cred_def_id: str


@router.post("/dereference/cred-def")
async def post_dereference_cred_def(
    req: CredDefDerefRequest,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> CredDef:
    """Dereference a DID URL."""
    parsed = parse_did_indy_from_url(req.cred_def_id)

    pool = ledgers.get(parsed.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {parsed.namespace} is unknown")

    async with Resolver(pool) as resolver:
        result = await resolver.get_cred_def(req.cred_def_id)

    return result


class RevRegDefDerefRequest(BaseModel):
    """Dereference request."""

    rev_reg_def_id: str


@router.post("/dereference/rev-reg-def")
async def post_dereference_rev_reg_def(
    req: RevRegDefDerefRequest,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> RevRegDef:
    """Dereference a DID URL."""
    parsed = parse_did_indy_from_url(req.rev_reg_def_id)

    pool = ledgers.get(parsed.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {parsed.namespace} is unknown")

    async with Resolver(pool) as resolver:
        result = await resolver.get_rev_reg_def(req.rev_reg_def_id)

    return result


class ResolveRevStatusListRequest(BaseModel):
    """Resolve rev status list request."""

    rev_reg_def_id: str
    timestamp_from: int | None = 0
    timestamp_to: int | None = None


@router.post("/resolve/rev-status-list")
async def post_resolve_rev_status_list(
    req: ResolveRevStatusListRequest,
    ledgers: LedgersDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> RevStatusList:
    """Resolve a revocation status list."""
    parsed = parse_did_indy_from_url(req.rev_reg_def_id)

    pool = ledgers.get(parsed.namespace)
    if not pool:
        raise HTTPException(404, detail=f"Namespace {parsed.namespace} is unknown")

    async with Resolver(pool) as resolver:
        result = await resolver.get_rev_status_list(
            rev_reg_def_id=req.rev_reg_def_id,
            timestamp_from=req.timestamp_from,
            timestamp_to=req.timestamp_to,
        )

    return result
