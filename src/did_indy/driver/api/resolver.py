"""Resolver API."""

from fastapi import APIRouter, Security
from pydantic import BaseModel, Field

from did_indy.driver.auto_endorse import SCOPE_RESOLVE
from did_indy.driver.depends import ResolverDep
from did_indy.driver.security import client
from did_indy.models.anoncreds import CredDef, RevRegDef, RevStatusList, Schema
from did_indy.models.txn.deref import CredDefDeref, RevRegDefDeref, SchemaDeref

router = APIRouter(tags=["Resolver"])


@router.get("/resolve/{did}")
async def get_resolve_did(
    did: str,
    resolver: ResolverDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
):
    """Resolve a did:indy DID."""
    result = await resolver.resolve_did(did)

    return result


class ResolveRequest(BaseModel):
    """Resolve request."""

    did: str


@router.post("/resolve")
async def post_resolve(
    req: ResolveRequest,
    resolver: ResolverDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
):
    """Resolve a did:indy DID.

    This does exactly the same resolution as `GET /resolve/{did}` but uses the
    request body to send the DID to avoid having to encode the did.
    """
    result = await resolver.resolve_did(req.did)

    return result


class SchemaDerefRequest(BaseModel):
    """Dereference request."""

    schema_id: str


class SchemaDerefResponse(BaseModel):
    """Dereference response"""

    schema_value: Schema = Field(alias="schema")
    deref: SchemaDeref


@router.post("/dereference/schema")
async def post_dereference_schema(
    req: SchemaDerefRequest,
    resolver: ResolverDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> SchemaDerefResponse:
    """Dereference a DID URL."""
    schema, deref = await resolver.get_schema(req.schema_id)

    return SchemaDerefResponse(schema=schema, deref=deref)


class CredDefDerefRequest(BaseModel):
    """Dereference request."""

    cred_def_id: str


class CredDefDerefResponse(BaseModel):
    """Dereference response"""

    cred_def: CredDef
    deref: CredDefDeref


@router.post("/dereference/cred-def")
async def post_dereference_cred_def(
    req: CredDefDerefRequest,
    resolver: ResolverDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> CredDefDerefResponse:
    """Dereference a DID URL."""
    cred_def, deref = await resolver.get_cred_def(req.cred_def_id)

    return CredDefDerefResponse(cred_def=cred_def, deref=deref)


class RevRegDefDerefRequest(BaseModel):
    """Dereference request."""

    rev_reg_def_id: str


class RevRegDefDerefResponse(BaseModel):
    """Dereference response"""

    rev_ref_def: RevRegDef
    deref: RevRegDefDeref


@router.post("/dereference/rev-reg-def")
async def post_dereference_rev_reg_def(
    req: RevRegDefDerefRequest,
    resolver: ResolverDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> RevRegDefDerefResponse:
    """Dereference a DID URL."""
    rev_reg_def, deref = await resolver.get_rev_reg_def(req.rev_reg_def_id)

    return RevRegDefDerefResponse(rev_ref_def=rev_reg_def, deref=deref)


class ResolveRevStatusListRequest(BaseModel):
    """Resolve rev status list request."""

    rev_reg_def_id: str
    timestamp_from: int | None = 0
    timestamp_to: int | None = None


@router.post("/resolve/rev-status-list")
async def post_resolve_rev_status_list(
    req: ResolveRevStatusListRequest,
    resolver: ResolverDep,
    _=Security(client, scopes=[SCOPE_RESOLVE]),
) -> RevStatusList:
    """Resolve a revocation status list."""
    result = await resolver.get_rev_status_list(
        rev_reg_def_id=req.rev_reg_def_id,
        timestamp_from=req.timestamp_from,
        timestamp_to=req.timestamp_to,
    )

    return result
