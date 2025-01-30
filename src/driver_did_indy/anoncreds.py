"""AnonCreds Indy support functions."""

import logging

from anoncreds import CredentialDefinition, Schema
from indy_vdr import Request
from indy_vdr import ledger

from driver_did_indy.did import parse_did_indy

LOGGER = logging.getLogger(__name__)


def make_schema_id(issuer_id: str, name: str, version: str, **_):
    """Make schema id from parts."""
    return f"{issuer_id}/anoncreds/v0/SCHEMA/{name}/{version}"


def make_schema_id_from_schema(schema: Schema | dict):
    """Make a schema id from a schema object."""
    if isinstance(schema, Schema):
        schema = schema.to_dict()

    return make_schema_id(issuer_id=schema.pop("issuerId"), **schema)


def make_indy_schema_id(issuer_id: str, name: str, version: str, **_):
    """Make indy schema id from parts."""
    if issuer_id.startswith("did:indy:"):
        nym = parse_did_indy(issuer_id).nym
    elif issuer_id.startswith("did:"):
        raise ValueError("Only nyms or did:indy DIDs expected")
    else:
        nym = issuer_id

    return f"{nym}:2:{name}:{version}"


def make_indy_schema_id_from_schema(schema: Schema | dict):
    """Make an indy schema id from a schema object."""
    if isinstance(schema, Schema):
        schema = schema.to_dict()

    return make_indy_schema_id(issuer_id=schema.pop("issuerId"), **schema)


def indy_schema_request(
    schema: Schema | dict,
) -> Request:
    """Create a schema request."""
    if isinstance(schema, Schema):
        schema = schema.to_dict()
    print(schema)

    submitter = schema["issuerId"]
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    schema_id = make_indy_schema_id(submitter, **schema)
    indy_schema = {
        "ver": "1.0",
        "id": schema_id,
        "name": schema["name"],
        "version": schema["version"],
        "attrNames": schema["attrNames"],
        "seqNo": None,
    }
    request = ledger.build_schema_request(submitter, indy_schema)
    return request


def make_indy_cred_def_id(nym: str, type: str, schema_seq_no: int, tag: str) -> str:
    """Make indy cred def ID."""
    return f"{nym}:3:{type}:{schema_seq_no}:{tag}"


def make_cred_def_id(did: str, ref: str, tag: str) -> str:
    """Make cred def ID."""
    return f"{did}/anoncreds/v0/CLAIM_DEF/{ref}/{tag}"


def indy_cred_def_request(
    schema_seq_no: int,
    cred_def: CredentialDefinition | dict,
) -> Request:
    """Create a cred def request."""
    if isinstance(cred_def, CredentialDefinition):
        cred_def = cred_def.to_dict()

    submitter = cred_def["issuerId"]
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    cred_def_id = make_indy_cred_def_id(
        submitter, cred_def["type"], schema_seq_no, cred_def["tag"]
    )
    indy_cred_def = {
        "id": cred_def_id,
        "schemaId": str(schema_seq_no),
        "tag": cred_def["tag"],
        "type": cred_def["type"],
        "value": cred_def["value"],
        "ver": "1.0",
    }
    request = ledger.build_cred_def_request(
        submitter_did=submitter, cred_def=indy_cred_def
    )
    return request
