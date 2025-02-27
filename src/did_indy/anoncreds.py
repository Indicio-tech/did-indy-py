"""AnonCreds Indy support functions."""

import logging

from anoncreds import CredentialDefinition, Schema, RevocationRegistryDefinition
from indy_vdr import Request
from indy_vdr import ledger

from did_indy.did import parse_did_indy
from did_indy.models.anoncreds import (
    RevRegDef as RevRegDefModel,
    Schema as SchemaModel,
    CredDef as CredDefModel,
)
from did_indy.models.txn import RevRegDefTxnData

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
    schema: SchemaModel | Schema | dict,
) -> Request:
    """Create a schema request."""
    if isinstance(schema, Schema):
        schema = schema.to_dict()
    elif isinstance(schema, SchemaModel):
        schema = schema.model_dump(by_alias=True)

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


def indy_cred_def_id_from_did_url(cred_def_id: str) -> str:
    """Transform a did url for a cred def to the indy cred def id."""
    _, after_prefix = cred_def_id.rsplit(":", 1)
    origin, _, _, _, seq_no, tag = after_prefix.split("/")
    return make_indy_cred_def_id(origin, "CL", int(seq_no), tag)


def indy_cred_def_request(
    schema_seq_no: int,
    cred_def: CredDefModel | CredentialDefinition | dict,
) -> Request:
    """Create a cred def request."""
    if isinstance(cred_def, CredentialDefinition):
        cred_def = cred_def.to_dict()
    elif isinstance(cred_def, CredDefModel):
        cred_def = cred_def.model_dump(by_alias=True)

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


def make_rev_reg_def_id(did: str, ref: str, tag: str) -> str:
    """Make rev reg def id."""
    return f"{did}/anoncreds/v0/REV_REG_DEF/{ref}/{tag}"


def make_rev_reg_def_id_from_result(submitter: str, rev_reg_def: RevRegDefTxnData):
    """Get rev reg def id from result."""
    _, ref, _ = rev_reg_def.cred_def_id.rsplit(":", 2)
    return make_rev_reg_def_id(submitter, ref, rev_reg_def.tag)


def make_indy_rev_reg_def_id(
    submitter: str,
    indy_cred_def_id: str,
    revoc_def_type: str,
    tag: str,
) -> str:
    """Derive the revocation registry definition ID."""
    return f"{submitter}:4:{indy_cred_def_id}:{revoc_def_type}:{tag}"


def indy_rev_reg_def_request(
    rev_reg_def: RevRegDefModel | RevocationRegistryDefinition | dict,
) -> Request:
    """Create a rev reg def request."""
    if isinstance(rev_reg_def, RevocationRegistryDefinition):
        rev_reg_def = rev_reg_def.to_dict()
    if isinstance(rev_reg_def, RevRegDefModel):
        rev_reg_def = rev_reg_def.model_dump(by_alias=True)

    submitter = rev_reg_def["issuerId"]
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    indy_cred_def_id = indy_cred_def_id_from_did_url(rev_reg_def["credDefId"])
    rev_reg_def_id = make_indy_rev_reg_def_id(
        submitter, indy_cred_def_id, rev_reg_def["revocDefType"], rev_reg_def["tag"]
    )

    indy_rev_reg_def = {
        "ver": "1.0",
        "id": rev_reg_def_id,
        "revocDefType": rev_reg_def["revocDefType"],
        "credDefId": indy_cred_def_id,
        "tag": rev_reg_def["tag"],
        "value": {
            "issuanceType": "ISSUANCE_BY_DEFAULT",
            "maxCredNum": rev_reg_def["value"]["maxCredNum"],
            "publicKeys": rev_reg_def["value"]["publicKeys"],
            "tailsHash": rev_reg_def["value"]["tailsHash"],
            "tailsLocation": rev_reg_def["value"]["tailsLocation"],
        },
    }
    request = ledger.build_revoc_reg_def_request(
        submitter_did=submitter, revoc_reg_def=indy_rev_reg_def
    )
    return request
