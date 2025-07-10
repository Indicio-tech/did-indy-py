"""AnonCreds Indy support functions."""

import logging
from typing import Any

from anoncreds import (
    CredentialDefinition,
    RevocationRegistryDefinition,
    RevocationStatusList,
)
from anoncreds import (
    Schema as ACSchema,
)
from indy_vdr import Request, ledger

from did_indy.did import parse_did_indy
from did_indy.models.anoncreds import (
    CredDef,
    RevRegDef,
    RevStatusList,
    Schema,
)
from did_indy.models.txn import CredDefTxnData, RevRegDefTxnData

LOGGER = logging.getLogger(__name__)


SchemaTypes = Schema | ACSchema | dict


def normalize_schema_representation(schema: SchemaTypes | Any) -> Schema:
    """Normalize the schema representation to our native representation."""
    if isinstance(schema, Schema):
        return schema
    elif isinstance(schema, ACSchema):
        return Schema.model_validate(schema.to_dict())
    elif isinstance(schema, dict):
        return Schema.model_validate(schema)

    raise TypeError(f"Invalid schema type: {type(schema)}")


CredDefTypes = CredDef | CredentialDefinition | dict


def normalize_cred_def_representation(cred_def: CredDefTypes | Any) -> CredDef:
    """Normalize the cred def representation to our native representation."""
    if isinstance(cred_def, CredDef):
        return cred_def
    elif isinstance(cred_def, CredentialDefinition):
        return CredDef.model_validate(cred_def.to_dict())
    elif isinstance(cred_def, dict):
        return CredDef.model_validate(cred_def)

    raise TypeError(f"Invalid cred_def type: {type(cred_def)}")


RevRegDefTypes = RevRegDef | RevocationRegistryDefinition | dict


def normalize_rev_reg_def_representation(
    rev_reg_def: RevRegDefTypes | Any,
) -> RevRegDef:
    """Normalize the rev reg def representation to our native representation."""
    if isinstance(rev_reg_def, RevRegDef):
        return rev_reg_def
    elif isinstance(rev_reg_def, RevocationRegistryDefinition):
        return RevRegDef.model_validate(rev_reg_def.to_dict())
    elif isinstance(rev_reg_def, dict):
        return RevRegDef.model_validate(rev_reg_def)

    raise TypeError(f"Invalid rev_reg_def type: {type(rev_reg_def)}")


RevStatusListTypes = RevStatusList | RevocationStatusList | dict


def normalize_rev_status_list_representation(
    rev_status_list: RevStatusListTypes | Any,
) -> RevStatusList:
    """Normalize the rev status list representation to our native representation."""
    if isinstance(rev_status_list, RevStatusList):
        return rev_status_list
    elif isinstance(rev_status_list, RevocationStatusList):
        return RevStatusList.model_validate(rev_status_list.to_dict())
    elif isinstance(rev_status_list, dict):
        return RevStatusList.model_validate(rev_status_list)

    raise TypeError(f"Invalid rev_status_list type: {type(rev_status_list)}")


def make_schema_id(issuer_id: str, name: str, version: str):
    """Make schema id from parts."""
    return f"{issuer_id}/anoncreds/v0/SCHEMA/{name}/{version}"


def make_indy_schema_id(issuer_id: str, name: str, version: str):
    """Make indy schema id from parts."""
    if issuer_id.startswith("did:indy:"):
        nym = parse_did_indy(issuer_id).nym
    elif issuer_id.startswith("did:"):
        raise ValueError("Only nyms or did:indy DIDs expected")
    else:
        nym = issuer_id

    return f"{nym}:2:{name}:{version}"


def make_indy_schema_id_from_schema(schema: SchemaTypes) -> str:
    """Derive the indy schema ID for a schema."""
    schema = normalize_schema_representation(schema)
    return make_indy_schema_id(schema.issuer_id, schema.name, schema.version)


def make_schema_id_from_schema(schema: SchemaTypes) -> str:
    """Derive the DID Url for a schema."""
    schema = normalize_schema_representation(schema)
    return make_schema_id(schema.issuer_id, schema.name, schema.version)


def indy_schema_request(
    schema: SchemaTypes,
) -> Request:
    """Create a schema request."""
    schema = normalize_schema_representation(schema)

    submitter = schema.issuer_id
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    schema_id = make_indy_schema_id_from_schema(schema)
    indy_schema = {
        "ver": "1.0",
        "id": schema_id,
        "name": schema.name,
        "version": schema.version,
        "attrNames": schema.attr_names,
        "seqNo": None,
    }
    request = ledger.build_schema_request(submitter, indy_schema)
    return request


def make_indy_cred_def_id(nym: str, type: str, schema_seq_no: int, tag: str) -> str:
    """Make indy cred def ID."""
    return f"{nym}:3:{type}:{schema_seq_no}:{tag}"


def make_cred_def_id(did: str, ref: int | str, tag: str) -> str:
    """Make cred def ID."""
    return f"{did}/anoncreds/v0/CLAIM_DEF/{ref}/{tag}"


def make_cred_def_id_from_indy(namespace: str, indy_cred_def_id) -> str:
    """Make cred def ID."""
    nym, _, _, ref, tag = indy_cred_def_id.split(":")
    return f"did:indy:{namespace}:{nym}/anoncreds/v0/CLAIM_DEF/{ref}/{tag}"


def make_indy_cred_def_id_from_result(nym: str, cred_def: CredDefTxnData) -> str:
    """Make cred def ID."""
    return make_indy_cred_def_id(
        nym, cred_def.signature_type, cred_def.ref, cred_def.tag
    )


def make_indy_cred_def_id_from_cred_def(
    nym: str, cred_def: CredDef, schema_seq_no: int
) -> str:
    """Make cred def ID."""
    return make_indy_cred_def_id(nym, cred_def.type, schema_seq_no, cred_def.tag)


def make_cred_def_id_from_result(did: str, cred_def: CredDefTxnData) -> str:
    """Make cred def ID."""
    return make_cred_def_id(did, cred_def.ref, cred_def.tag)


def indy_cred_def_id_from_did_url(cred_def_id: str) -> str:
    """Transform a did url for a cred def to the indy cred def id."""
    _, after_prefix = cred_def_id.rsplit(":", 1)
    origin, _, _, _, seq_no, tag = after_prefix.split("/")
    return make_indy_cred_def_id(origin, "CL", int(seq_no), tag)


def indy_cred_def_request(
    schema_seq_no: int,
    cred_def: CredDefTypes,
) -> Request:
    """Create a cred def request."""
    cred_def = normalize_cred_def_representation(cred_def)

    submitter = cred_def.issuer_id
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    cred_def_id = make_indy_cred_def_id(
        submitter, cred_def.type, schema_seq_no, cred_def.tag
    )
    indy_cred_def = {
        "id": cred_def_id,
        "schemaId": str(schema_seq_no),
        "tag": cred_def.tag,
        "type": cred_def.type,
        "value": cred_def.value,
        "ver": "1.0",
    }
    request = ledger.build_cred_def_request(
        submitter_did=submitter, cred_def=indy_cred_def
    )
    return request


def make_rev_reg_def_id(did: str, ref: str, name: str, tag: str) -> str:
    """Make rev reg def id."""
    return f"{did}/anoncreds/v0/REV_REG_DEF/{ref}/{name}/{tag}"


def make_rev_reg_def_id_from_result(submitter: str, rev_reg_def: RevRegDefTxnData):
    """Get rev reg def id from result."""
    _, ref, name = rev_reg_def.cred_def_id.rsplit(":", 2)
    return make_rev_reg_def_id(submitter, ref, name, rev_reg_def.tag)


def make_indy_rev_reg_def_id(
    submitter: str,
    indy_cred_def_id: str,
    revoc_def_type: str,
    tag: str,
) -> str:
    """Derive the revocation registry definition ID."""
    return f"{submitter}:4:{indy_cred_def_id}:{revoc_def_type}:{tag}"


def make_indy_rev_reg_def_id_from_did_url(rev_reg_def_id: str) -> str:
    """Derive indy rev reg def id from DID URL."""
    did, _, _, _, ref, name, tag = rev_reg_def_id.split("/")
    did = parse_did_indy(did)
    cred_def_id = make_indy_cred_def_id(did.nym, "CL", int(ref), name)
    return make_indy_rev_reg_def_id(did.nym, cred_def_id, "CL_ACCUM", tag)


def indy_rev_reg_def_request(
    rev_reg_def: RevRegDefTypes,
) -> Request:
    """Create a rev reg def request."""
    rev_reg_def = normalize_rev_reg_def_representation(rev_reg_def)

    submitter = rev_reg_def.issuer_id
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    indy_cred_def_id = indy_cred_def_id_from_did_url(rev_reg_def.cred_def_id)
    rev_reg_def_id = make_indy_rev_reg_def_id(
        submitter, indy_cred_def_id, rev_reg_def.revoc_def_type, rev_reg_def.tag
    )

    indy_rev_reg_def = {
        "ver": "1.0",
        "id": rev_reg_def_id,
        "revocDefType": rev_reg_def.revoc_def_type,
        "credDefId": indy_cred_def_id,
        "tag": rev_reg_def.tag,
        "value": {
            "issuanceType": "ISSUANCE_BY_DEFAULT",
            "maxCredNum": rev_reg_def.value.max_cred_num,
            "publicKeys": rev_reg_def.value.public_keys,
            "tailsHash": rev_reg_def.value.tails_hash,
            "tailsLocation": rev_reg_def.value.tails_location,
        },
    }
    request = ledger.build_revoc_reg_def_request(
        submitter_did=submitter, revoc_reg_def=indy_rev_reg_def
    )
    return request


def indy_rev_reg_initial_entry_request(status_list: RevStatusListTypes) -> Request:
    """Create an initial revocation entry request."""
    status_list = normalize_rev_status_list_representation(status_list)

    submitter = status_list.issuer_id
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    indy_rev_reg_entry = {
        "ver": "1.0",
        "value": {"accum": status_list.current_accumulator},
    }
    request = ledger.build_revoc_reg_entry_request(
        submitter,
        make_indy_rev_reg_def_id_from_did_url(status_list.rev_reg_def_id),
        "CL_ACCUM",
        indy_rev_reg_entry,
    )
    return request


def indy_rev_reg_entry_request(
    prev_accum: str,
    curr_list: RevStatusListTypes,
    revoked: list[int],
) -> Request:
    """Create a revocation entry request."""
    curr_list = normalize_rev_status_list_representation(curr_list)

    submitter = curr_list.issuer_id
    if submitter.startswith("did:indy:"):
        submitter = parse_did_indy(submitter).nym

    indy_rev_reg_entry = {
        "ver": "1.0",
        "value": {
            "accum": curr_list.current_accumulator,
            "prevAccum": prev_accum,
            "revoked": revoked,
        },
    }
    request = ledger.build_revoc_reg_entry_request(
        submitter,
        make_indy_rev_reg_def_id_from_did_url(curr_list.rev_reg_def_id),
        "CL_ACCUM",
        indy_rev_reg_entry,
    )

    return request
