from pydantic import BaseModel


class ClientAutoEndorseRules(BaseModel):
    """Client auto endorsement rules."""

    new_nyms: int = 1
    nym_updates: bool = True
    nym_role_changes: bool = False
    schemas: bool = False
    cred_defs: bool = False
    rev_reg_defs: bool = True
    rev_reg_entries: bool = True


SCOPE_NYM_NEW = "nym:new"
SCOPE_NYM_UPDATE = "nym:update"
SCOPE_NYM_ROLE_CHANGE = "nym:role-change"
SCOPE_SCHEMA = "schema"
SCOPE_CRED_DEF = "cred-def"
SCOPE_REV_REG_DEF = "rev-reg-def"
SCOPE_REV_REG_ENTRY = "rev-reg-entry"

ALL_SCOPES = [
    SCOPE_NYM_NEW,
    SCOPE_NYM_UPDATE,
    SCOPE_NYM_ROLE_CHANGE,
    SCOPE_SCHEMA,
    SCOPE_CRED_DEF,
    SCOPE_REV_REG_DEF,
    SCOPE_REV_REG_ENTRY,
]


def derive_scopes(rules: ClientAutoEndorseRules) -> list[str]:
    """Derive scopes from rules."""
    scopes = []
    if rules.new_nyms > 0:
        scopes.append(SCOPE_NYM_NEW)

    if rules.nym_updates:
        scopes.append(SCOPE_NYM_UPDATE)

    if rules.nym_role_changes:
        scopes.append(SCOPE_NYM_ROLE_CHANGE)

    if rules.schemas:
        scopes.append(SCOPE_SCHEMA)

    if rules.cred_defs:
        scopes.append(SCOPE_CRED_DEF)

    if rules.rev_reg_defs:
        scopes.append(SCOPE_REV_REG_DEF)

    if rules.rev_reg_entries:
        scopes.append(SCOPE_REV_REG_ENTRY)

    return scopes
