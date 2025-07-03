"""Test the models against ledger responses."""

from did_indy.models.txn import (
    CredDefTxnData,
    NymTxnData,
    RevRegDefTxnData,
    RevRegEntryTxnData,
    SchemaTxnData,
    TxnResult,
)

from .data.responses.cred_def import CRED_DEF_RESPONSES
from .data.responses.nym import NYM_RESPONSES
from .data.responses.rev_reg_def import REV_REG_DEF_RESPONSES
from .data.responses.rev_reg_entry import REV_REG_ENTRY_RESPONSES
from .data.responses.schema import SCHEMA_RESPONSES


def test_nym():
    for resp in NYM_RESPONSES:
        TxnResult[NymTxnData].model_validate(resp)


def test_schema():
    for resp in SCHEMA_RESPONSES:
        TxnResult[SchemaTxnData].model_validate(resp)


def test_cred_def():
    for resp in CRED_DEF_RESPONSES:
        TxnResult[CredDefTxnData].model_validate(resp)


def test_rev_reg_def():
    for resp in REV_REG_DEF_RESPONSES:
        TxnResult[RevRegDefTxnData].model_validate(resp)


def test_rev_reg_entry():
    for resp in REV_REG_ENTRY_RESPONSES:
        TxnResult[RevRegEntryTxnData].model_validate(resp)
