"""Test did parsing."""

import pytest

from did_indy.did import parse_did_indy, parse_did_indy_from_url


@pytest.mark.parametrize(
    ("did", "namespace", "nym"),
    [
        ("did:indy:indicio:test:abc123", "indicio:test", "abc123"),
        ("did:indy:indicio:demo:abc123", "indicio:demo", "abc123"),
        ("did:indy:indicio:abc123", "indicio", "abc123"),
        ("did:indy:sovrin:abc123", "sovrin", "abc123"),
    ],
)
def test_parse_did_indy(did: str, namespace: str, nym: str):
    """Test parsing a did:indy"""
    did_indy = parse_did_indy(did)
    assert did_indy.namespace == namespace
    assert did_indy.nym == nym


@pytest.mark.parametrize(
    ("did_url", "namespace", "nym"),
    [
        (
            "did:indy:sovrin:F72i3Y3Q4i466efjYJYCHM/anoncreds/v0/SCHEMA/npdb/4.3.4",
            "sovrin",
            "F72i3Y3Q4i466efjYJYCHM",
        ),
        ("did:indy:indicio:demo:abc123#verkey", "indicio:demo", "abc123"),
        ("did:indy:indicio:abc123?test=123", "indicio", "abc123"),
    ],
)
def test_parse_did_indy_from_url(did_url: str, namespace: str, nym: str):
    """Test parsing a did:indy from a url."""
    did_indy = parse_did_indy_from_url(did_url)
    assert did_indy.namespace == namespace
    assert did_indy.nym == nym
