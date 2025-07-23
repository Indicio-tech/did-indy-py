"""Ledger registry."""

from typing import Mapping, Tuple, cast

from aries_askar import Key, Store

from did_indy.ledger import LedgerPool


async def store_nym_and_key(store: Store, namespace: str, nym: str, key: Key):
    """Store nym and key for a namespace."""
    async with store.session() as session:
        entry = await session.fetch_key(name=namespace, for_update=True)
        if not entry:
            await session.insert_key(
                name=namespace,
                key=key,
                tags={"nym": nym},
            )
        else:
            prior = cast(Key, entry.key)
            if prior.get_public_bytes() != key.get_public_bytes():
                await session.remove_key(namespace)
                await session.insert_key(
                    name=namespace,
                    key=key,
                    tags={"nym": nym},
                )


class NymNotFoundError(Exception):
    """Raised when no nym is found for ledger."""


async def get_nym_and_key(store: Store, namespace: str) -> Tuple[str, Key]:
    """Retrieve our nym and key for this ledger."""
    async with store.session() as session:
        entry = await session.fetch_key(namespace)
    if not entry:
        raise NymNotFoundError(f"No nym found for {namespace}")

    key = cast(Key, entry.key)
    tags = cast(dict, entry.tags)
    nym = tags.get("nym")
    assert nym, "Key was saved without a nym tag"
    return nym, key


class UnknownNamespaceError(Exception):
    """Raised when an unknown namespace is encountered."""

    def __init__(self, namespace: str):
        """Init exception."""
        self.namespace = namespace


class Ledgers:
    """Registry of ledgers, identified by namespace."""

    def __init__(self, ledgers: Mapping[str, LedgerPool] | None = None):
        self.ledgers = dict(ledgers) if ledgers else {}

    def add(self, namespace: str, pool: LedgerPool):
        """Add to the registry."""
        self.ledgers[namespace] = pool

    def get_or(self, namespace: str) -> LedgerPool | None:
        """Get a ledger by namespace."""
        return self.ledgers.get(namespace)

    def get(self, namespace: str) -> LedgerPool:
        """Get a ledger by namespace."""
        pool = self.ledgers.get(namespace)
        if not pool:
            raise UnknownNamespaceError(namespace)

        return pool

    def get_pool(self, namespace: str) -> LedgerPool:
        """Alias to match PoolProvider protocol."""
        return self.get(namespace)
