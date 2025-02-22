"""TAA utility functions."""

from datetime import date, datetime, timezone
from aries_askar import Store
from did_indy.ledger import LedgerPool
from did_indy.models.taa import TAARecord, TaaAcceptance


def taa_rough_timestamp() -> int:
    """Get a timestamp accurate to the day.

    Anything more accurate is a privacy concern.
    """
    return int(
        datetime.combine(date.today(), datetime.min.time(), timezone.utc).timestamp()
    )


async def accept_txn_author_agreement(
    pool: LedgerPool,
    store: Store,
    taa_record: TAARecord,
    mechanism: str,
    accept_time: int | None = None,
) -> TaaAcceptance:
    """Save a new record recording the acceptance of the TAA."""
    if not accept_time:
        accept_time = taa_rough_timestamp()

    taa = TaaAcceptance(
        taaDigest=taa_record.digest,
        mechanism=mechanism,
        time=accept_time,
    )
    async with store.session() as session:
        prior = await session.fetch("taa_accepted", pool.name, for_update=True)
        if prior:
            await session.replace(
                "taa_accepted", pool.name, value_json=taa.model_dump()
            )
        else:
            await session.insert("taa_accepted", pool.name, value_json=taa.model_dump())

    cache_key = "taa_accepted:" + pool.name
    await pool.cache.set(cache_key, taa, pool.cache_duration)
    return taa


async def get_latest_txn_author_acceptance(
    pool: LedgerPool, store: Store
) -> TaaAcceptance | None:
    """Look up the latest TAA acceptance."""
    cache_key = "taa_accepted:" + pool.name
    taa = await pool.cache.get(cache_key)
    if not taa:
        async with store.session() as session:
            entry = await session.fetch("taa_accepted", pool.name)
        if entry:
            taa = TaaAcceptance.model_validate(entry.value_json)
        else:
            taa = None
        await pool.cache.set(cache_key, taa, pool.cache_duration)
    return taa
