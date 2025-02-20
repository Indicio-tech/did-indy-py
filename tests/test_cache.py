"""Test Cache."""

import asyncio

import pytest

from driver_did_indy.cache import BasicCache


@pytest.mark.asyncio
async def test_cache():
    cache = BasicCache()

    await cache.set("key1", "value1", 0.1)
    await cache.set("key2", "value2", 0.5)
    assert await cache.get("key1") == "value1"
    await asyncio.sleep(0.25)
    assert await cache.get("key1") is None

    assert await cache.get("key2") == "value2"
    await asyncio.sleep(0.25)
    assert await cache.get("key2") is None
