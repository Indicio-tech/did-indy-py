"""Cache with Passive Expiry."""

import asyncio
import heapq
import logging
import time
from typing import Any, Dict, List, Protocol, Tuple


LOGGER = logging.getLogger(__name__)

DEFAULT_TTL = 600.0


class Cache(Protocol):
    """Cache Protocol."""

    async def set(self, keys: str | List[str], value: Any, ttl: float | None = None):
        """Set a value with TTL."""
        ...

    async def get(self, key: str) -> Any:
        """Get a value, expiring any stale keys."""
        ...

    async def clear(self, key: str):
        """Clear a key."""
        ...

    async def flush(self):
        """Remove all items from the cache."""
        ...


class BasicCache(Cache):
    """KV Cache with TTL expiry on access."""

    def __init__(self):
        """Initialize the store."""
        self.cache: Dict[str, Any] = {}
        self.expiry_heap: List[Tuple[float, str]] = []
        self.lock = asyncio.Lock()

    def _expire_keys(self):
        """Expire keys that have passed their TTL."""
        now = time.time()
        while self.expiry_heap and self.expiry_heap[0][0] <= now:
            _, key = heapq.heappop(self.expiry_heap)
            if self.cache.get(key) is not None:
                LOGGER.debug("Expiring key: %s", key)
                self.cache.pop(key, None)

    async def set(self, keys: str | List[str], value: Any, ttl: float | None = None):
        """Set a value with TTL."""
        if isinstance(keys, list):
            pass
        else:
            keys = [keys]

        if ttl is None:
            ttl = DEFAULT_TTL

        async with self.lock:
            LOGGER.debug("Set: %s", keys)
            self._expire_keys()
            expire_time = time.time() + ttl
            for key in keys:
                self.cache[key] = value
                heapq.heappush(self.expiry_heap, (expire_time, key))

    async def get(self, key: str) -> Any:
        """Get a value, expiring any stale keys."""
        async with self.lock:
            LOGGER.debug("Get: %s", key)
            self._expire_keys()
            return self.cache.get(key)

    async def clear(self, key: str):
        """Clear a key."""
        async with self.lock:
            LOGGER.debug("Delete: %s", key)
            self.cache.pop(key, None)

    async def flush(self):
        """Remove all items from the cache."""
        self.cache = {}
