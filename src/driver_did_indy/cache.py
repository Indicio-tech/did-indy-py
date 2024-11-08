"""Cache with Passive Expiry."""

import asyncio
import heapq
import logging
import time
from typing import Any, Dict, List, Tuple


LOGGER = logging.getLogger(__name__)


class Cache:
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

    async def set(self, keys: str | List[str], value: Any, ttl: float):
        """Set a value with TTL."""
        if isinstance(keys, list):
            pass
        else:
            keys = [keys]

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


async def main():
    """Example."""
    cache = Cache()
    await cache.set("key1", "value1", 5)  # key1 will expire in 5 seconds
    await asyncio.sleep(1)
    await cache.set("key2", "value2", 5)  # key2 will expire in 5 seconds
    await asyncio.sleep(7)
    print(await cache.get("key1"))  # Should print None as key1 has expired
    print(await cache.get("key2"))  # Should print None as key2 has expired


if __name__ == "__main__":
    asyncio.run(main())
