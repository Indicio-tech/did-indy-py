"""Utilities."""

import asyncio
from dataclasses import dataclass
from hashlib import sha256

from base58 import b58decode, b58encode
from httpx import AsyncClient, HTTPStatusError, Response


class RepeatAttempt:
    """Represents the current iteration in a repeat sequence."""

    def __init__(self, seq: "RepeatSequence", index: int = 1):
        """Initialize the attempt instance."""
        self.index = index
        self.seq = seq

    def next(self) -> "RepeatAttempt":
        """Get the next attempt instance."""
        if self.final:
            raise StopIteration
        self.index += 1
        return self

    async def __anext__(self) -> "RepeatAttempt":
        """Implement async iterator protocol to wait between attempts."""
        if not self.index:
            self.index = 1
            return self
        else:
            if self.final:
                raise StopAsyncIteration
            interval = self.next_interval
            if interval:
                await asyncio.sleep(interval)
            self.index += 1
            return self

    @property
    def final(self) -> bool:
        """Check if this is the last instance in the sequence."""
        return bool(self.seq.limit and self.index >= self.seq.limit)

    @property
    def next_interval(self) -> float:
        """Calculate the interval before the next attempt."""
        return self.seq.next_interval(self.index)

    def timeout(self, interval: float | None = None):
        """Create a context manager for timing out an attempt."""
        return asyncio.timeout(self.next_interval if interval is None else interval)

    def __repr__(self) -> str:
        """Format as a string for debugging."""
        return f"<{self.__class__.__name__} index={self.index} seq={self.seq}>"


class RepeatSequence:
    """Represents a repetition sequence."""

    def __init__(self, limit: int = 0, interval: float = 0.0, backoff: float = 0.0):
        """Initialize the sequence instance."""
        self.limit = limit
        self.interval = interval
        self.backoff = backoff

    def next_interval(self, index: int) -> float:
        """Calculate the time before the next attempt."""
        return pow(self.interval, 1 + (self.backoff * (index - 1)))

    def start(self) -> RepeatAttempt:
        """Get the first attempt in the sequence."""
        return RepeatAttempt(self)

    def __iter__(self):
        """Create a generator for the repeat attempts."""
        attempt = self.start()
        while True:
            yield attempt
            if attempt.final:
                break
            attempt = attempt.next()

    def __aiter__(self):
        """Implement async iterator protocol to wait between attempts."""
        return RepeatAttempt(self, index=0)

    def __repr__(self) -> str:
        """Format as a string for debugging."""
        return (
            f"<{self.__class__.__name__} "
            f"limit={self.limit} interval={self.interval} backoff={self.backoff}>"
        )


class FetchError(Exception):
    """Error raised when an HTTP fetch fails."""


async def fetch(
    url: str,
    *,
    headers: dict | None = None,
    retry: bool = True,
    max_attempts: int = 5,
    interval: float = 1.0,
    backoff: float = 0.25,
    request_timeout: float = 10.0,
    json: bool = False,
):
    """Fetch from an HTTP server with automatic retries and timeouts.

    Args:
        url: the address to fetch
        headers: an optional dict of headers to send
        retry: flag to retry the fetch
        max_attempts: the maximum number of attempts to make
        interval: the interval between retries, in seconds
        backoff: the backoff interval, in seconds
        request_timeout: the HTTP request timeout, in seconds
        json: flag to parse the result as JSON

    """
    limit = max_attempts if retry else 1
    session = AsyncClient()
    async with session:
        async for attempt in RepeatSequence(limit, interval, backoff):
            try:
                async with attempt.timeout(request_timeout):
                    response: Response = await session.get(url, headers=headers)
                    response.raise_for_status()
                    return await response.json() if json else response.text
            except (HTTPStatusError, asyncio.TimeoutError) as e:
                if attempt.final:
                    raise FetchError("Exceeded maximum fetch attempts") from e


@dataclass
class DidIndy:
    """Parsed did:indy DID."""

    namespace: str
    nym: str


def parse_did_indy(did: str) -> DidIndy:
    """Extract info from a did:indy DID."""
    method_and_namespace, nym = did.rsplit(":", maxsplit=1)
    namespace = method_and_namespace.removeprefix("did:indy:")
    return DidIndy(namespace, nym)


def nym_from_verkey(verkey: str, version: int = 2) -> str:
    """Generate a nym from a verkey."""
    key = b58decode(verkey)
    if version == 2:
        nym = b58encode(sha256(key).digest()[:16]).decode()
    else:
        nym = b58encode(key[:16]).decode()
    return nym
