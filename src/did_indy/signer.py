"""Signature abstraction to enable flexible cryptography backends."""

from typing import Awaitable, Callable

Signer = Callable[[bytes], bytes | Awaitable[bytes]]


async def sign_message(sign: Signer, message: bytes) -> bytes:
    """Sign a message.

    The signer must either be a callable returning bytes or a callable returning
    an awaitable of bytes.
    """
    value = sign(message)
    if isinstance(value, bytes):
        return value

    # If you give anything other than an awaitable, this will raise a TypeError.
    # Callers be warned!
    return await value
