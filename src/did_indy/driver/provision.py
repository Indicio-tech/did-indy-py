"""Provisioning."""

import asyncio

from driver_did_indy.depends import lifespan


async def provision():
    """Provisioning"""
    async with lifespan(None):
        pass


def main():
    """Entrypoint."""
    asyncio.run(provision())
