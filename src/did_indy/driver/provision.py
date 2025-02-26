"""Provisioning."""

import asyncio

from did_indy.driver.depends import lifespan


async def provision():
    """Provisioning"""
    async with lifespan(None):
        pass


def main():
    """Entrypoint."""
    asyncio.run(provision())
