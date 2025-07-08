"""Provisioning."""

import asyncio

from did_indy.driver.depends import lifespan


async def provision():
    """Provisioning"""
    async with lifespan(None):  # type: ignore
        pass


def main():
    """Entrypoint."""
    asyncio.run(provision())


if __name__ == "__main__":
    main()
