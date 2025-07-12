import logging.config
from os import getenv

from fastapi import FastAPI

from did_indy.driver.config import Config
from did_indy.driver.depends import lifespan

from .api import clients, namespaces, resolver, txns
from .webhooks import webhooks

LOG_LEVEL = getenv("LOG_LEVEL", "DEBUG")
logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "standard": {
                "format": "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "did_indy": {
                "handlers": ["default"],
                "level": LOG_LEVEL,
                "propagate": True,
            },
            "indy_vdr": {
                "handlers": ["default"],
                "level": LOG_LEVEL,
                "propagate": True,
            },
            "uvicorn": {
                "handlers": ["default"],
                "level": LOG_LEVEL,
                "propagate": True,
            },
            "*": {
                "handlers": ["default"],
                "level": LOG_LEVEL,
                "propagate": True,
            },
        },
    }
)

app = FastAPI(
    title="did:indy",
    summary="did:indy driver",
    openapi_tags=[
        {
            "name": "Registrar",
            "description": "DID Registration interface",
            "externalDocs": {
                "description": "Specification",
                "url": "https://identity.foundation/did-registration",
            },
        },
        {
            "name": "Clients",
            "description": "Client registration and management",
        },
        {
            "name": "Config",
            "description": "Driver configuration",
        },
        {
            "name": "TAA",
            "description": "Transaction author agreement",
        },
        {
            "name": "Nym",
            "description": "Nym creation and updates",
        },
        {
            "name": "Transaction",
            "description": "Transaction creation and submission (for lite clients)",
        },
        {
            "name": "Endorse",
            "description": "Transaction endorsement (for full clients)",
        },
    ],
    webhooks=webhooks,
    lifespan=lifespan,
)

config = Config()  # type: ignore
if config.auth == "client-tokens":
    app.include_router(clients.router)

app.include_router(namespaces.router)
app.include_router(txns.router)
app.include_router(resolver.router)
