import logging.config
from os import getenv
from fastapi import FastAPI

from driver_did_indy.config import Config
from driver_did_indy.depends import lifespan

from .webhooks import webhooks
from .api import txns, namespaces, clients

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
            "driver_did_indy": {
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
        }
    ],
    webhooks=webhooks,
    lifespan=lifespan,
)

app.include_router(txns.router)
app.include_router(namespaces.router)

config = Config()  # type: ignore
if config.auth == "client-tokens":
    app.include_router(clients.router)
