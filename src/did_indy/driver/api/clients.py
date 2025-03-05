"""Manage clients."""

from datetime import timedelta
from time import time
from typing import Literal
from uuid import uuid4
from secrets import token_urlsafe

from aries_askar import Store
from fastapi import APIRouter, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from pydantic import BaseModel, ConfigDict

from did_indy.driver.config import Config
from did_indy.driver.depends import ConfigDep, StoreDep
from did_indy.driver.security import admin
from did_indy.driver.auto_endorse import ClientAutoEndorseRules

router = APIRouter(prefix="/clients", tags=["Clients"])


class ClientCreateRequest(BaseModel):
    """Client Create Request."""

    name: str
    auto_endorse: ClientAutoEndorseRules | None = None


class ClientCreateResponse(BaseModel):
    """Client create response."""

    client_id: str
    name: str
    token: str


async def create_client(
    store: Store, config: Config, name: str, rules: ClientAutoEndorseRules | None = None
) -> ClientCreateResponse:
    """Create a client."""
    assert config.client_token_secret, "Clients endpoint hit but invalid config"
    jti = str(uuid4())
    client_id = str(uuid4())
    token = jwt.encode(
        payload={"jti": jti, "client_id": client_id, "nonce": token_urlsafe()},
        key=config.client_token_secret,
        algorithm="HS256",
    )
    rules = rules or ClientAutoEndorseRules()
    async with store.session() as session:
        await session.insert(
            category="clients",
            name=client_id,
            value_json={
                "name": name,
                "jti": jti,
                "rules": rules.model_dump(),
            },
        )
    return ClientCreateResponse(client_id=client_id, name=name, token=token)


@router.post("", summary="Register a new client")
async def post_clients(
    req: ClientCreateRequest,
    store: StoreDep,
    config: ConfigDep,
    _=Security(admin),
) -> ClientCreateResponse:
    """Create a client."""
    return await create_client(store, config, req.name, req.auto_endorse)


@router.get("/token/{client_id}", summary="Generate a new client token")
async def get_client_token(
    client_id: str,
    store: StoreDep,
    config: ConfigDep,
    _=Security(admin),  # TODO permit client to regen?
) -> ClientCreateResponse:
    """Generate a new token, revoking the previous token."""
    assert config.client_token_secret, "Clients endpoint hit but invalid config"
    async with store.transaction() as session:
        entry = await session.fetch(category="clients", name=client_id, for_update=True)
        if not entry:
            raise HTTPException(404, f"No client with id {client_id}")

        name = entry.value_json["name"]
        jti = str(uuid4())
        await session.replace(
            category="clients",
            name=client_id,
            value_json={
                "name": name,
                "jti": jti,
                "rules": entry.value_json["rules"],
            },
        )
        await session.commit()

    token = jwt.encode(
        payload={"jti": jti, "client_id": client_id, "nonce": token_urlsafe()},
        key=config.client_token_secret,
        algorithm="HS256",
    )
    return ClientCreateResponse(client_id=client_id, name=name, token=token)


class ClientRegisterTokenResponse(BaseModel):
    """Response to register token."""

    token: str


@router.post("/register/token", summary="Generate a new client registration token")
async def post_register_token(
    req: ClientCreateRequest,
    store: StoreDep,
    config: ConfigDep,
    _=Security(admin),
) -> ClientRegisterTokenResponse:
    """Generate a client registration token."""
    assert config.client_token_secret, "Clients endpoint hit but invalid config"
    iat = int(time())
    # TODO determine appropriate exp
    exp = iat + int(timedelta(days=1).total_seconds())
    rules = req.auto_endorse or ClientAutoEndorseRules()
    jti = str(uuid4())
    token = jwt.encode(
        payload={
            "jti": jti,
            "iss": config.issuer,
            "aud": config.issuer,
            "iat": iat,
            "exp": exp,
            "ver": 1,
            "nonce": token_urlsafe(),
            "name": req.name,
            "auto_endorse": rules.model_dump(),
        },
        key=config.client_token_secret,
        algorithm="HS256",
    )

    async with store.session() as session:
        await session.insert(
            category="registration-tokens",
            name=jti,
            value_json={
                "jti": jti,
                "name": req.name,
                "rules": rules.model_dump(),
                "iat": iat,
                "exp": exp,
            },
        )

    return ClientRegisterTokenResponse(token=token)


class RegistrationTokenPayload(BaseModel):
    """Expected payload of a registration token."""

    model_config = ConfigDict(extra="ignore")

    jti: str
    iss: str
    aud: str
    iat: int
    exp: int
    ver: Literal[1]
    nonce: str
    name: str
    auto_endorse: ClientAutoEndorseRules


@router.post("/register", summary="Register using a registration token")
async def post_register(
    store: StoreDep,
    config: ConfigDep,
    token: HTTPAuthorizationCredentials = Security(HTTPBearer()),
) -> ClientCreateResponse:
    assert config.client_token_secret, "Clients endpoint hit but invalid config"
    try:
        payload = jwt.decode(
            token.credentials,
            config.client_token_secret,
            algorithms=["HS256"],  # TODO asymmetric?
            audience=config.issuer,
            issuer=config.issuer,  # TODO permit others?
        )
    except Exception as error:
        raise HTTPException(401) from error

    payload = RegistrationTokenPayload.model_validate(payload)

    async with store.session() as session:
        entry = await session.fetch(
            category="registration-tokens",
            name=payload.jti,
            for_update=True,
        )
        if not entry:
            raise HTTPException(401)

        await session.remove(category="registration-tokens", name=payload.jti)

    return await create_client(store, config, payload.name, payload.auto_endorse)


@router.delete("/register/{jti}", summary="Revoke a registration token")
async def delete_register_token(
    jti: str,
    store: StoreDep,
    _=Security(admin),
) -> str:
    """Delete/revoke a registration token."""
    async with store.session() as session:
        entry = await session.fetch(
            category="registration-tokens",
            name=jti,
            for_update=True,
        )
        if not entry:
            raise HTTPException(
                404, detail=f"No registration token found with jti {jti}"
            )

        await session.remove(category="registration-tokens", name=jti)

    return jti


class RegistrationToken(BaseModel):
    """Registration token."""

    jti: str
    name: str
    rules: ClientAutoEndorseRules
    iat: int
    exp: int


class RegistrationTokenList(BaseModel):
    """Registration token list."""

    tokens: list[RegistrationToken]


@router.get("/register/token", summary="List registration token records")
async def get_register_token(
    store: StoreDep,
    _=Security(admin),
) -> RegistrationTokenList:
    """List registration tokens."""
    async with store.session() as session:
        # TODO Pagination
        entries = await session.fetch_all(category="registration-tokens")

    return RegistrationTokenList(
        tokens=[RegistrationToken.model_validate(entry.value_json) for entry in entries]
    )
