"""Application dependencies."""

from base64 import urlsafe_b64decode
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from aries_askar import Key, KeyAlg, Store
from base58 import b58encode
from fastapi import Depends, FastAPI, HTTPException
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from did_indy.cache import BasicCache, Cache
from did_indy.config import LedgerConfig, LocalLedgerGenesis, RemoteLedgerGenesis
from did_indy.driver.config import Config
from did_indy.driver.ledgers import Ledgers, UnknownNamespaceError, store_nym_and_key
from did_indy.driver.taa import accept_txn_author_agreement
from did_indy.ledger import LedgerPool, ReadOnlyLedger, get_genesis_transactions
from did_indy.resolver import Resolver

config: Config | None = None
cache: Cache | None = None
store: Store | None = None
ledgers: Ledgers | None = None
resolver: Resolver | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Setup dependencies"""
    global config, cache, store, ledgers, resolver

    # For pretty printing
    console = Console(width=90)

    # Loads configuration from environment
    config = Config()  # type: ignore
    ledgers_config = LedgerConfig.from_config_file(config.ledger_config)

    cache = BasicCache()

    # TODO Most of this store setup needs to be done in a more resilient way
    store_path = Path("./temp.db")
    store_path.parent.mkdir(parents=True, exist_ok=True)
    if store_path.exists():
        store = await Store.open(
            f"sqlite://{store_path}", "kdf:argon2i", config.passphrase
        )
    else:
        store = await Store.provision(
            f"sqlite://{store_path}", "kdf:argon2i", config.passphrase
        )

    ledgers = Ledgers()
    resolver = Resolver(ledgers)
    nyms = []
    for ledger in ledgers_config.ledgers:
        nym, verkey = await derive_nym_from_seed(store, ledger.seed, ledger.namespace)
        pool = await init_ledger_pool(console, cache, store, ledger)
        ledgers.add(ledger.namespace, pool)
        nyms.append((ledger.namespace, nym, verkey))

    console = Console(width=120)
    table = Table(title="Generated Nyms", show_header=True, header_style="bold")
    table.add_column("Ledger")
    table.add_column("Nym")
    table.add_column("Verkey")
    for nym in nyms:
        table.add_row(*nym)
    console.print("\n\n")
    console.print(table)
    yield
    await store.close()


def get_store() -> Store:
    """Retrieve store.

    This is intended to be called by FastAPI.Depends.
    """
    global store

    if store is None:
        raise RuntimeError("Store is not set; did startup fail?")

    return store


StoreDep = Annotated[Store, Depends(get_store)]


async def init_ledger_pool(
    console: Console,
    cache: Cache,
    store: Store,
    config: RemoteLedgerGenesis | LocalLedgerGenesis,
):
    """Initialize the pool and prepare for writes."""
    pool = LedgerPool(
        config.namespace,
        cache=cache,
        genesis_transactions=await get_genesis_transactions(config),
    )

    async with ReadOnlyLedger(pool) as ledger:
        info = await ledger.get_txn_author_agreement()

    if not info.taa or not info.required:
        return pool

    markdown = Markdown(info.taa.text)
    console.print(
        f"By continuing to use this software, you agree to the Transaction Author "
        f"Agreement Version {info.taa.version} for {config.namespace} presented "
        "below:\n\n",
        style="bold red",
    )
    console.print(markdown)
    console.print(
        f"\n\nBy continuing to use this software, you agree to the Transaction Author "
        f"Agreement Version {info.taa.version} for {config.namespace} presented "
        "above.",
        style="bold red",
    )
    await accept_txn_author_agreement(pool, store, info.taa, "wallet_agreement")

    return pool


def get_ledgers():
    """Retrieve ledgers registry."""
    global ledgers
    if ledgers is None:
        raise RuntimeError("Ledgers is not set; did startup fail?")

    try:
        yield ledgers
    except UnknownNamespaceError as err:
        raise HTTPException(404, detail=f"Namespace {err.namespace} is unknown")


LedgersDep = Annotated[Ledgers, Depends(get_ledgers)]


def get_resolver():
    """Get resolver provider."""
    global resolver
    if resolver is None:
        raise RuntimeError("Resolver is not set; did startup fail?")

    try:
        yield resolver
    except UnknownNamespaceError as err:
        raise HTTPException(404, detail=f"Namespace {err.namespace} is unknown")


ResolverDep = Annotated[Resolver, Depends(get_resolver)]


async def derive_nym_from_seed(store: Store, seed: str, namespace: str):
    if "=" in seed:
        seed_b = urlsafe_b64decode(seed)
    else:
        seed_b = seed.encode("ascii")

    key = Key.from_secret_bytes(KeyAlg.ED25519, seed_b)
    pub_bytes = key.get_public_bytes()
    # TODO selfserve doesn't support v2 validation...
    # nym = b58encode(sha256(pub_bytes).digest()[:16]).decode()
    # So we resort to v1 validation
    nym = b58encode(pub_bytes[:16]).decode()
    verkey = b58encode(pub_bytes).decode()

    await store_nym_and_key(store, namespace, nym, key)

    return nym, verkey


def get_config() -> Config:
    """Retrieve config."""
    global config
    if config is None:
        raise RuntimeError("config is not set; did startup fail?")

    return config


ConfigDep = Annotated[Config, Depends(get_config)]


def get_cache() -> Cache:
    """Retrieve cache."""
    global cache
    if cache is None:
        raise RuntimeError("config is not set; did startup fail?")

    return cache


CacheDep = Annotated[Cache, Depends(get_cache)]
