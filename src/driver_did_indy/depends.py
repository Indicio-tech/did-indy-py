"""Application dependencies."""

from contextlib import asynccontextmanager
from pathlib import Path
from base64 import urlsafe_b64decode
from typing import Annotated, cast

from aries_askar import Key, KeyAlg, Store
from base58 import b58encode
from fastapi import Depends, FastAPI
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from driver_did_indy.cache import BasicCache, Cache
from driver_did_indy.config import (
    Config,
    LedgersConfig,
    LocalLedgerGenesis,
    RemoteLedgerGenesis,
)
from driver_did_indy.ledgers import (
    Ledger,
    LedgerPool,
    Ledgers,
    get_genesis_transactions,
)


config: Config | None = None
cache: Cache | None = None
store: Store | None = None
ledgers: Ledgers | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Setup dependencies"""
    global config, cache, store, ledgers

    # For pretty printing
    console = Console(width=90)

    # Loads configuration from environment
    config = Config()  # type: ignore
    ledgers_config = LedgersConfig.from_config_file(config.ledger_config)

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

    async with Ledger(pool, store) as ledger:
        info = await ledger.get_txn_author_agreement()
        if info.taa and info.required:
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
            await ledger.accept_txn_author_agreement(info.taa, "wallet_agreement")

    return pool


def get_ledgers() -> Ledgers:
    """Retrieve ledgers registry."""
    global ledgers
    if ledgers is None:
        raise RuntimeError("Ledgers is not set; did startup fail?")

    return ledgers


LedgersDep = Annotated[Ledgers, Depends(get_ledgers)]


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

    async with store.session() as session:
        entry = await session.fetch_key(name=namespace, for_update=True)
        if not entry:
            await session.insert_key(
                name=namespace,
                key=key,
                tags={"nym": nym},
            )
            await session.insert(
                category="nym",
                name=namespace,
                value=nym,
                tags={"verkey": verkey},
            )
        else:
            prior = cast(Key, entry.key)
            if prior.get_public_bytes() != pub_bytes:
                await session.remove_key(namespace)
                await session.insert_key(
                    name=namespace,
                    key=key,
                    tags={"nym": nym},
                )
                await session.replace(
                    category="nym",
                    name=namespace,
                    value=nym,
                    tags={"verkey": verkey},
                )

    return nym, verkey
