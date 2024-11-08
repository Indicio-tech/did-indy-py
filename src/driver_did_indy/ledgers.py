"""Ledger loading and management."""

import asyncio
from dataclasses import dataclass
from datetime import date, datetime, timezone
from io import StringIO
import logging
from pathlib import Path
from typing import Mapping, Optional, Tuple, cast
import tempfile
import hashlib
import os

from aries_askar import Key, Store
from indy_vdr import Pool, VdrError, ledger, open_pool, Request

from driver_did_indy.cache import Cache
from driver_did_indy.config import LocalLedgerGenesis, RemoteLedgerGenesis
from driver_did_indy.utils import FetchError, fetch


LOGGER = logging.getLogger(__name__)


def _normalize_txns(txns: str) -> str:
    """Normalize a set of genesis transactions."""
    lines = StringIO()
    for line in txns.splitlines():
        line = line.strip()
        if line:
            lines.write(line)
            lines.write("\n")
    return lines.getvalue()


def _write_safe(path: Path, content: str):
    """Atomically write to a file path."""
    dir_path = path.parent
    with tempfile.NamedTemporaryFile(dir=dir_path, delete=False) as tmp:
        tmp.write(content.encode("utf-8"))
        tmp_name = tmp.name
    os.rename(tmp_name, path)


def _hash_txns(txns: str) -> str:
    """Obtain a hash of a set of genesis transactions."""
    return hashlib.sha256(txns.encode("utf-8")).hexdigest()[-16:]


def _path_from_env(var: str, default: Path) -> Path:
    """Return a path from an environment variable"""
    if (value := os.getenv(var)) and (path := Path(value)).is_absolute():
        return path
    return default


def _storage_path(name: str) -> Path:
    """Return a path for storage."""
    data_dir = _path_from_env("XDG_DATA_HOME", Path.home() / ".local" / "share")
    path = data_dir / name
    path.mkdir(parents=True, exist_ok=True)
    return path


async def fetch_genesis_transactions(genesis_url: str) -> str:
    """Get genesis transactions."""
    headers = {}
    headers["Content-Type"] = "application/json"
    LOGGER.info("Fetching genesis transactions from: %s", genesis_url)
    try:
        # Fetch from --genesis-url likely to fail in composed container setup
        # https://github.com/openwallet-foundation/acapy/issues/1745
        result = await fetch(genesis_url, headers=headers, max_attempts=20)
        return cast(str, result)
    except FetchError as e:
        raise LedgerConfigError("Error retrieving ledger genesis transactions") from e


async def get_genesis_transactions(
    config: RemoteLedgerGenesis | LocalLedgerGenesis,
) -> str:
    """Fetch genesis transactions if necessary."""

    if isinstance(config, RemoteLedgerGenesis):
        txns = await fetch_genesis_transactions(config.url)
    else:
        try:
            LOGGER.info("Reading ledger genesis transactions from: %s", config.path)
            with open(config.path, "r") as genesis_file:
                txns = genesis_file.read()
        except IOError as e:
            raise LedgerConfigError("Error reading ledger genesis transactions") from e
    return txns


class LedgerError(Exception):
    """Raised on general ledger errors."""


class LedgerConfigError(LedgerError):
    """Raised on error opening configuring ledger."""


class ClosedPoolError(LedgerError):
    """Raised on pool closed."""


class BadLedgerRequestError(LedgerError):
    """Raised on bad ledger request."""


class LedgerTransactionError(LedgerError):
    """Raised on error with a txn."""


class NymNotFoundError(LedgerError):
    """Raised when no nym is found for ledger."""


class LedgerPool:
    """Indy-VDR ledger pool manager."""

    def __init__(
        self,
        name: str,
        *,
        keepalive: int = 0,
        cache: Cache,
        cache_duration: int = 600,
        genesis_transactions: Optional[str] = None,
    ):
        """Initialize an IndyLedger instance.

        Args:
            name: The pool ledger configuration name
            keepalive: How many seconds to keep the ledger open
            cache: The cache instance to use
            cache_duration: The TTL for ledger cache entries
            genesis_transactions: The ledger genesis transaction as a string
        """
        self.ref_count = 0
        self.ref_lock = asyncio.Lock()
        self.keepalive = keepalive
        self.close_task: asyncio.Future | None = None
        self.cache = cache
        self.cache_duration: int = cache_duration
        self.handle: Optional[Pool] = None
        self.name = name
        self.cfg_path_cache: Optional[Path] = None
        self.genesis_hash_cache: Optional[str] = None
        self.genesis_txns_cache = genesis_transactions
        self.init_config = bool(genesis_transactions)
        self.taa_cache: TAAInfo | None = None

    @property
    def cfg_path(self) -> Path:
        """Get the path to the configuration file, ensuring it's created."""
        if not self.cfg_path_cache:
            self.cfg_path_cache = _storage_path("vdr")
        return self.cfg_path_cache

    @property
    def genesis_hash(self) -> str:
        """Get the hash of the configured genesis transactions."""
        if not self.genesis_hash_cache:
            self.genesis_hash_cache = _hash_txns(self.genesis_txns)
        return self.genesis_hash_cache

    @property
    def genesis_txns(self) -> str:
        """Get the configured genesis transactions."""
        if not self.genesis_txns_cache:
            try:
                path = self.cfg_path.joinpath(self.name, "genesis")
                self.genesis_txns_cache = _normalize_txns(open(path).read())
            except FileNotFoundError:
                raise LedgerConfigError(
                    "Pool config '%s' not found", self.name
                ) from None
        return self.genesis_txns_cache

    async def create_pool_config(
        self, genesis_transactions: str, recreate: bool = False
    ):
        """Create the pool ledger configuration."""

        cfg_pool = self.cfg_path.joinpath(self.name)
        cfg_pool.mkdir(exist_ok=True)
        genesis = _normalize_txns(genesis_transactions)
        if not genesis:
            raise LedgerConfigError("Empty genesis transactions")

        genesis_path = cfg_pool.joinpath("genesis")
        try:
            cmp_genesis = open(genesis_path).read()
            if _normalize_txns(cmp_genesis) == genesis:
                LOGGER.debug(
                    "Pool ledger config '%s' is consistent, skipping write",
                    self.name,
                )
                return
            elif not recreate:
                raise LedgerConfigError(
                    f"Pool ledger '{self.name}' exists with "
                    "different genesis transactions"
                )
        except FileNotFoundError:
            pass

        try:
            _write_safe(genesis_path, genesis)
        except OSError as err:
            raise LedgerConfigError("Error writing genesis transactions") from err
        LOGGER.debug("Wrote pool ledger config '%s'", self.name)

        self.genesis_txns_cache = genesis

    async def open(self):
        """Open the pool ledger, creating it if necessary."""

        if self.init_config:
            await self.create_pool_config(self.genesis_txns, recreate=True)
            self.init_config = False

        genesis_hash = self.genesis_hash
        cfg_pool = self.cfg_path.joinpath(self.name)
        cfg_pool.mkdir(exist_ok=True)

        cache_path = cfg_pool.joinpath(f"cache-{genesis_hash}")
        try:
            txns = open(cache_path).read()
            cached = True
        except FileNotFoundError:
            txns = self.genesis_txns
            cached = False

        self.handle = await open_pool(transactions=txns)
        upd_txns = _normalize_txns(await self.handle.get_transactions())
        if not cached or upd_txns != txns:
            try:
                _write_safe(cache_path, upd_txns)
            except OSError:
                LOGGER.exception("Error writing cached genesis transactions")

    async def close(self):
        """Close the pool ledger."""
        if self.handle:
            exc = None
            for _ in range(3):
                try:
                    self.handle.close()
                except VdrError as err:
                    await asyncio.sleep(0.01)
                    exc = err
                    continue

                self.handle = None
                exc = None
                break

            if exc:
                LOGGER.exception("Exception when closing pool ledger", exc_info=exc)
                self.ref_count += 1  # if we are here, we should have self.ref_lock
                self.close_task = None
                raise LedgerError("Exception when closing pool ledger") from exc

    async def context_open(self):
        """Open the ledger if necessary and increase the number of active references."""
        async with self.ref_lock:
            if self.close_task:
                self.close_task.cancel()
            if not self.handle:
                LOGGER.debug("Opening the pool ledger")
                await self.open()
            self.ref_count += 1

    async def context_close(self):
        """Release the reference and schedule closing of the pool ledger."""

        async def closer(timeout: int):
            """Close the pool ledger after a timeout."""
            await asyncio.sleep(timeout)
            async with self.ref_lock:
                if not self.ref_count:
                    LOGGER.debug("Closing pool ledger after timeout")
                    await self.close()

        async with self.ref_lock:
            self.ref_count -= 1
            if not self.ref_count:
                if self.keepalive:
                    self.close_task = asyncio.ensure_future(closer(self.keepalive))
                else:
                    await self.close()


sentinel = object()


@dataclass
class TAARecord:
    text: str
    version: str
    digest: str


@dataclass
class TAAInfo:
    aml: dict
    taa: TAARecord | None
    required: bool


class Ledger:
    """Ledger interface."""

    def __init__(
        self,
        pool: LedgerPool,
        store: Store,
    ):
        """Initialize an IndyVdrLedger instance.

        Args:
            pool: The pool instance handling the raw ledger connection
            profile: The active profile instance
        """
        self.pool = pool
        self.store = store

    async def __aenter__(self) -> "Ledger":
        """Context manager entry.

        Returns:
            The current instance

        """
        await self.pool.context_open()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit."""
        await self.pool.context_close()

    async def get_nym_and_key(self) -> Tuple[str, Key]:
        """Retrieve our nym and key for this ledger."""
        async with self.store.session() as session:
            entry = await session.fetch_key(self.pool.name)
        if not entry:
            raise NymNotFoundError(f"No nym found for {self.pool.name}")

        key = cast(Key, entry.key)
        tags = cast(dict, entry.tags)
        nym = tags.get("nym")
        assert nym, "Key was saved without a nym tag"
        return nym, key

    def taa_digest(self, version: str, text: str):
        """Generate the digest of a TAA record."""
        if not version or not text:
            raise ValueError("Bad input for TAA digest")
        taa_plaintext = version + text
        return hashlib.sha256(taa_plaintext.encode("utf-8")).digest().hex()

    async def get_txn_author_agreement(self, reload: bool = False) -> TAAInfo:
        """Get the current transaction author agreement, fetching it if necessary."""
        if not self.pool.taa_cache or reload:
            self.pool.taa_cache = await self.fetch_txn_author_agreement()
        return self.pool.taa_cache

    async def fetch_txn_author_agreement(self) -> TAAInfo:
        """Fetch the current AML and TAA from the ledger."""
        response = await self.get(ledger.build_get_acceptance_mechanisms_request())
        aml_found = response["data"]

        response = await self.get(ledger.build_get_txn_author_agreement_request())
        taa_found = response["data"]
        taa_required = bool(taa_found and taa_found["text"])
        taa_record = None
        if taa_found:
            digest = self.taa_digest(taa_found["version"], taa_found["text"])
            taa_record = TAARecord(taa_found["text"], taa_found["version"], digest)

        return TAAInfo(aml_found, taa_record, taa_required)

    def taa_rough_timestamp(self) -> int:
        """Get a timestamp accurate to the day.

        Anything more accurate is a privacy concern.
        """
        return int(
            datetime.combine(
                date.today(), datetime.min.time(), timezone.utc
            ).timestamp()
        )

    async def accept_txn_author_agreement(
        self, taa_record: TAARecord, mechanism: str, accept_time: Optional[int] = None
    ):
        """Save a new record recording the acceptance of the TAA."""
        if not accept_time:
            accept_time = self.taa_rough_timestamp()

        acceptance = {
            "text": taa_record.text,
            "version": taa_record.version,
            "digest": taa_record.digest,
            "mechanism": mechanism,
            "time": accept_time,
        }
        async with self.store.session() as session:
            prior = await session.fetch("taa_accepted", self.pool.name, for_update=True)
            if prior:
                await session.replace(
                    "taa_accepted", self.pool.name, value_json=acceptance
                )
            else:
                await session.insert(
                    "taa_accepted", self.pool.name, value_json=acceptance
                )

        cache_key = "taa_accepted:" + self.pool.name
        await self.pool.cache.set(cache_key, acceptance, self.pool.cache_duration)

    async def get_latest_txn_author_acceptance(self) -> dict:
        """Look up the latest TAA acceptance."""
        cache_key = "taa_accepted:" + self.pool.name
        acceptance = await self.pool.cache.get(cache_key)
        if not acceptance:
            async with self.store.session() as session:
                entry = await session.fetch("taa_accepted", self.pool.name)
            if entry:
                acceptance = entry.value_json
            else:
                acceptance = {}
            await self.pool.cache.set(cache_key, acceptance, self.pool.cache_duration)
        return acceptance

    async def get(self, request: str | Request):
        """Submit a get request to the ledger."""
        if not self.pool.handle:
            raise ClosedPoolError(
                f"Cannot sign and submit request to closed pool '{self.pool.name}'"
            )

        if isinstance(request, str):
            request = ledger.build_custom_request(request)
        elif not isinstance(request, Request):
            raise BadLedgerRequestError("Expected str or Request")

        try:
            request_result = await self.pool.handle.submit_request(request)
        except VdrError as err:
            raise LedgerTransactionError("Ledger request error") from err

        return request_result

    async def submit(
        self,
        request: str | Request,
        key: Key,
    ) -> dict:
        """Sign and submit request to ledger.

        Args:
            request: The request to submit
            sign: whether or not to sign the request
            sign_did: override the signing DID
            write_ledger: whether to write the request to the ledger

        """

        if not self.pool.handle:
            raise ClosedPoolError(
                f"Cannot sign and submit request to closed pool '{self.pool.name}'"
            )

        if isinstance(request, str):
            request = ledger.build_custom_request(request)
        elif not isinstance(request, Request):
            raise BadLedgerRequestError("Expected str or Request")

        acceptance = await self.get_latest_txn_author_acceptance()
        if acceptance:
            acceptance = {
                "taaDigest": acceptance["digest"],
                "mechanism": acceptance["mechanism"],
                "time": acceptance["time"],
            }
            request.set_txn_author_agreement_acceptance(acceptance)

        request.set_signature(key.sign_message(request.signature_input))
        LOGGER.debug(request.body)

        request_result = await self.pool.handle.submit_request(request)

        return request_result

    async def endorse_and_submit(self, request: str | Request) -> dict:
        """Endorse and submit a request."""

        if not self.pool.handle:
            raise ClosedPoolError(
                f"Cannot sign and submit request to closed pool '{self.pool.name}'"
            )

        if isinstance(request, str):
            request = ledger.build_custom_request(request)
        elif not isinstance(request, Request):
            raise BadLedgerRequestError("Expected str or Request")

        nym, key = await self.get_nym_and_key()

        request.set_endorser(nym)
        request.set_multi_signature(nym, key.sign_message(request.signature_input))

        try:
            request_result = await self.pool.handle.submit_request(request)
        except VdrError as err:
            raise LedgerTransactionError("Ledger request error") from err

        return request_result


class Ledgers:
    """Registry of ledgers, identified by namespace."""

    def __init__(self, ledgers: Mapping[str, LedgerPool] | None = None):
        self.ledgers = dict(ledgers) if ledgers else {}

    def add(self, namespace: str, pool: LedgerPool):
        """Add to the registry."""
        self.ledgers[namespace] = pool

    def get(self, namespace: str) -> LedgerPool | None:
        """Get a ledger by namespace."""
        return self.ledgers.get(namespace)
