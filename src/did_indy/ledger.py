"""Ledger loading and management."""

import asyncio
import base64
import hashlib
import json
import logging
import os
import tempfile
from io import StringIO
from pathlib import Path
from time import time
from typing import Optional, TypeVar, cast

from indy_vdr import LedgerType, Pool, Request, VdrError, ledger, open_pool
from indy_vdr.bindings import dereference

from did_indy.cache import Cache
from did_indy.config import LocalLedgerGenesis, RemoteLedgerGenesis
from did_indy.models.endorsement import Endorsement
from did_indy.models.taa import TaaAcceptance, TAAInfo, TAARecord
from did_indy.models.txn.data import SchemaTxnData
from did_indy.models.txn.deref import (
    CredDefDeref,
    GetRevRegDefReply,
    GetTxnReply,
    RevRegDefDeref,
    SchemaDeref,
)
from did_indy.signer import Signer, sign_message
from did_indy.utils import FetchError, fetch

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


class LedgerPool:
    """Indy-VDR ledger pool manager.

    The LedgerPool will create files on the local filesystem to cache retrieved
    genesis and pool transactions. The following paths are created:

        - Config root at either `$XDG_DATA_HOME/vdr` or `$HOME/.local/share/vdr`
        - {root}/{ledger name}/genesis to store the original genesis txns
        - {root}/{ledger name}/cache-{pool txn hash} to cache the current state
          of the pool ledger (this speeds up txn time if genesis txns contain
          defunct nodes)
    """

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
            genesis_transactions: The ledger genesis transaction as a string. If
                omitted, attempt to load from cache on filesystem.
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

        cfg_pool = self.cfg_path.joinpath(self.name)
        cfg_pool.mkdir(exist_ok=True)

        cache_path = cfg_pool.joinpath(f"cache-{self.genesis_hash}")
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


T = TypeVar("T", bound="BaseLedger")


class BaseLedger:
    """Read Only Ledger interface."""

    def __init__(
        self,
        pool: LedgerPool,
    ):
        """Initialize an IndyVdrLedger instance.

        Args:
            pool: The pool instance handling the raw ledger connection
        """
        self.pool = pool

    async def __aenter__(self: T) -> T:
        """Context manager entry.

        Returns:
            The current instance

        """
        await self.pool.context_open()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit."""
        await self.pool.context_close()

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
            taa_record = TAARecord(
                text=taa_found["text"], version=taa_found["version"], digest=digest
            )

        return TAAInfo(aml=aml_found, taa=taa_record, required=taa_required)

    async def dereference(self, did_url: str) -> dict:
        """Dereference a DID URL to an object."""
        if not self.pool.handle or not self.pool.handle.handle:
            raise ClosedPoolError(
                f"Cannot dereference using a closed pool '{self.pool.name}'"
            )

        try:
            result = json.loads(await dereference(self.pool.handle.handle, did_url))
        except VdrError as err:
            raise LedgerError("Ledger request error") from err
        return result

    async def deref_schema(self, schema_id: str) -> SchemaDeref:
        """Retrieve schema by ID (DID URL)."""
        result = await self.dereference(schema_id)
        schema_result = SchemaDeref.model_validate(result)
        return schema_result

    async def get_schema_by_seq_no(self, seq_no: int) -> GetTxnReply[SchemaTxnData]:
        request = ledger.build_get_txn_request(
            submitter_did=None,
            ledger_type=LedgerType.DOMAIN,
            seq_no=seq_no,
        )
        result = await self.get(request)
        response = GetTxnReply[SchemaTxnData].model_validate(result)
        return response

    async def deref_cred_def(self, cred_def_id: str) -> CredDefDeref:
        """Retrieve cred def by ID (DID URL)."""
        result = await self.dereference(cred_def_id)
        cred_def_result = CredDefDeref.model_validate(result)
        return cred_def_result

    async def deref_rev_reg_def(self, rev_reg_def_id: str) -> RevRegDefDeref:
        """Retrieve a rev reg def by ID (DID URL)."""
        result = await self.dereference(rev_reg_def_id)
        rev_reg_def_result = RevRegDefDeref.model_validate(result)
        return rev_reg_def_result

    # --- Get Revocation Status List Helpers
    # These are all necessary since we don't have a convenient helper like dereference
    # for status lists since they're identified by rev_reg_def_id and time range.

    async def deref_revoc_reg_entry(
        self, indy_rev_reg_def_id: str, timestamp: int
    ) -> tuple[dict, int]:
        """Get revocation registry entry by rev reg def id and timestamp."""
        if not self.pool.handle or not self.pool.handle.handle:
            raise ClosedPoolError(
                f"Cannot submit get request to closed pool '{self.pool.name}'"
            )

        request = ledger.build_get_revoc_reg_request(
            submitter_did=None,
            revoc_reg_id=indy_rev_reg_def_id,
            timestamp=timestamp,
        )
        try:
            response = await self.pool.handle.submit_request(request)
        except VdrError as err:
            raise LedgerError(
                f"Failed to retrieve rev entry for {indy_rev_reg_def_id}"
            ) from err

        ledger_timestamp = response["data"]["txnTime"]
        reg_entry = {
            "ver": "1.0",
            "value": response["data"]["value"],
        }
        if response["data"]["revocRegDefId"] != indy_rev_reg_def_id:
            raise LedgerError(
                "ID of revocation registry response does not match requested ID"
            )
        return reg_entry, ledger_timestamp

    async def fetch_revoc_reg_delta(
        self,
        indy_rev_reg_def_id: str,
        timestamp_from: int | None,
        timestamp_to: int | None,
    ) -> dict:
        """Get revocation registry definition from ledger."""
        if not self.pool.handle or not self.pool.handle.handle:
            raise ClosedPoolError(
                f"Cannot submit get request to closed pool '{self.pool.name}'"
            )

        if timestamp_to is None:
            timestamp_to = int(time())

        request = ledger.build_get_revoc_reg_delta_request(
            submitter_did=None,
            revoc_reg_id=indy_rev_reg_def_id,
            from_ts=timestamp_from,
            to_ts=timestamp_to,
        )
        try:
            response = await self.pool.handle.submit_request(request)
        except VdrError as err:
            raise LedgerError(
                f"Failed to retrieve rev_status_list for {indy_rev_reg_def_id}"
            ) from err
        LOGGER.debug("revoc_reg_delta response: %s", response)

        if response["data"]["revocRegDefId"] != indy_rev_reg_def_id:
            raise LedgerError(
                "ID of revocation registry response does not match requested ID"
            )
        response_value = response["data"]["value"]
        return response_value

    async def get_revoc_reg_delta(
        self,
        indy_rev_reg_def_id: str,
        timestamp_from: int | None,
        timestamp_to: int | None,
    ) -> tuple[dict, int]:
        """Get revocation registry delta, with checks to correct time to reg creation."""
        response = await self.fetch_revoc_reg_delta(
            indy_rev_reg_def_id,
            timestamp_from,
            timestamp_to,
        )

        # If accum_to is not present, then the timestamp_to was before the registry
        # was created. In this case, we need to fetch the registry creation timestamp and
        # re-calculate the delta.
        if not response.get("accum_to"):
            _, timestamp_to = await self.deref_revoc_reg_entry(
                indy_rev_reg_def_id, int(time())
            )
            response = await self.fetch_revoc_reg_delta(
                indy_rev_reg_def_id, timestamp_from, timestamp_to
            )

        delta = {
            "accum": response["accum_to"]["value"]["accum"],
            "issued": response.get("issued", []),
            "revoked": response.get("revoked", []),
        }
        accum_from = response.get("accum_from")
        if accum_from:
            delta["prev_accum"] = accum_from["value"]["accum"]
        reg_delta = {"ver": "1.0", "value": delta}
        # question - why not response["to"] ?
        delta_timestamp = response["accum_to"]["txnTime"]
        return reg_delta, delta_timestamp

    async def get_or_fetch_rev_reg_def_max_cred_num(
        self, indy_rev_reg_def_id: str
    ) -> int:
        """Retrieve max cred num for a rev reg def.

        The value is retrieved from cache or from the ledger if necessary.
        The issuer could retrieve this value from the wallet but this info
        must also be known to the holder.
        """
        cache = self.pool.cache
        cache_key = f"rev_reg_max_cred_num::{indy_rev_reg_def_id}"

        max_cred_num = await cache.get(cache_key)
        if max_cred_num:
            return max_cred_num

        request = ledger.build_get_revoc_reg_def_request(
            submitter_did=None,
            revoc_reg_id=indy_rev_reg_def_id,
        )
        result = await self.get(request)
        response = GetRevRegDefReply.model_validate(result)
        max_cred_num = response.data.value.max_cred_num

        await cache.set(cache_key, max_cred_num)

        return max_cred_num

    # --- END Get Revocation Status List Helpers


class ReadOnlyLedger(BaseLedger):
    """Read Only Ledger interface."""


class Ledger(BaseLedger):
    """Ledger interface."""

    def __init__(
        self,
        pool: LedgerPool,
    ):
        """Initialize an IndyVdrLedger instance.

        Args:
            pool: The pool instance handling the raw ledger connection
            store: The askar store
        """
        super().__init__(pool)

    async def validate_taa_acceptance(self, acceptance: TaaAcceptance | None):
        """Validate a taa acceptance digest."""
        info = await self.get_txn_author_agreement()
        if not info.required or not info.taa:
            return

        if acceptance is None:
            raise LedgerTransactionError("TAA is required for this namespace")

        expected = self.taa_digest(info.taa.version, info.taa.text)
        if acceptance.taaDigest != expected:
            raise LedgerTransactionError("Invalid TAA digest")

        assert "aml" in info.aml
        valid_mechanisms = list(info.aml["aml"].keys())
        if acceptance.mechanism not in valid_mechanisms:
            raise LedgerTransactionError("Invalid TAA mechanism")

        # TODO validate time
        if acceptance.time < 0:
            raise LedgerTransactionError("Invalid TAA time")

    async def submit(
        self,
        request: str | Request,
        signer: Signer,
        taa: TaaAcceptance | None = None,
        *,
        endorsement: Endorsement | None = None,
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

        if taa:
            request.set_txn_author_agreement_acceptance(taa.for_request())

        if endorsement:
            request.set_endorser(endorsement.nym)

        request.set_signature(await sign_message(signer, request.signature_input))

        if endorsement:
            request.set_multi_signature(endorsement.nym, endorsement.signature)

        LOGGER.debug(request.body)

        request_result = await self.pool.handle.submit_request(request)

        return request_result

    async def endorse(
        self,
        request: str | Request,
        nym: str,
        signer: Signer,
    ) -> Endorsement:
        """Endorse and return a request."""
        if isinstance(request, str):
            request = ledger.build_custom_request(request)
        elif not isinstance(request, Request):
            raise BadLedgerRequestError("Expected str or Request")

        request.set_endorser(nym)
        return Endorsement(nym, await sign_message(signer, request.signature_input))

    async def endorse_and_submit(
        self,
        request: str | Request,
        submitter: str | None,
        submitter_signature: str | bytes | None,
        nym: str,
        signer: Signer,
    ) -> dict:
        """Endorse and submit a request."""
        if isinstance(request, str):
            request = ledger.build_custom_request(request)
        elif not isinstance(request, Request):
            raise BadLedgerRequestError("Expected str or Request")

        if not self.pool.handle:
            raise ClosedPoolError(
                f"Cannot sign and submit request to closed pool '{self.pool.name}'"
            )

        endorsement = await self.endorse(request, nym, signer)
        request.set_endorser(endorsement.nym)
        request.set_multi_signature(endorsement.nym, endorsement.signature)

        if submitter:
            if isinstance(submitter_signature, str):
                submitter_signature = base64.urlsafe_b64decode(submitter_signature)
            elif submitter_signature is None:
                raise BadLedgerRequestError("Submitter signature required")

            request.set_multi_signature(submitter, submitter_signature)

        try:
            request_result = await self.pool.handle.submit_request(request)
        except VdrError as err:
            raise LedgerTransactionError("Ledger request error") from err

        return request_result
