"""One-time takeover of `eu_data_act_sampler.py`'s captured data into Carchive's own schema.

The sampler (still running at the repository root, per `eu_data_act_sampler.py`'s own
`[portal]`/`[account:<name>]` config format and its `captures`/`placeholders`/`fetch_runs`
tables) collected independently of the new collector for a transition period. This module
reads its config and its per-account `captures.sqlite3` files read-only, and stores an
equivalent account/vehicle/data-request/delivery/run history in Carchive's database so the
sampler can be retired without losing anything it gathered. Never logs into the portal and
never writes to a sampler database.
"""

from __future__ import annotations

import configparser
import hashlib
import io
import re
import sqlite3
import urllib.parse
import zipfile
import zlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncConnection

from carchive.config import (
    Settings,
    WriteOutcome,
    config_dir,
    default_data_dir,
    load_secrets,
    write_credentials,
)
from carchive.core.redact import VIN_PATTERN, redact, register_secret
from carchive.core.timeutil import parse_timestamp
from carchive.providers.vwgroup.brands import known_brands
from carchive.storage.db import Database
from carchive.storage.records import DeliveryContentRecord
from carchive.storage.repositories import (
    AccountRepository,
    CollectorRunRepository,
    DataRequestRepository,
    DeliveryRepository,
    VehicleRepository,
)

PROVIDER_ID = "vwgroup-euda"

_ACCOUNT_SECTION = re.compile(r"^account:([A-Za-z0-9_-]+)$")
_NAME_TIMESTAMP = re.compile(r"^(\d{14})_")

_MAX_VERIFIED_MEMBER_BYTES = 256 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


def _utcnow() -> datetime:
    return datetime.now(UTC)


def default_sampler_config_path() -> Path:
    """Return the sampler's own default config file location.

    Same directory as Carchive's own config/secrets files (`config.config_dir`, XDG-aware),
    since the sampler already writes its config there too; only the file name differs
    (`config.ini`, an INI file, versus Carchive's own `carchive.toml`).
    """
    return config_dir() / "config.ini"


def resolve_sampler_data_dir(config_path: Path, override: Path | None) -> Path:
    """Resolve the sampler's data directory the same way `eu_data_act_sampler.py` would.

    Args:
        config_path: the sampler's config file; its `[storage] data_dir` is consulted if
            `override` is not given.
        override: an explicit data directory, taking precedence over everything else.

    Returns:
        `override` if given, else the config file's `[storage] data_dir`, else
        `config.default_data_dir()` (XDG-aware, same default Carchive itself uses).
    """
    if override is not None:
        return override
    if config_path.is_file():
        parser = configparser.RawConfigParser()
        try:
            parser.read(config_path)
        except configparser.Error:
            return default_data_dir()
        configured = parser.get("storage", "data_dir", fallback="").strip()
        if configured:
            return Path(configured).expanduser()
    return default_data_dir()


@dataclass(frozen=True, slots=True)
class SamplerAccountConfig:
    """One account read from the sampler's config file.

    Attributes:
        name: the account name (`"default"` for the single `[portal]` section, else the
            `[account:<name>]` section's name).
        brand: the VW-group brand, lower-cased.
        vins: the VINs configured for this account, in config-file order.
        sampler_db_path: path to this account's `captures.sqlite3`.
    """

    name: str
    brand: str
    user: str
    password: str
    vins: tuple[str, ...]
    sampler_db_path: Path


def _add_account(
    accounts: list[SamplerAccountConfig],
    problems: list[str],
    seen_names: set[str],
    name: str,
    section: configparser.SectionProxy,
    vins: tuple[str, ...],
    sampler_db_path: Path,
) -> None:
    """Validate one config section and append it to `accounts`, or record a `problems` entry."""
    if name in seen_names:
        problems.append(f"account '{name}': duplicate section, skipped")
        return
    brand = section.get("brand", "").strip()
    if brand.lower() not in known_brands():
        problems.append(f"account '{name}': unknown brand {brand!r}, skipped")
        return
    user = section.get("user", "").strip()
    password = section.get("password", "")
    if not user or not password:
        problems.append(f"account '{name}': missing user or password, skipped")
        return
    register_secret(password)
    seen_names.add(name)
    accounts.append(
        SamplerAccountConfig(
            name=name,
            brand=brand.lower(),
            user=user,
            password=password,
            vins=vins,
            sampler_db_path=sampler_db_path,
        )
    )


def _read_sampler_config(
    config_path: Path, sampler_data_dir: Path
) -> tuple[list[SamplerAccountConfig], list[str]]:
    """Read every account from the sampler's config file.

    Mirrors `eu_data_act_sampler.load_accounts`'s section layout (`[portal]` for the single
    unnamed account, `[account:<name>]` for the rest), but never aborts on a broken
    section: it is recorded in the returned problems and the rest of the file is still
    read.

    Args:
        config_path: the sampler's `config.ini`.
        sampler_data_dir: the resolved base data directory (see `resolve_sampler_data_dir`).

    Returns:
        The valid accounts found, and a list of human-readable problem descriptions for
        anything skipped.
    """
    problems: list[str] = []
    accounts: list[SamplerAccountConfig] = []
    if not config_path.is_file():
        problems.append(f"sampler config file not found: {config_path}")
        return accounts, problems

    # RawConfigParser: a password containing "%" must not be run through ConfigParser's
    # default interpolation (same reasoning as the sampler's own `load_accounts`).
    parser = configparser.RawConfigParser()
    try:
        parser.read(config_path)
    except configparser.Error as exc:
        problems.append(f"could not parse {config_path}: {exc}")
        return accounts, problems

    seen_names: set[str] = set()

    if parser.has_section("portal"):
        section = parser["portal"]
        vin = section.get("vin", "").strip()
        _add_account(
            accounts,
            problems,
            seen_names,
            "default",
            section,
            (vin,) if vin else (),
            sampler_data_dir / "captures.sqlite3",
        )

    for section_name in parser.sections():
        match = _ACCOUNT_SECTION.match(section_name)
        if not match:
            continue
        name = match.group(1)
        section = parser[section_name]
        vins = tuple(v for v in re.split(r"[\s,]+", section.get("vins", "")) if v)
        _add_account(
            accounts,
            problems,
            seen_names,
            name,
            section,
            vins,
            sampler_data_dir / name / "captures.sqlite3",
        )

    return accounts, problems


def _vin_from_name(name: str) -> str | None:
    """Extract the VIN embedded in a sampler-downloaded file name, if any."""
    match = VIN_PATTERN.search(name)
    return match.group(0) if match else None


def _delivered_at_from_name(name: str) -> datetime | None:
    """Parse the `YYYYmmddHHMMSS_` creation-time prefix the portal gives every file name."""
    match = _NAME_TIMESTAMP.match(name)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _wrap_json_as_zip(raw_json: str) -> bytes:
    """Repack the sampler's bare JSON text as a single-member ZIP, matching a live delivery.

    The sampler kept only the unpacked JSON document; `providers.vwgroup.parser` expects
    the ZIP archive the portal itself delivers, so one is reconstructed here.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("data.json", raw_json)
    return buffer.getvalue()


def _stored_json_sha256(payload: bytes) -> str | None:
    """Hash the JSON document inside a stored delivery ZIP.

    Args:
        payload: the stored delivery bytes.

    Returns:
        The SHA-256 hex digest of the archive's single file member, or `None` if `payload`
        is not a readable ZIP with exactly one file member no larger than the verification
        limit.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if len(members) != 1:
                return None
            digest = hashlib.sha256()
            total = 0
            with archive.open(members[0]) as member:
                while chunk := member.read(_HASH_CHUNK_BYTES):
                    total += len(chunk)
                    if total > _MAX_VERIFIED_MEMBER_BYTES:
                        return None
                    digest.update(chunk)
            return digest.hexdigest()
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error, OSError):
        return None


def _open_sampler_db_readonly(path: Path) -> sqlite3.Connection | None:
    """Open the sampler's database read-only, or return `None` if it does not exist yet."""
    if not path.is_file():
        return None
    uri = f"file:{urllib.parse.quote(str(path))}?mode=ro"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError:
        return None


@dataclass(frozen=True, slots=True)
class AccountStats:
    """Counts of what one sampler account contributed, planned or actually applied."""

    name: str
    account_new: bool
    credential_state: str
    vehicles_new: int
    vehicles_existing: int
    requests_new: int
    deliveries_with_content_new: int
    deliveries_with_content_skipped: int
    deliveries_placeholder_new: int
    deliveries_placeholder_skipped: int
    runs_new: int
    runs_skipped: int


@dataclass(frozen=True, slots=True)
class ImportPlan:
    """A dry-run result of `SamplerImporter.plan`: nothing has been written yet.

    Attributes:
        config_path: the sampler config file this plan was computed from; re-read by
            `SamplerImporter.apply`.
        sampler_data_dir: the resolved sampler data directory this plan was computed
            against; re-read by `SamplerImporter.apply`.
    """

    config_path: Path
    sampler_data_dir: Path
    accounts: tuple[AccountStats, ...]
    problems: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KindVerification:
    """Verification counts for one data request kind of one sampler account.

    Attributes:
        kind: the data request kind (`"all"` or `"partial"`).
        files: files (captures and placeholders) the sampler holds for this kind.
        present: of those, how many Carchive stores under the same identity.
        missing: how many Carchive does not store (this includes files the import would
            skip, e.g. for a VIN that is not configured).
        differing: of the present ones, how many have different or unreadable content.
    """

    kind: str
    files: int
    present: int
    missing: int
    differing: int


@dataclass(frozen=True, slots=True)
class AccountVerification:
    """Verification result for one sampler account.

    Attributes:
        name: the account name.
        account_present: whether Carchive has an account with this label at all.
        kinds: one entry per data request kind the sampler holds files for.
    """

    name: str
    account_present: bool
    kinds: tuple[KindVerification, ...]


@dataclass(frozen=True, slots=True)
class VerifyReport:
    """The outcome of `SamplerImporter.verify`.

    Attributes:
        accounts: one entry per valid sampler account.
        problems: human-readable (redacted) reasons why something could not be verified.
    """

    accounts: tuple[AccountVerification, ...]
    problems: tuple[str, ...]

    @property
    def complete(self) -> bool:
        """Whether an account was checked and nothing is missing, differing or unverified."""
        return (
            bool(self.accounts)
            and not self.problems
            and all(k.missing == 0 and k.differing == 0 for a in self.accounts for k in a.kinds)
        )


@dataclass(frozen=True, slots=True)
class ImportReport:
    """The outcome of `SamplerImporter.apply`: what was actually written."""

    accounts: tuple[AccountStats, ...]
    problems: tuple[str, ...]


class SamplerImporter:
    """Takes over `eu_data_act_sampler.py`'s captured data into Carchive's schema.

    Args:
        db: the database to read and write through.
        settings: used for `secrets_file` and the polling interval assigned to newly
            discovered data requests.
        clock: returns the current UTC time; overridable for tests.
    """

    def __init__(
        self,
        db: Database,
        settings: Settings,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._db = db
        self._settings = settings
        self._clock = clock
        self._accounts = AccountRepository()
        self._vehicles = VehicleRepository()
        self._requests = DataRequestRepository()
        self._deliveries = DeliveryRepository()
        self._runs = CollectorRunRepository()

    async def plan(self, config_path: Path, sampler_data_dir: Path) -> ImportPlan:
        """Compute what an import would do, without writing anything.

        Args:
            config_path: the sampler's `config.ini`.
            sampler_data_dir: the resolved sampler data directory (see
                `resolve_sampler_data_dir`).

        Returns:
            The computed `ImportPlan`.

        Raises:
            InsecureSecretsError: if `settings.secrets_file` exists but is group/world
                accessible.
            ConfigError: if `settings.secrets_file` exists but is malformed.
        """
        stats, problems = await self._run(config_path, sampler_data_dir, write=False)
        return ImportPlan(
            config_path=config_path,
            sampler_data_dir=sampler_data_dir,
            accounts=tuple(stats),
            problems=tuple(problems),
        )

    async def apply(self, plan: ImportPlan) -> ImportReport:
        """Perform the import `plan` described, writing to the database and secrets file.

        Re-reads the sampler's config and database files rather than trusting `plan`'s own
        counts, so it stays correct even if time has passed since `plan` was computed;
        every check it performs is idempotent, so running `apply` twice in a row writes
        nothing the second time.

        Args:
            plan: a plan previously returned by `plan`, naming the sources to import from.

        Returns:
            The computed `ImportReport`.

        Raises:
            InsecureSecretsError: if `settings.secrets_file` exists but is group/world
                accessible.
            ConfigError: if `settings.secrets_file` exists but is malformed.
        """
        stats, problems = await self._run(plan.config_path, plan.sampler_data_dir, write=True)
        return ImportReport(accounts=tuple(stats), problems=tuple(problems))

    async def verify(self, config_path: Path, sampler_data_dir: Path) -> VerifyReport:
        """Check that everything the sampler holds is stored in Carchive, read-only.

        Files are matched the way the import deduplicates them: by the data request of
        (vehicle, kind) and the file name. Content is compared by checksum, but not by the
        checksum the import stores, because the import repacks the sampler's bare JSON
        into a new ZIP whose bytes (and thus checksum) differ from run to run. For
        captures the JSON document inside Carchive's stored ZIP is hashed and compared
        with the hash of the sampler's JSON text; for placeholders the stored checksum is
        compared with the sampler's. Captures that are stored as placeholders (or vice
        versa), or whose stored ZIP is unreadable, count as differing. Only the sampler
        databases and Carchive's database are read; nothing is written or logged beyond
        counts.

        Args:
            config_path: the sampler's `config.ini`.
            sampler_data_dir: the resolved sampler data directory (see
                `resolve_sampler_data_dir`).

        Returns:
            The per-account, per-kind counts and any problems that kept something from
            being verified (skipped config sections, missing or unreadable sampler
            databases, malformed rows).
        """
        account_configs, config_problems = _read_sampler_config(config_path, sampler_data_dir)
        problems = [redact(p) for p in config_problems]
        results: list[AccountVerification] = []
        for cfg in account_configs:
            async with self._db.read() as conn:
                result, account_problems = await self._verify_account(conn, cfg)
            results.append(result)
            problems.extend(redact(p) for p in account_problems)
        return VerifyReport(accounts=tuple(results), problems=tuple(problems))

    async def _verify_account(
        self, conn: AsyncConnection, cfg: SamplerAccountConfig
    ) -> tuple[AccountVerification, list[str]]:
        problems: list[str] = []
        account = await self._accounts.get_by_label(conn, cfg.name)
        request_ids: dict[tuple[str, str], UUID | None] = {}
        vehicle_ids: dict[str, UUID] = {}
        if account is not None:
            for vin in cfg.vins:
                vehicle = await self._vehicles.get_by_vin(conn, account.id, vin)
                if vehicle is not None:
                    vehicle_ids[vin] = vehicle.id

        async def request_id_for(vin: str, kind: str) -> UUID | None:
            key = (vin, kind)
            if key not in request_ids:
                vehicle_id = vehicle_ids.get(vin)
                found: UUID | None = None
                if vehicle_id is not None:
                    for record in await self._requests.list_for_vehicle(conn, vehicle_id):
                        if record.kind == kind:
                            found = record.id
                            break
                request_ids[key] = found
            return request_ids[key]

        counts: dict[str, list[int]] = {}

        def count(kind: str) -> list[int]:
            return counts.setdefault(kind, [0, 0, 0, 0])  # files, present, missing, differing

        sampler_conn = _open_sampler_db_readonly(cfg.sampler_db_path)
        if sampler_conn is None:
            problems.append(f"account '{cfg.name}': sampler database missing or unreadable")
        else:
            try:
                for row in sampler_conn.execute(
                    "SELECT dataset_name, dataset_type, raw_json FROM captures ORDER BY id"
                ):
                    name, kind, raw_json = row
                    if not isinstance(name, str) or not isinstance(kind, str):
                        problems.append(f"account '{cfg.name}': malformed capture row")
                        continue
                    tally = count(kind)
                    tally[0] += 1
                    stored = await self._find_stored(conn, request_id_for, name, kind)
                    if stored is None:
                        tally[2] += 1
                        continue
                    tally[1] += 1
                    expected = (
                        hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
                        if isinstance(raw_json, str)
                        else None
                    )
                    actual = (
                        _stored_json_sha256(stored.raw_payload)
                        if stored.has_content and stored.raw_payload is not None
                        else None
                    )
                    if expected is None or actual != expected:
                        tally[3] += 1

                for row in sampler_conn.execute(
                    "SELECT dataset_name, dataset_type, sha256 FROM placeholders ORDER BY id"
                ):
                    name, kind, sha256 = row
                    if not isinstance(name, str) or not isinstance(kind, str):
                        problems.append(f"account '{cfg.name}': malformed placeholder row")
                        continue
                    tally = count(kind)
                    tally[0] += 1
                    stored = await self._find_stored(conn, request_id_for, name, kind)
                    if stored is None:
                        tally[2] += 1
                        continue
                    tally[1] += 1
                    if stored.has_content or stored.sha256 != sha256:
                        tally[3] += 1
            except sqlite3.Error as exc:
                problems.append(
                    f"account '{cfg.name}': sampler database could not be read"
                    f" ({type(exc).__name__})"
                )
            finally:
                sampler_conn.close()

        kinds = tuple(
            KindVerification(kind=k, files=v[0], present=v[1], missing=v[2], differing=v[3])
            for k, v in sorted(counts.items())
        )
        return AccountVerification(cfg.name, account is not None, kinds), problems

    async def _find_stored(
        self,
        conn: AsyncConnection,
        request_id_for: Callable[[str, str], Awaitable[UUID | None]],
        name: str,
        kind: str,
    ) -> DeliveryContentRecord | None:
        """Look up the Carchive delivery for a sampler file the way the import dedups it."""
        vin = _vin_from_name(name)
        if vin is None:
            return None
        request_id = await request_id_for(vin, kind)
        if request_id is None:
            return None
        return await self._deliveries.get_content(conn, request_id, name)

    async def _run(
        self, config_path: Path, sampler_data_dir: Path, *, write: bool
    ) -> tuple[list[AccountStats], list[str]]:
        existing_secrets = load_secrets(self._settings.secrets_file)
        account_configs, problems = _read_sampler_config(config_path, sampler_data_dir)
        problems = [redact(p) for p in problems]

        stats: list[AccountStats] = []
        for cfg in account_configs:
            if write:
                async with self._db.write() as conn:
                    account_stats, account_problems = await self._process_account(
                        conn, cfg, existing_secrets, write=True
                    )
            else:
                async with self._db.read() as conn:
                    account_stats, account_problems = await self._process_account(
                        conn, cfg, existing_secrets, write=False
                    )
            stats.append(account_stats)
            problems.extend(redact(p) for p in account_problems)

        return stats, problems

    async def _process_account(
        self,
        conn: AsyncConnection,
        cfg: SamplerAccountConfig,
        existing_secrets: Mapping[str, Mapping[str, str]],
        *,
        write: bool,
    ) -> tuple[AccountStats, list[str]]:
        problems: list[str] = []

        account = await self._accounts.get_by_label(conn, cfg.name)
        account_new = account is None
        if account is None:
            account_id = uuid4()
            if write:
                await self._accounts.add(
                    conn,
                    id=account_id,
                    provider_id=PROVIDER_ID,
                    brand=cfg.brand,
                    label=cfg.name,
                    credential_ref=cfg.name,
                    state="active",
                    state_reason=None,
                    created_at=self._clock(),
                )
        else:
            account_id = account.id

        new_values = {"user": cfg.user, "password": cfg.password}
        if write:
            outcome = write_credentials(
                self._settings.secrets_file, cfg.name, new_values, overwrite=False
            )
            credential_state = {
                WriteOutcome.CREATED: "new",
                WriteOutcome.UNCHANGED: "same",
                WriteOutcome.CONFLICT: "conflict",
            }[outcome]
        else:
            existing_cred = existing_secrets.get(cfg.name)
            if existing_cred is None:
                credential_state = "new"
            elif dict(existing_cred) == new_values:
                credential_state = "same"
            else:
                credential_state = "conflict"
        if credential_state == "conflict":
            problems.append(
                f"account '{cfg.name}': credentials in the secrets file differ, not overwritten"
            )

        vehicles_new = 0
        vehicles_existing = 0
        vehicle_ids: dict[str, UUID] = {}
        for vin in cfg.vins:
            existing_vehicle = (
                None if account_new else await self._vehicles.get_by_vin(conn, account_id, vin)
            )
            if existing_vehicle is None:
                vehicles_new += 1
                vehicle_id = uuid4()
                if write:
                    await self._vehicles.add(
                        conn,
                        id=vehicle_id,
                        account_id=account_id,
                        vin=vin,
                        label=f"{cfg.name} …{vin[-6:]}" if len(vin) >= 6 else cfg.name,
                        brand=cfg.brand,
                        model=None,
                        created_at=self._clock(),
                    )
            else:
                vehicles_existing += 1
                vehicle_id = existing_vehicle.id
            vehicle_ids[vin] = vehicle_id

        request_cache: dict[tuple[str, str], tuple[UUID | None, bool]] = {}

        async def ensure_request(vin: str, kind: str) -> tuple[UUID | None, bool]:
            """Return `(data_request_id, is_new)`.

            `data_request_id` is `None` only when `write` is False and the request would
            be newly created (a dry run never inserts, so no real id exists yet to
            report).
            """
            key = (vin, kind)
            if key in request_cache:
                return request_cache[key]
            vehicle_id = vehicle_ids.get(vin)
            if vehicle_id is None:
                result: tuple[UUID | None, bool] = (None, False)
                request_cache[key] = result
                return result

            existing_request = None
            if not account_new:
                for record in await self._requests.list_for_vehicle(conn, vehicle_id):
                    if record.kind == kind:
                        existing_request = record
                        break
            if existing_request is not None:
                result = (existing_request.id, False)
            elif write:
                new_id = await self._requests.ensure(
                    conn,
                    vehicle_id=vehicle_id,
                    kind=kind,
                    interval_s=self._settings.fetch_interval_min * 60,
                )
                result = (new_id, True)
            else:
                result = (None, True)
            request_cache[key] = result
            return result

        deliveries_with_content_new = 0
        deliveries_with_content_skipped = 0
        deliveries_placeholder_new = 0
        deliveries_placeholder_skipped = 0
        runs_new = 0
        runs_skipped = 0

        sampler_conn = _open_sampler_db_readonly(cfg.sampler_db_path)
        if sampler_conn is not None:
            try:
                for row in sampler_conn.execute(
                    "SELECT dataset_name, dataset_type, sha256, size_bytes, raw_json,"
                    " fetched_at_utc FROM captures ORDER BY id"
                ):
                    name, kind, _sha256, _size_bytes, raw_json, fetched_at_utc = row
                    found_vin = _vin_from_name(name)
                    if found_vin is None or found_vin not in vehicle_ids:
                        problems.append(
                            f"account '{cfg.name}': capture for an unconfigured vehicle, skipped"
                        )
                        continue
                    request_id, request_is_new = await ensure_request(found_vin, kind)
                    already = False
                    if not request_is_new:
                        assert request_id is not None  # an existing request always has a real id
                        already = await self._deliveries.exists(conn, request_id, name)
                    if already:
                        deliveries_with_content_skipped += 1
                        continue
                    deliveries_with_content_new += 1
                    if not write:
                        continue
                    fetched_at, _quality = parse_timestamp(fetched_at_utc)
                    if fetched_at is None:
                        problems.append(
                            f"account '{cfg.name}': capture with an unparsable fetch time, skipped"
                        )
                        deliveries_with_content_new -= 1
                        continue
                    payload = _wrap_json_as_zip(raw_json)
                    await self._deliveries.add(
                        conn,
                        data_request_id=request_id,
                        import_batch_id=None,
                        remote_name=name,
                        delivered_at=_delivered_at_from_name(name),
                        fetched_at=fetched_at,
                        has_content=True,
                        sha256=hashlib.sha256(payload).hexdigest(),
                        size_bytes=len(payload),
                        parse_state="pending",
                        parser_version=None,
                        raw_payload=payload,
                    )

                for row in sampler_conn.execute(
                    "SELECT dataset_name, dataset_type, sha256, size_bytes, fetched_at_utc"
                    " FROM placeholders ORDER BY id"
                ):
                    name, kind, sha256, size_bytes, fetched_at_utc = row
                    found_vin = _vin_from_name(name)
                    if found_vin is None or found_vin not in vehicle_ids:
                        problems.append(
                            f"account '{cfg.name}': placeholder for an unconfigured vehicle,"
                            " skipped"
                        )
                        continue
                    request_id, request_is_new = await ensure_request(found_vin, kind)
                    already = False
                    if not request_is_new:
                        assert request_id is not None  # an existing request always has a real id
                        already = await self._deliveries.exists(conn, request_id, name)
                    if already:
                        deliveries_placeholder_skipped += 1
                        continue
                    deliveries_placeholder_new += 1
                    if not write:
                        continue
                    fetched_at, _quality = parse_timestamp(fetched_at_utc)
                    if fetched_at is None:
                        problems.append(
                            f"account '{cfg.name}': placeholder with an unparsable fetch time,"
                            " skipped"
                        )
                        deliveries_placeholder_new -= 1
                        continue
                    await self._deliveries.add(
                        conn,
                        data_request_id=request_id,
                        import_batch_id=None,
                        remote_name=name,
                        delivered_at=_delivered_at_from_name(name),
                        fetched_at=fetched_at,
                        has_content=False,
                        sha256=sha256,
                        size_bytes=size_bytes,
                        parse_state="empty",
                        parser_version=None,
                        raw_payload=None,
                    )

                for row in sampler_conn.execute(
                    "SELECT started_at_utc, finished_at_utc, vin, dataset_type, outcome,"
                    " listed, placeholders, downloaded, with_content, pending, message"
                    " FROM fetch_runs ORDER BY id"
                ):
                    (
                        started_raw,
                        finished_raw,
                        vin,
                        kind,
                        outcome,
                        listed,
                        placeholders_n,
                        downloaded,
                        with_content,
                        pending,
                        message,
                    ) = row
                    started_at, _quality = parse_timestamp(started_raw)
                    finished_at, _quality = parse_timestamp(finished_raw)
                    if started_at is None or finished_at is None:
                        problems.append(
                            f"account '{cfg.name}': run with an unparsable timestamp, skipped"
                        )
                        continue

                    if vin == "*":
                        request_id = None
                        request_is_new = False
                    else:
                        if vin not in vehicle_ids:
                            problems.append(
                                f"account '{cfg.name}': run for an unconfigured vehicle, skipped"
                            )
                            continue
                        request_id, request_is_new = await ensure_request(vin, kind)

                    already = (
                        False
                        if request_is_new
                        else await self._runs.exists(
                            conn,
                            account_id=account_id,
                            data_request_id=request_id,
                            started_at=started_at,
                            outcome=outcome,
                        )
                    )
                    if already:
                        runs_skipped += 1
                        continue
                    runs_new += 1
                    if not write:
                        continue
                    await self._runs.add(
                        conn,
                        account_id=account_id,
                        data_request_id=request_id,
                        started_at=started_at,
                        finished_at=finished_at,
                        outcome=outcome,
                        listed=listed,
                        placeholders=placeholders_n,
                        downloaded=downloaded,
                        with_content=with_content,
                        pending=pending,
                        oldest_pending_age_s=None,
                        message=redact(message)[:300] if message else None,
                    )
            finally:
                sampler_conn.close()

        requests_new = sum(1 for _, is_new in request_cache.values() if is_new)
        account_stats = AccountStats(
            name=cfg.name,
            account_new=account_new,
            credential_state=credential_state,
            vehicles_new=vehicles_new,
            vehicles_existing=vehicles_existing,
            requests_new=requests_new,
            deliveries_with_content_new=deliveries_with_content_new,
            deliveries_with_content_skipped=deliveries_with_content_skipped,
            deliveries_placeholder_new=deliveries_placeholder_new,
            deliveries_placeholder_skipped=deliveries_placeholder_skipped,
            runs_new=runs_new,
            runs_skipped=runs_skipped,
        )
        return account_stats, problems
