"""Composition root: wires `Settings` and secrets into the running application's services.

Only `cli` may import this module (enforced by `tests/test_layering.py`) — everywhere else
takes its collaborators as constructor arguments instead of knowing how to build them, so
the object graph has exactly one place that changes when a new provider or storage backend
is added.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from pathlib import Path

import structlog

from carchive import __version__
from carchive.config import ConfigError, InsecureSecretsError, Settings, load_secrets
from carchive.core.provider import ProviderRegistry
from carchive.providers.vwgroup.provider import VwGroupProvider
from carchive.services.accounts import AccountService
from carchive.services.backup import BackupService, options_from_settings
from carchive.services.catalog import CatalogService
from carchive.services.collector import Collector
from carchive.services.operator_auth import LoginThrottle, OperatorAuth
from carchive.services.reparse import Reparser
from carchive.services.sampler_import import SamplerImporter
from carchive.services.scheduler import Scheduler
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head

DB_FILENAME = "carchive.sqlite3"

logger = structlog.get_logger(__name__)

_Signature = tuple[int, int, int, int, int]


class LiveCredentials:
    """Decrypted portal credentials that follow changes to the secrets file.

    The file is re-read whenever its modification time, change time, size, inode or mode
    differs from the last successful read, so a password set while the service runs takes
    effect on the next collection pass. A failed re-read is an error, never a reason to keep
    using the previous values.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._credentials: dict[str, dict[str, str]] = {}
        self._signature: _Signature | None = None
        self._loaded = False

    def __call__(self, credential_ref: str) -> Mapping[str, str]:
        """Return the current credentials of one reference.

        Args:
            credential_ref: the account's credential reference.

        Returns:
            The decrypted fields of `credential_ref`.

        Raises:
            KeyError: if the secrets file holds no entry for `credential_ref`.
            ConfigError: if the secrets file cannot be read, is insecure or malformed, or its
                encrypted values cannot be decrypted. The message never carries a value.
        """
        signature = self._current_signature()
        if not self._loaded or signature != self._signature:
            try:
                credentials = load_secrets(self._path)
            except (ConfigError, InsecureSecretsError) as exc:
                raise ConfigError(f"cannot load portal credentials: {exc}") from None
            except OSError as exc:
                raise ConfigError(
                    f"cannot read portal credentials from {self._path}: {exc.strerror}"
                ) from None
            if self._loaded:
                logger.info("credentials.reloaded")
            self._credentials = credentials
            self._signature = signature
            self._loaded = True
        return self._credentials[credential_ref]

    def _current_signature(self) -> _Signature | None:
        try:
            info = self._path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConfigError(
                f"cannot read portal credentials from {self._path}: {exc.strerror}"
            ) from None
        return (info.st_mtime_ns, info.st_size, info.st_ino, info.st_ctime_ns, info.st_mode)


class Services:
    """The fully wired, not-yet-running application.

    Attributes:
        db: the connected application database.
        registry: providers available to `collector`.
        collector: runs one account's collection pass.
        backup: creates/verifies/prunes/restores backups.
        scheduler: the due-time loop driving `collector`, and `backup` once daily.
        accounts: adds, tests, lists and deletes accounts and vehicles.
        operator_auth: password and session handling for the operator login.
        login_throttle: the brute-force throttle for login attempts, one per process.
    """

    def __init__(
        self,
        db: Database,
        registry: ProviderRegistry,
        collector: Collector,
        backup: BackupService,
        scheduler: Scheduler,
        accounts: AccountService,
        operator_auth: OperatorAuth,
        login_throttle: LoginThrottle,
    ) -> None:
        self.db = db
        self.registry = registry
        self.collector = collector
        self.backup = backup
        self.scheduler = scheduler
        self.accounts = accounts
        self.operator_auth = operator_auth
        self.login_throttle = login_throttle

    async def close(self) -> None:
        """Close the database connection; the only resource this object owns."""
        await self.db.close()


def build_provider_registry() -> ProviderRegistry:
    """Build a `ProviderRegistry` holding every provider Carchive currently supports.

    Returns:
        A registry with the VW-group provider registered, identifying itself with a
        `carchive/<version>` user agent.
    """
    registry = ProviderRegistry()
    registry.register(VwGroupProvider(user_agent=f"carchive/{__version__}"))
    return registry


async def build_services(
    settings: Settings,
    db_path: Path,
) -> Services:
    """Build the application's services from loaded settings.

    Provider credentials are read from `settings.secrets_file` when the collector first
    needs them and again whenever the file changes (see `LiveCredentials`).

    Args:
        settings: the application's runtime configuration.
        db_path: path to the SQLite database file. Its parent directory must already
            exist; the caller is expected to hold a `DataDirLock` on it.

    Returns:
        The wired `Services`, with `db` already connected. Callers must call
        `Services.close` when done.
    """
    db = Database()
    await db.connect(db_path)

    registry = build_provider_registry()

    collector = Collector(
        db,
        registry,
        LiveCredentials(settings.secrets_file),
        interval_s=settings.fetch_interval_min * 60,
    )
    backup = BackupService(
        db_path,
        settings.effective_backup_dir,
        db,
        keep_daily=settings.backup_keep_daily,
        keep_weekly=settings.backup_keep_weekly,
        keep_monthly=settings.backup_keep_monthly,
        options=options_from_settings(settings),
    )
    scheduler = Scheduler(
        collector,
        db,
        backup=backup,
        backup_time=settings.backup_time,
        raw_payload_retention_days=settings.raw_payload_retention_days,
    )
    accounts = AccountService(db, registry, settings, backup=backup)

    operator_auth = OperatorAuth(db, settings.secrets_file)

    return Services(
        db, registry, collector, backup, scheduler, accounts, operator_auth, LoginThrottle()
    )


class ReparseServices:
    """The database and `Reparser` wired up for a one-off `parse-pending` CLI run.

    Attributes:
        db: the connected application database.
        reparser: re-parses pending deliveries and recomputes signal values.
    """

    def __init__(self, db: Database, reparser: Reparser) -> None:
        self.db = db
        self.reparser = reparser

    async def close(self) -> None:
        """Close the database connection; the only resource this object owns."""
        await self.db.close()


async def build_reparse_services(db_path: Path) -> ReparseServices:
    """Build a `Reparser` against `db_path`, with no provider credentials needed.

    Args:
        db_path: path to the SQLite database file. Its parent directory must already
            exist; the caller is expected to hold a `DataDirLock` on it.

    Returns:
        The wired `ReparseServices`, with `db` already connected. Callers must call
        `ReparseServices.close` when done.
    """
    db = Database()
    await db.connect(db_path)
    registry = build_provider_registry()
    return ReparseServices(db, Reparser(db, registry))


class CatalogServices:
    """The database and `CatalogService` wired up for a `catalog` CLI run.

    Attributes:
        db: the connected application database.
        catalog: imports and looks up Data Dictionary catalog entries.
    """

    def __init__(self, db: Database, catalog: CatalogService) -> None:
        self.db = db
        self.catalog = catalog

    async def close(self) -> None:
        """Close the database connection; the only resource this object owns."""
        await self.db.close()


async def build_catalog_services(db_path: Path) -> CatalogServices:
    """Build a `CatalogService` against `db_path`, with no provider credentials needed.

    Args:
        db_path: path to the SQLite database file. Its parent directory must already
            exist; the caller is expected to hold a `DataDirLock` on it.

    Returns:
        The wired `CatalogServices`, with `db` already connected. Callers must call
        `CatalogServices.close` when done.
    """
    db = Database()
    await db.connect(db_path)
    return CatalogServices(db, CatalogService(db))


class SamplerImportServices:
    """The database, `SamplerImporter` and `Reparser` wired up for a `import-sampler` run.

    Attributes:
        db: the connected application database.
        importer: reads the sampler's config and per-account databases and imports them.
        reparser: parses the deliveries `importer.apply` just stored, once requested.
    """

    def __init__(
        self,
        db: Database,
        importer: SamplerImporter,
        reparser: Reparser,
        *,
        temp_dir: tempfile.TemporaryDirectory[str] | None = None,
    ) -> None:
        self.db = db
        self.importer = importer
        self.reparser = reparser
        self._temp_dir = temp_dir

    async def close(self) -> None:
        """Close the database connection, and remove the temporary directory, if any."""
        await self.db.close()
        if self._temp_dir is not None:
            self._temp_dir.cleanup()


async def build_sampler_import_services(settings: Settings, db_path: Path) -> SamplerImportServices:
    """Build a `SamplerImporter` and `Reparser` against `db_path`, with no portal login needed.

    Args:
        settings: the application's runtime configuration.
        db_path: path to the SQLite database file. Its parent directory must already
            exist; the caller is expected to hold a `DataDirLock` on it.

    Returns:
        The wired `SamplerImportServices`, with `db` already connected. Callers must call
        `SamplerImportServices.close` when done.
    """
    db = Database()
    await db.connect(db_path)
    registry = build_provider_registry()
    return SamplerImportServices(db, SamplerImporter(db, settings), Reparser(db, registry))


async def build_sampler_plan_services(settings: Settings, db_path: Path) -> SamplerImportServices:
    """Build a `SamplerImporter`/`Reparser` for a read-only sampler-import plan.

    Never migrates, backs up or writes to `db_path` or its parent directory, so a dry-run
    plan is safe to compute without a `DataDirLock` on a data directory that may not even
    exist yet.

    Args:
        settings: the application's runtime configuration.
        db_path: path to the SQLite database file to plan against.

    Returns:
        The wired `SamplerImportServices`. If `db_path` exists, `db` is connected to it
        directly, with no migration: a schema older than the plan's queries expect surfaces
        as a `sqlalchemy.exc.OperationalError` from the first affected query, which the
        caller is expected to turn into a "run `db upgrade` first" message. If `db_path`
        does not exist yet, a freshly migrated, empty database in a temporary directory
        stands in for it instead, since a plan against a database that has never been
        written to is the same as a plan against an empty one. Callers must call
        `SamplerImportServices.close` when done, which also removes the temporary
        directory, if one was created.
    """
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    connect_path = db_path
    if not db_path.exists():
        temp_dir = tempfile.TemporaryDirectory(prefix="carchive-plan-")
        connect_path = Path(temp_dir.name) / DB_FILENAME
        await upgrade_to_head(connect_path)

    db = Database()
    await db.connect(connect_path)
    registry = build_provider_registry()
    return SamplerImportServices(
        db, SamplerImporter(db, settings), Reparser(db, registry), temp_dir=temp_dir
    )
