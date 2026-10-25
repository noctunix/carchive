"""Carchive command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import getpass
import logging
import os
import ssl
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import httpx
import structlog
import uvicorn
from sqlalchemy.exc import OperationalError

from carchive import __version__
from carchive.bootstrap import (
    Services,
    build_catalog_services,
    build_reparse_services,
    build_sampler_import_services,
    build_sampler_plan_services,
    build_services,
)
from carchive.config import (
    ConfigError,
    InsecureSecretsError,
    SecretsLockTimeoutError,
    Settings,
    inspect_vault,
    is_loopback_host,
    load_operator_hash,
    load_secrets,
    load_settings,
)
from carchive.core.errors import ProviderError
from carchive.core.models import RemoteVehicle
from carchive.core.redact import mask_vin, register_secret
from carchive.logging_setup import configure_logging
from carchive.services import sampler_import, tls, tls_selfsigned, user_service
from carchive.services.accounts import (
    AccountInfo,
    AccountServiceError,
    DeletionResult,
    LoginRejectedError,
    VehicleInfo,
)
from carchive.services.app_services import AppServices
from carchive.services.backup import (
    BackupError,
    BackupOptions,
    BackupService,
    PassphraseProvider,
    PassphraseUnavailableError,
    options_from_settings,
    read_passphrase_file,
)
from carchive.services.catalog import (
    CatalogError,
    CatalogImportResult,
    CatalogVersionSummary,
    default_catalog_version,
)
from carchive.services.lock import AlreadyRunningError, DataDirLock
from carchive.services.operator_auth import (
    OperatorAuth,
    OperatorAuthError,
    PasswordPolicyError,
)
from carchive.services.reparse import ReparseResult
from carchive.services.sampler_import import ImportPlan, ImportReport, VerifyReport
from carchive.storage.migrate import current_revision, head_revision, upgrade_to_head
from carchive.web.app import create_app

logger = structlog.get_logger(__name__)

_DB_FILENAME = "carchive.sqlite3"
_HEALTHCHECK_TIMEOUT_S = 5.0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="carchive")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    parser.add_argument(
        "--log-format",
        choices=["console", "json", "auto"],
        default="auto",
        help="log output format (default: auto, console on a TTY else JSON)",
    )

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("version", help="print the version and exit")
    subparsers.add_parser("check", help="verify configuration, secrets and data directory")

    subparsers.add_parser("serve", help="run the collector and web GUI")
    subparsers.add_parser(
        "healthcheck", help="probe the local server's /healthz (exit 0 if healthy, else 1)"
    )

    subparsers.add_parser(
        "parse-pending", help="re-parse deliveries stuck at parse_state 'pending'"
    )

    import_sampler_parser = subparsers.add_parser(
        "import-sampler",
        help="take over eu_data_act_sampler.py's captured data, idempotently",
    )
    import_sampler_parser.add_argument(
        "--config",
        default=None,
        help="sampler config.ini (default: ~/.config/carchive/config.ini)",
    )
    import_sampler_parser.add_argument(
        "--sampler-data-dir",
        default=None,
        help="sampler data directory (default: its own [storage] data_dir, else "
        "~/.local/share/carchive)",
    )
    import_mode = import_sampler_parser.add_mutually_exclusive_group()
    import_mode.add_argument(
        "--apply",
        action="store_true",
        help="write the import; without this flag only a dry-run plan is printed",
    )
    import_mode.add_argument(
        "--verify",
        action="store_true",
        help="read-only check that everything in the sampler's databases is stored in "
        "Carchive with matching content; exits 1 if anything is missing or differs",
    )
    import_sampler_parser.add_argument(
        "--no-parse",
        action="store_true",
        help="skip parsing newly imported deliveries into data points and signal values",
    )

    db_parser = subparsers.add_parser("db", help="manage the local database schema")
    db_subparsers = db_parser.add_subparsers(dest="db_command")
    db_subparsers.add_parser("upgrade", help="migrate the database to the latest schema")
    db_subparsers.add_parser("status", help="show the database's current and latest revision")

    backup_parser = subparsers.add_parser(
        "backup", help="create, verify, prune and restore backups"
    )
    backup_subparsers = backup_parser.add_subparsers(dest="backup_command")
    create_parser = backup_subparsers.add_parser("create", help="create a new verified backup")
    create_parser.add_argument(
        "--include-credentials",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="add secrets.toml and vault.key to the backup (overrides backup_include_credentials)",
    )
    create_parser.add_argument(
        "--encrypt",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="encrypt the backup with a passphrase (overrides backup_encrypt)",
    )
    create_parser.add_argument(
        "--allow-plaintext-credentials",
        action="store_true",
        help="allow credentials in an unencrypted backup; vault.key then lies next to "
        "secrets.toml in a readable archive",
    )
    backup_subparsers.add_parser("list", help="list existing backups")
    verify_parser = backup_subparsers.add_parser("verify", help="verify one backup archive")
    verify_parser.add_argument("file", help="path to the backup archive")
    backup_subparsers.add_parser("prune", help="delete backups outside the retention window")
    restore_parser = backup_subparsers.add_parser(
        "restore", help="restore a backup over the live database"
    )
    restore_parser.add_argument("file", help="path to the backup archive")
    restore_parser.add_argument(
        "--restore-credentials",
        action="store_true",
        help="also restore secrets.toml and vault.key from the archive",
    )
    restore_parser.add_argument(
        "--overwrite-credentials",
        action="store_true",
        help="with --restore-credentials, replace existing credential files "
        "(kept aside with a .before-restore suffix)",
    )

    catalog_parser = subparsers.add_parser(
        "catalog", help="import and list the local Data Dictionary catalog"
    )
    catalog_subparsers = catalog_parser.add_subparsers(dest="catalog_command")
    catalog_import_parser = catalog_subparsers.add_parser(
        "import", help="import a Data Dictionary PDF"
    )
    catalog_import_parser.add_argument("pdf", help="path to the dictionary PDF")
    catalog_import_parser.add_argument(
        "--catalog-version",
        default=None,
        help="version to store entries under (default: derived from the filename)",
    )
    catalog_import_parser.add_argument(
        "--provider",
        default="vwgroup-euda",
        help="provider the dictionary belongs to (default: vwgroup-euda)",
    )
    catalog_subparsers.add_parser("list", help="list imported catalog versions")

    account_parser = subparsers.add_parser("account", help="manage portal accounts")
    account_subparsers = account_parser.add_subparsers(dest="account_command")
    account_subparsers.add_parser("add", help="add a new portal account interactively")
    account_subparsers.add_parser("list", help="list configured accounts")
    account_remove_parser = account_subparsers.add_parser(
        "remove", help="remove an account, its vehicles and all their data"
    )
    account_remove_parser.add_argument("label")
    account_remove_parser.add_argument(
        "--yes", action="store_true", help="actually delete; without this, only preview"
    )

    account_set_password_parser = account_subparsers.add_parser(
        "set-password",
        help="replace an account's stored portal password (prompts; keeps all data); without "
        "a label, replace every unreadable password, e.g. after losing vault.key",
    )
    account_set_password_parser.add_argument("label", nargs="?")

    operator_parser = subparsers.add_parser("operator", help="manage the web login")
    operator_subparsers = operator_parser.add_subparsers(dest="operator_command")
    operator_subparsers.add_parser(
        "set-password", help="set or replace the operator password (ends all sessions)"
    )

    vehicle_parser = subparsers.add_parser("vehicle", help="manage vehicles")
    vehicle_subparsers = vehicle_parser.add_subparsers(dest="vehicle_command")
    vehicle_sync_parser = vehicle_subparsers.add_parser(
        "sync", help="discover and add new vehicles reported by an account"
    )
    vehicle_sync_parser.add_argument("label")
    vehicle_subparsers.add_parser("list", help="list configured vehicles")
    vehicle_remove_parser = vehicle_subparsers.add_parser(
        "remove", help="remove a vehicle and all its data"
    )
    vehicle_remove_parser.add_argument("id_prefix", help="a prefix of the vehicle's id")
    vehicle_remove_parser.add_argument(
        "--yes", action="store_true", help="actually delete; without this, only preview"
    )

    service_parser = subparsers.add_parser("service", help="run Carchive as a systemd user service")
    service_subparsers = service_parser.add_subparsers(dest="service_command")
    service_install_parser = service_subparsers.add_parser(
        "install", help="install, enable and start the user service, and enable lingering"
    )
    service_install_parser.add_argument(
        "--no-start", action="store_true", help="enable the service but do not start it now"
    )
    service_subparsers.add_parser(
        "uninstall", help="stop and remove the user service (lingering stays on)"
    )
    service_subparsers.add_parser("status", help="show the service state and recent log lines")

    fetch_parser = subparsers.add_parser("fetch", help="run one collection pass now")
    fetch_parser.add_argument("--account", default=None, help="only this account's label")
    fetch_parser.add_argument(
        "--now",
        action="store_true",
        help="run every account now, not only those with work currently due",
    )

    return parser


def _is_loopback_host(host: str) -> bool:
    """Return whether `host` resolves to a loopback address without a DNS lookup."""
    return is_loopback_host(host)


def _load_settings_or_print_error() -> Settings | None:
    """Load settings, printing a `ConfigError` to stderr instead of raising it.

    Returns:
        The loaded `Settings`, or `None` if loading failed (already reported).
    """
    try:
        return load_settings()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None


def _run_check() -> int:
    """Run the `check` subcommand's diagnostics.

    Each check prints exactly one line (`ok` or `error: …`) and never a
    secret or full VIN. Settings failing to load is fatal for the whole
    command; the other checks are independent and all run even if one
    fails.

    Returns:
        0 if every check passed, else 1.
    """
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    all_ok = True

    try:
        load_secrets(settings.secrets_file)
        print("secrets file: ok")
    except InsecureSecretsError as exc:
        print(f"secrets file: error: {exc}")
        all_ok = False
    except ConfigError as exc:
        print(f"secrets file: error: {exc}")
        all_ok = False

    if not _print_vault_check(settings):
        all_ok = False

    try:
        if not settings.data_dir.is_dir():
            settings.data_dir.mkdir(parents=True)
            settings.data_dir.chmod(0o700)
        probe = settings.data_dir / ".carchive-check"
        probe.touch()
        probe.unlink()
        print("data directory: ok")
    except OSError as exc:
        print(f"data directory: error: {exc}")
        all_ok = False

    bind_refusal = _serve_bind_refusal(settings.bind_host, settings.container, settings.tls_enabled)
    if bind_refusal is None:
        print("bind host: ok")
    else:
        print(f"bind host: error: {bind_refusal}")
        all_ok = False

    if not _print_auth_check(settings):
        all_ok = False

    if not _print_tls_check(settings):
        all_ok = False

    print(f"container mode: {'enabled' if settings.container else 'disabled'}")

    return 0 if all_ok else 1


def _print_vault_check(settings: Settings) -> bool:
    """Print the `vault:` line of `check`.

    Args:
        settings: the loaded settings.

    Returns:
        `True` unless the vault key or the secrets file is unusable.
    """
    try:
        status = inspect_vault(settings.secrets_file)
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"vault: error: {exc}")
        return False
    key = "key present, mode ok" if status.key_present else "no key file yet"
    line = (
        f"vault: {key}; {status.sealed_values} encrypted, "
        f"{status.plaintext_values} plaintext password(s)"
    )
    if status.plaintext_values:
        line += " (the next credential write encrypts them)"
    print(line)
    return True


def _print_auth_check(settings: Settings) -> bool:
    """Print the `auth:` line of `check`.

    Returns:
        `False` if the stored login state is unusable.
    """
    try:
        password_set = load_operator_hash(settings.secrets_file) is not None
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"auth: error: {exc}")
        return False
    if password_set:
        print("auth: password set")
    else:
        print(
            f"auth: no password set (open {_server_url(settings)}/login and choose one; "
            "whoever submits the form first becomes the operator)"
        )
    return True


def _print_tls_check(settings: Settings) -> bool:
    """Print the `tls:` lines of `check`.

    Never writes: for the automatic self-signed certificate it only reports what `serve`
    would find or do.

    Returns:
        Whether TLS is unconfigured or configured without errors and with an unexpired
        certificate.
    """
    if settings.tls_certfile is None or settings.tls_keyfile is None:
        if settings.tls_selfsigned_active:
            return _print_selfsigned_check(settings)
        if settings.container:
            print("tls: warning: container serves plain HTTP (tls_selfsigned disabled)")
        else:
            print("tls: not configured")
        return True
    report = tls.inspect_tls(settings.tls_certfile, settings.tls_keyfile, settings.allowed_hosts)
    for error in report.errors:
        print(f"tls: error: {error}")
    if not report.errors:
        if report.expired:
            print(f"tls: error: {report.expiry_note}")
        else:
            details = f"expires in {report.days_left} days, names: {', '.join(report.names)}"
            print(f"tls: ok ({details})")
            if report.expiry_note:
                print(f"tls: warning: {report.expiry_note}")
    for warning in report.warnings:
        print(f"tls: warning: {warning}")
    return not report.errors and not report.expired


def _print_selfsigned_check(settings: Settings) -> bool:
    """Print the `tls:` lines for the automatic self-signed certificate.

    Returns:
        `False` if the host allowlist cannot be put into a certificate.
    """
    try:
        assessment = tls_selfsigned.assess_selfsigned(settings.data_dir, settings.allowed_hosts)
    except tls_selfsigned.SelfSignedError as exc:
        print(f"tls: error: {exc}")
        return False
    info = assessment.info
    if assessment.reason is not None:
        print(
            "tls: ok (self-signed (automatic), a new certificate will be generated on "
            f"start: {assessment.reason.value})"
        )
    if assessment.reason is None and info is not None:
        details = f"expires in {info.days_left} days, names: {', '.join(info.names)}"
        print(f"tls: ok (self-signed (automatic), {details})")
    if info is not None:
        print(f"tls: sha256 fingerprint: {info.fingerprint}")
    return True


def _server_url(settings: Settings) -> str:
    """Return the base URL the server is reachable at, `https://` if TLS is configured."""
    host = f"[{settings.bind_host}]" if ":" in settings.bind_host else settings.bind_host
    scheme = "https" if settings.tls_enabled else "http"
    return f"{scheme}://{host}:{settings.port}"


def _preflight_tls(settings: Settings) -> bool:
    """Validate the TLS files before `serve` starts and log non-blocking findings.

    An expired or soon-expiring certificate is logged but never stops the collector.

    Returns:
        `False` (after printing the problems to stderr) if the server must not start.
    """
    if settings.tls_certfile is None or settings.tls_keyfile is None:
        return True
    report = tls.inspect_tls(settings.tls_certfile, settings.tls_keyfile, settings.allowed_hosts)
    if report.errors:
        for error in report.errors:
            print(f"error: tls: {error}", file=sys.stderr)
        return False
    if report.expired:
        logger.error("cli.tls_certificate_expired", note=report.expiry_note)
    elif report.expiry_note:
        logger.warning("cli.tls_certificate_expiring", note=report.expiry_note)
    for warning in report.warnings:
        logger.warning("cli.tls_warning", note=warning)
    return True


async def _upgrade_with_backup(settings: Settings, db_path: Path) -> tuple[str | None, str | None]:
    """Back up `db_path` first if it exists and the migration will actually change its revision.

    A database that was never migrated (fresh install) has no meaningful content to
    protect, so no backup is created for it.
    """
    if db_path.exists() and await current_revision(db_path) != head_revision():
        async with BackupService.connect(
            db_path,
            settings.effective_backup_dir,
            keep_daily=settings.backup_keep_daily,
            keep_weekly=settings.backup_keep_weekly,
            keep_monthly=settings.backup_keep_monthly,
            options=_backup_options(settings),
        ) as backup_service:
            await backup_service.create()
    return await upgrade_to_head(db_path)


def _run_db_upgrade() -> int:
    """Run the `db upgrade` subcommand: back up, then migrate the database to the latest schema.

    Takes the data directory lock for the duration of the backup and migration, so it
    never races a running server.

    Returns:
        0 on success, 1 if the data directory is already locked by another process or the
        pre-migration backup failed, 2 if settings fail to load.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            previous, new = asyncio.run(_upgrade_with_backup(settings, db_path))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1

    print(f"upgraded {previous or '(none)'} -> {new}")
    return 0


def _run_db_status() -> int:
    """Run the `db status` subcommand: compare the database's revision against the latest.

    Returns:
        0 if the database is at the latest revision, 1 if it is behind, 2 if settings fail
        to load.
    """
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    current = asyncio.run(current_revision(db_path))
    head = head_revision()
    print(f"current: {current or '(none)'}")
    print(f"head: {head or '(none)'}")
    return 0 if current == head else 1


async def _parse_pending(db_path: Path) -> ReparseResult:
    services = await build_reparse_services(db_path)
    try:
        return await services.reparser.parse_pending()
    finally:
        await services.close()


def _run_parse_pending() -> int:
    """Run the `parse-pending` subcommand: re-parse deliveries stuck at `parse_state = 'pending'`.

    Takes the data directory lock for the duration of the run, so it never races a running
    server's collector.

    Returns:
        0 on success, 1 if the data directory is already locked, 2 if settings fail to load.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            result = asyncio.run(_parse_pending(db_path))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"parsed {result.parsed}, failed {result.failed}")
    return 0


def _print_import_result(result: ImportPlan | ImportReport) -> None:
    """Print an `ImportPlan` or `ImportReport`: one line per account, then every problem.

    Never prints a password or full VIN: both are held only as config/sampler state, never
    carried into `AccountStats` or the problem strings (which are redacted before storage).
    """
    for account in result.accounts:
        print(
            f"{account.name}: account {'new' if account.account_new else 'existing'}, "
            f"credentials {account.credential_state}, "
            f"vehicles {account.vehicles_new} new / {account.vehicles_existing} existing, "
            f"requests {account.requests_new} new, "
            f"deliveries {account.deliveries_with_content_new} new / "
            f"{account.deliveries_with_content_skipped} skipped with content, "
            f"{account.deliveries_placeholder_new} new / "
            f"{account.deliveries_placeholder_skipped} skipped placeholders, "
            f"runs {account.runs_new} new / {account.runs_skipped} skipped"
        )
    for problem in result.problems:
        print(f"problem: {problem}")


async def _plan_import_sampler(
    settings: Settings, db_path: Path, config_path: Path, sampler_data_dir: Path
) -> ImportPlan:
    """Compute a dry-run plan without migrating, backing up or writing to `db_path`.

    Raises:
        OperationalError: if `db_path` exists but its schema is too old for the plan's
            queries.
    """
    services = await build_sampler_plan_services(settings, db_path)
    try:
        return await services.importer.plan(config_path, sampler_data_dir)
    finally:
        await services.close()


async def _apply_import_sampler(
    settings: Settings, db_path: Path, config_path: Path, sampler_data_dir: Path, no_parse: bool
) -> tuple[ImportReport, ReparseResult | None]:
    await _upgrade_with_backup(settings, db_path)
    services = await build_sampler_import_services(settings, db_path)
    try:
        plan = await services.importer.plan(config_path, sampler_data_dir)
        report = await services.importer.apply(plan)
        parse_result = None if no_parse else await services.reparser.parse_pending()
        return report, parse_result
    finally:
        await services.close()


def _resolve_sampler_inputs(
    config: str | None, sampler_data_dir_arg: str | None
) -> tuple[Settings, Path, Path, Path] | None:
    """Load settings and resolve the sampler paths shared by `import-sampler` modes.

    Args:
        config: the `--config` argument, or `None` for the default location.
        sampler_data_dir_arg: the `--sampler-data-dir` argument, or `None`.

    Returns:
        `(settings, config_path, sampler_data_dir, db_path)`, or `None` after printing an
        error if settings fail to load or the sampler config file does not exist.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return None
    config_path = (
        Path(config).expanduser() if config else sampler_import.default_sampler_config_path()
    )
    if not config_path.is_file():
        print(f"error: sampler config file not found: {config_path}", file=sys.stderr)
        return None
    override = Path(sampler_data_dir_arg).expanduser() if sampler_data_dir_arg else None
    sampler_data_dir = sampler_import.resolve_sampler_data_dir(config_path, override)
    return settings, config_path, sampler_data_dir, settings.data_dir / _DB_FILENAME


async def _verify_import_sampler(
    settings: Settings, db_path: Path, config_path: Path, sampler_data_dir: Path
) -> VerifyReport:
    """Compare the sampler's data with `db_path` without migrating or writing anything.

    Raises:
        OperationalError: if `db_path` exists but its schema is too old for the queries.
    """
    services = await build_sampler_plan_services(settings, db_path)
    try:
        return await services.importer.verify(config_path, sampler_data_dir)
    finally:
        await services.close()


def _print_verify_report(report: VerifyReport) -> None:
    """Print one line per account and kind, then every problem and the verdict.

    Contains only counts, account names and kinds: no file names, VINs or contents.
    """
    for account in report.accounts:
        note = "" if account.account_present else " (account not in Carchive)"
        if not account.kinds:
            print(f"{account.name}: no files in the sampler{note}")
        for kind in account.kinds:
            print(
                f"{account.name} [{kind.kind}]{note}: sampler {kind.files}, "
                f"in Carchive {kind.present}, missing {kind.missing}, "
                f"content differs {kind.differing}"
            )
    for problem in report.problems:
        print(f"problem: {problem}")
    print("verify: complete" if report.complete else "verify: INCOMPLETE")


def _run_verify_sampler(config: str | None, sampler_data_dir_arg: str | None) -> int:
    """Run `import-sampler --verify`: check that the import lost nothing, read-only.

    Takes the data directory lock only if the directory exists, like a dry run, and never
    migrates, backs up or creates anything.

    Returns:
        0 if at least one account was checked and nothing is missing, differs or could not
        be verified, 1 if anything is missing, differs or could not be verified, or if the
        data directory is locked, 2 if settings, the sampler config file or the live
        database schema fail to load.
    """
    inputs = _resolve_sampler_inputs(config, sampler_data_dir_arg)
    if inputs is None:
        return 2
    settings, config_path, sampler_data_dir, db_path = inputs
    try:
        if settings.data_dir.is_dir():
            with DataDirLock(settings.data_dir):
                report = asyncio.run(
                    _verify_import_sampler(settings, db_path, config_path, sampler_data_dir)
                )
        else:
            report = asyncio.run(
                _verify_import_sampler(settings, db_path, config_path, sampler_data_dir)
            )
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OperationalError:
        print(
            "error: database schema is too old to verify against; run `carchive db upgrade` first",
            file=sys.stderr,
        )
        return 2
    _print_verify_report(report)
    return 0 if report.complete else 1


def _run_import_sampler(
    config: str | None, sampler_data_dir_arg: str | None, apply: bool, no_parse: bool
) -> int:
    """Run the `import-sampler` subcommand: take over the sampler's captured data.

    A dry run (`--apply` not given) never writes anything: no migration, no backup, no
    database file and no data directory are created, and the data directory is locked
    only if it already exists (so a run against a brand-new install does not race a
    `DataDirLock` against a directory `serve`/`db upgrade` would otherwise create first).
    `--apply` always migrates (with a pre-migration backup, like `db upgrade`) and holds
    the lock for the whole run, as every other writing subcommand does.

    Returns:
        0 on success with at least one importable account, 1 if the data directory is
        already locked, the pre-migration backup failed, or the plan found no importable
        account at all, 2 if settings, the secrets file, the sampler config file or (for a
        dry run) the live database schema fail to load.
    """
    inputs = _resolve_sampler_inputs(config, sampler_data_dir_arg)
    if inputs is None:
        return 2
    settings, config_path, sampler_data_dir, db_path = inputs

    try:
        if apply:
            with DataDirLock(settings.data_dir):
                report, parse_result = asyncio.run(
                    _apply_import_sampler(
                        settings, db_path, config_path, sampler_data_dir, no_parse
                    )
                )
            result: ImportPlan | ImportReport = report
        elif settings.data_dir.is_dir():
            with DataDirLock(settings.data_dir):
                result = asyncio.run(
                    _plan_import_sampler(settings, db_path, config_path, sampler_data_dir)
                )
            parse_result = None
        else:
            result = asyncio.run(
                _plan_import_sampler(settings, db_path, config_path, sampler_data_dir)
            )
            parse_result = None
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1
    except OperationalError:
        print(
            "error: database schema is too old for this plan; run `carchive db upgrade` first",
            file=sys.stderr,
        )
        return 2

    _print_import_result(result)
    if not result.accounts:
        return 1
    if parse_result is not None:
        print(f"parsed {parse_result.parsed}, failed {parse_result.failed}")
    return 0


def _passphrase_provider(
    settings: Settings, *, confirm: bool = False, interactive: bool = True
) -> PassphraseProvider:
    """Build the passphrase source for backups: the configured file, else a terminal prompt.

    The passphrase is never taken from arguments or the environment.

    Args:
        settings: the loaded settings (`backup_passphrase_file`).
        confirm: ask twice when prompting, for choosing a new passphrase.
        interactive: allow prompting on a terminal at all.

    Returns:
        A callable returning the passphrase; it raises `PassphraseUnavailableError` when
        there is no file and no terminal to ask on, or the two entries differ.
    """

    def provide() -> str:
        if settings.backup_passphrase_file is not None:
            return read_passphrase_file(settings.backup_passphrase_file)
        if not interactive or not sys.stdin.isatty():
            raise PassphraseUnavailableError(
                "a backup passphrase is required: set backup_passphrase_file or run this "
                "command from a terminal"
            )
        first = getpass.getpass("Backup passphrase: ")
        if confirm and getpass.getpass("Repeat passphrase: ") != first:
            raise PassphraseUnavailableError("the passphrases do not match")
        register_secret(first)
        return first

    return provide


def _backup_options(
    settings: Settings,
    *,
    include_credentials: bool | None = None,
    encrypt: bool | None = None,
    allow_plaintext_credentials: bool = False,
    confirm: bool = False,
    interactive: bool = True,
) -> BackupOptions:
    """Combine the backup settings with command-line overrides (`None` keeps the setting)."""
    options = options_from_settings(
        settings,
        passphrase=_passphrase_provider(settings, confirm=confirm, interactive=interactive),
    )
    return dataclasses.replace(
        options,
        include_credentials=(
            options.include_credentials if include_credentials is None else include_credentials
        ),
        encrypt=options.encrypt if encrypt is None else encrypt,
        allow_plaintext_credentials=(
            options.allow_plaintext_credentials or allow_plaintext_credentials
        ),
    )


def _backup_service(settings: Settings, options: BackupOptions | None = None) -> BackupService:
    """Build a `BackupService` with no `Database` attached, for read-only subcommands."""
    return BackupService(
        settings.data_dir / _DB_FILENAME,
        settings.effective_backup_dir,
        None,
        keep_daily=settings.backup_keep_daily,
        keep_weekly=settings.backup_keep_weekly,
        keep_monthly=settings.backup_keep_monthly,
        options=options if options is not None else _backup_options(settings),
    )


def _run_backup_create(
    include_credentials: bool | None, encrypt: bool | None, allow_plaintext_credentials: bool
) -> int:
    """Run the `backup create` subcommand.

    Args:
        include_credentials: overrides `backup_include_credentials` if not `None`.
        encrypt: overrides `backup_encrypt` if not `None`.
        allow_plaintext_credentials: permit credentials in an unencrypted backup.

    Returns:
        0 on success, 1 if creation failed (including credentials requested without
        encryption), 2 if settings fail to load or a needed passphrase is unavailable.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    options = _backup_options(
        settings,
        include_credentials=include_credentials,
        encrypt=encrypt,
        allow_plaintext_credentials=allow_plaintext_credentials,
        confirm=True,
    )

    async def _create() -> Path:
        async with BackupService.connect(
            settings.data_dir / _DB_FILENAME,
            settings.effective_backup_dir,
            keep_daily=settings.backup_keep_daily,
            keep_weekly=settings.backup_keep_weekly,
            keep_monthly=settings.backup_keep_monthly,
            options=options,
        ) as backup_service:
            return await backup_service.create()

    try:
        path = asyncio.run(_create())
    except PassphraseUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if options.include_credentials and not options.encrypt:
        print(
            "warning: the backup holds secrets.toml and vault.key unencrypted; "
            "anyone who can read it can read the stored portal passwords",
            file=sys.stderr,
        )
    print(f"created {path}")
    return 0


def _run_backup_list() -> int:
    """Run the `backup list` subcommand: show time, size, protection and verification status.

    Never prompts: an encrypted archive is verified in full only if a passphrase file is
    configured, otherwise just by checksum.

    Returns:
        0 always (an individual backup failing verification is reported per line, not a
        command failure), 2 if settings fail to load.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    service = _backup_service(settings, _backup_options(settings, interactive=False))
    for backup in service.list_backups():
        try:
            service.verify(backup.path)
            status = "verified"
        except PassphraseUnavailableError:
            try:
                service.verify(backup.path, content=False)
                status = "checksum ok, content not checked (no passphrase)"
            except BackupError as exc:
                status = f"not verified: {exc}"
        except BackupError as exc:
            status = f"not verified: {exc}"
        credentials = (
            "unknown" if backup.credentials is None else ("yes" if backup.credentials else "no")
        )
        print(
            f"{backup.created_at.isoformat()}  {backup.size_bytes} bytes  "
            f"encrypted={'yes' if backup.encrypted else 'no'}  credentials={credentials}  "
            f"{status}  {backup.path}"
        )
    return 0


def _run_backup_verify(file: str) -> int:
    """Run the `backup verify` subcommand on a single archive.

    Returns:
        0 if verification passed, 1 if it failed, 2 if settings fail to load or a needed
        passphrase is unavailable.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    try:
        _backup_service(settings).verify(Path(file))
    except PassphraseUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("ok")
    return 0


def _run_backup_prune() -> int:
    """Run the `backup prune` subcommand.

    Returns:
        0 always (nothing to prune, or the newest backup failing verification, are both
        reported, not command failures), 2 if settings fail to load.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    deleted = _backup_service(settings).prune(datetime.now(UTC))
    if not deleted:
        print("nothing to prune")
    for path in deleted:
        print(f"deleted {path}")
    return 0


def _run_backup_restore(file: str, restore_credentials: bool, overwrite_credentials: bool) -> int:
    """Run the `backup restore` subcommand: restore an archive over the live database.

    Takes the data directory lock for the duration of the restore, so it never races a
    running server.

    Args:
        file: path to the backup archive.
        restore_credentials: also restore `secrets.toml` and `vault.key`.
        overwrite_credentials: replace credential files that already exist.

    Returns:
        0 on success, 1 if the data directory is already locked or restore failed, 2 if
        settings fail to load or a needed passphrase is unavailable.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    service = _backup_service(settings)
    try:
        with DataDirLock(settings.data_dir):
            result = asyncio.run(
                service.restore(
                    Path(file),
                    db_path,
                    restore_credentials=restore_credentials,
                    overwrite_credentials=overwrite_credentials,
                )
            )
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except PassphraseUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if result.previous_db is not None:
        print(f"restored; previous database moved to {result.previous_db}")
    else:
        print("restored; no previous database existed")
    if result.credentials_restored:
        print("restored secrets.toml and vault.key")
        for moved in result.previous_credentials:
            print(f"previous credentials moved to {moved}")
    elif result.credentials_available:
        print("the backup also holds credentials; pass --restore-credentials to restore them")
    return 0


async def _import_catalog(
    db_path: Path, pdf_path: Path, provider_id: str, catalog_version: str
) -> CatalogImportResult:
    services = await build_catalog_services(db_path)
    try:
        return await services.catalog.import_pdf(pdf_path, provider_id, catalog_version)
    finally:
        await services.close()


def _run_catalog_import(pdf: str, catalog_version: str | None, provider: str) -> int:
    """Run the `catalog import` subcommand: parse a dictionary PDF into `catalog_entries`.

    Takes the data directory lock for the duration of the import, so it never races a
    running server's own catalog import.

    Returns:
        0 on success, 1 if the data directory is already locked or the pre-migration
        backup failed, 2 if settings fail to load, the PDF file does not exist, or it
        cannot be parsed (oversized, too many pages, or an unrecognizable kind).
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    pdf_path = Path(pdf).expanduser()
    if not pdf_path.is_file():
        print(f"error: no such file: {pdf_path}", file=sys.stderr)
        return 2

    try:
        version = catalog_version or default_catalog_version(pdf_path.name)
    except CatalogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            result = asyncio.run(_import_catalog(db_path, pdf_path, provider, version))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1
    except CatalogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"imported {result.kind} dictionary as version {version}: "
        f"{result.new} new, {result.updated} updated, "
        f"{result.duplicate_keys_in_file} duplicate keys in file"
    )
    return 0


async def _list_catalog_versions(db_path: Path) -> list[CatalogVersionSummary]:
    services = await build_catalog_services(db_path)
    try:
        return await services.catalog.list_versions()
    finally:
        await services.close()


def _run_catalog_list() -> int:
    """Run the `catalog list` subcommand.

    Returns:
        0 always, 1 if the data directory is already locked, 2 if settings fail to load.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            versions = asyncio.run(_list_catalog_versions(db_path))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1

    if not versions:
        print("no catalog imported yet")
    for version in versions:
        print(
            f"{version.provider_id} {version.catalog_version} ({version.kind}): "
            f"{version.entry_count} entries"
        )
    return 0


def _tls_files(
    settings: Settings, selfsigned: tls_selfsigned.SelfSignedCertificate | None
) -> tuple[Path, Path] | None:
    """Return the certificate and key paths uvicorn serves with, `None` for plain HTTP."""
    if selfsigned is not None:
        return selfsigned.certfile, selfsigned.keyfile
    if settings.tls_certfile is not None and settings.tls_keyfile is not None:
        return settings.tls_certfile, settings.tls_keyfile
    return None


def _prepare_selfsigned(settings: Settings) -> tls_selfsigned.SelfSignedCertificate | None:
    """Ensure the automatic certificate exists and log which one is in use.

    Returns:
        The certificate, or `None` if the automatic certificate is not active.

    Raises:
        SelfSignedError: if the certificate cannot be generated or stored.
    """
    if not settings.tls_selfsigned_active:
        return None
    certificate = tls_selfsigned.ensure_selfsigned(settings.data_dir, settings.allowed_hosts)
    logger.info(
        "cli.tls_selfsigned",
        fingerprint_sha256=certificate.info.fingerprint,
        days_left=certificate.info.days_left,
        names=list(certificate.info.names),
        generated=certificate.replaced.value if certificate.replaced else None,
    )
    return certificate


def _hardened_ssl_context(
    _config: uvicorn.Config, default_factory: Callable[[], ssl.SSLContext]
) -> ssl.SSLContext:
    """Build uvicorn's default server context, then pin the minimum protocol to TLS 1.2.

    The Python default already is TLS 1.2, but a system-wide OpenSSL configuration can lower
    it; the explicit floor keeps the guarantee independent of the host.
    """
    return tls.enforce_minimum_tls_version(default_factory())


async def _serve(settings: Settings, db_path: Path) -> None:
    """Migrate, build the services and serve the web GUI until signalled to stop.

    With the automatic self-signed certificate, a background task re-checks it every 12
    hours and loads a renewed one into the running TLS context; it is stopped on shutdown.

    Raises:
        InsecureSecretsError: if the secrets file is group/world-accessible.
        ConfigError: if the secrets file is malformed.
        BackupError: if the pre-migration backup fails.
        SelfSignedError: if the automatic certificate cannot be generated or stored.
    """
    # Fail before touching anything if the secrets are unusable; later reads follow the file.
    load_secrets(settings.secrets_file)
    await _upgrade_with_backup(settings, db_path)
    selfsigned = await asyncio.to_thread(_prepare_selfsigned, settings)

    services: Services = await build_services(settings, db_path)
    renewal: asyncio.Task[None] | None = None
    try:
        _announce_setup_if_needed(settings, services.operator_auth)
        app_services = AppServices(
            services.db,
            services.scheduler,
            services.accounts,
            services.operator_auth,
            services.login_throttle,
        )
        await app_services.catalog.seed_bundled()
        app = create_app(app_services, settings, version=__version__)
        tls_files = _tls_files(settings, selfsigned)
        config = uvicorn.Config(
            app,
            host=settings.bind_host,
            port=settings.port,
            log_config=None,
            ssl_certfile=tls_files[0] if tls_files else None,
            ssl_keyfile=tls_files[1] if tls_files else None,
            ssl_context_factory=_hardened_ssl_context if tls_files else None,
        )
        if selfsigned is not None:
            # Loading early exposes the live context that the renewal task updates.
            config.load()
            if config.ssl is None:
                raise RuntimeError("TLS context missing after loading the server configuration")
            renewal = asyncio.create_task(
                tls_selfsigned.run_renewal(
                    config.ssl,
                    settings.data_dir,
                    settings.allowed_hosts,
                    loaded_fingerprint=selfsigned.info.fingerprint,
                ),
                name="tls-selfsigned-renewal",
            )
        await uvicorn.Server(config).serve()
    finally:
        if renewal is not None:
            renewal.cancel()
            await asyncio.wait({renewal})
        await services.close()


def _announce_setup_if_needed(settings: Settings, operator_auth: OperatorAuth) -> None:
    """Log that no password is set yet; loudly if the server is reachable from the network.

    The first password is claimed by whoever submits the setup form first, so it matters
    whether anyone but the local machine can reach it. A container counts as reachable: only
    the runtime's port mapping decides who can connect.

    Args:
        settings: the loaded settings.
        operator_auth: the operator login backend.

    Raises:
        InsecureSecretsError: if the secrets file is group/world-accessible.
        ConfigError: if the secrets file is malformed.
    """
    if operator_auth.password_is_set():
        return
    url = f"{_server_url(settings)}/login"
    if settings.container or not _is_loopback_host(settings.bind_host):
        logger.warning(
            "operator.setup_open_to_network",
            url=url,
            hint="no password is set and the server is reachable beyond this machine: "
            "anyone who can connect can set the first password and become the operator; "
            "set it now at the URL",
        )
    else:
        logger.info(
            "operator.setup_required",
            url=url,
            hint="choose a password there",
        )


def _run_healthcheck() -> int:
    """Run the `healthcheck` subcommand: probe `/healthz` of the local server.

    The target is always `127.0.0.1` on the configured port, over HTTPS if TLS is enabled.
    The certificate is not verified, since the target is fixed to the loopback address and
    a generated certificate is self-signed. Prints nothing.

    Returns:
        0 if the server answered with HTTP 200, else 1 (including unloadable settings).
    """
    try:
        settings = load_settings()
    except ConfigError:
        return 1
    # httpx logs every request at INFO; the probe must stay silent.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    scheme = "https" if settings.tls_enabled else "http"
    # The host allowlist applies to the probe too; present an allowed name.
    host_header = (
        "127.0.0.1" if "127.0.0.1" in settings.allowed_hosts else settings.allowed_hosts[0]
    )
    try:
        response = httpx.get(
            f"{scheme}://127.0.0.1:{settings.port}/healthz",
            headers={"Host": host_header},
            timeout=_HEALTHCHECK_TIMEOUT_S,
            verify=False,  # noqa: S501 - fixed loopback target
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return 1
    return 0 if response.status_code == 200 else 1


def _serve_bind_refusal(bind_host: str, container: bool, tls_enabled: bool) -> str | None:
    """Decide whether `serve` may bind to `bind_host`.

    Every page needs a login, but the password would travel in clear text over a plain-HTTP
    network bind, so a non-loopback bind requires TLS. `container` is the exception, for
    the explicit opt-out of the default HTTPS (a TLS-terminating proxy sits in front);
    `serve` warns about it at startup.

    Args:
        bind_host: the configured bind address.
        container: `Settings.container`.
        tls_enabled: `Settings.tls_enabled`.

    Returns:
        The refusal message, or `None` if binding is allowed.
    """
    if _is_loopback_host(bind_host) or container or tls_enabled:
        return None
    return (
        "non-loopback binds require TLS: configure tls_certfile and tls_keyfile, "
        "or enable tls_selfsigned"
    )


def _run_serve() -> int:
    """Run the `serve` subcommand: migrate, then serve the web GUI until signalled to stop.

    Takes the data directory lock for the whole run, so `fetch`/`backup`/`restore` never
    race a running server. Refuses to bind to a non-loopback address without TLS unless
    `settings.container` is true.

    Returns:
        0 on a clean shutdown (SIGINT/SIGTERM), 1 if the data directory is already locked
        or the pre-migration backup failed, 2 if settings/secrets fail to load, the bind
        address is refused or the TLS certificate is unusable or cannot be generated.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    if settings.container:
        logger.info(
            "cli.container_mode",
            bind_host=settings.bind_host,
            port=settings.port,
            tls=settings.tls_enabled,
        )
        if not settings.tls_enabled:
            logger.warning(
                "tls.container_plaintext",
                hint="the container serves plain HTTP: the operator password travels "
                "unencrypted unless a TLS-terminating proxy in front of it is the only "
                "way to reach this port; remove CARCHIVE_TLS_SELFSIGNED=false to serve "
                "HTTPS directly",
            )

    refusal = _serve_bind_refusal(settings.bind_host, settings.container, settings.tls_enabled)
    if refusal is not None:
        print(f"error: {refusal}", file=sys.stderr)
        return 2

    if not _preflight_tls(settings):
        return 2

    logger.info("cli.serve_starting", url=_server_url(settings))

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            asyncio.run(_serve(settings, db_path))
    except KeyboardInterrupt:
        # uvicorn shuts down gracefully on SIGINT/SIGTERM, then re-raises the signal so the
        # caller sees it was interrupted; that is this clean shutdown, not a crash.
        return 0
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError, OperatorAuthError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1
    except tls_selfsigned.SelfSignedError as exc:
        print(f"error: tls: {exc}", file=sys.stderr)
        return 2

    return 0


def _choose_brand(brands: Sequence[str]) -> str | None:
    """Print `brands` as a numbered list and ask the user to pick one.

    Args:
        brands: brand names, in the order to display and number them.

    Returns:
        The chosen brand, or ``None`` if the answer was not a number in range (the caller
        prints no further message; an error was already printed to stderr).
    """
    for index, brand in enumerate(brands, start=1):
        print(f"  {index}) {brand}")
    choice = input("Brand (number): ").strip()
    if not choice.isdigit():
        print(f"error: {choice!r} is not a number", file=sys.stderr)
        return None
    index = int(choice)
    if not (1 <= index <= len(brands)):
        print(f"error: no brand numbered {index}", file=sys.stderr)
        return None
    return brands[index - 1]


def _parse_vehicle_selection(selection: str, remote: Sequence[RemoteVehicle]) -> list[str]:
    """Parse a user's answer to "which vehicles" into VINs from `remote`.

    Accepts `"all"` (case-insensitive) or a comma-separated list of 1-based indices into
    `remote`, as printed to the user just before asking. Out-of-range or unparsable
    entries are silently skipped, since `AccountService.add_vehicles` already ignores any
    VIN the account does not actually report.

    Args:
        selection: the raw answer.
        remote: the vehicles that were offered, in the order they were numbered.

    Returns:
        The selected VINs, in no particular order.
    """
    if selection.strip().lower() == "all":
        return [vehicle.vin for vehicle in remote]
    vins = []
    for part in selection.split(","):
        part = part.strip()
        if not part.isdigit():
            continue
        index = int(part)
        if 1 <= index <= len(remote):
            vins.append(remote[index - 1].vin)
    return vins


def _print_remote_vehicles(remote: Sequence[RemoteVehicle]) -> None:
    for index, vehicle in enumerate(remote, start=1):
        label = f" {vehicle.name}" if vehicle.name else ""
        print(f"  {index}) {mask_vin(vehicle.vin)}{label}")


async def _select_and_add_vehicles(
    services: Services, account_id: UUID, remote: Sequence[RemoteVehicle]
) -> None:
    """Print `remote`, ask the user which to add, and add the selected ones.

    Does nothing (prints a note) if `remote` is empty.
    """
    if not remote:
        print("no vehicles reported for this account yet")
        return
    _print_remote_vehicles(remote)
    selection = input("Add which vehicles? (numbers, comma-separated, or 'all'): ")
    vins = _parse_vehicle_selection(selection, remote)
    added = await services.accounts.add_vehicles(account_id, vins)
    print(f"added {len(added)} vehicle(s)")


async def _account_add_flow(settings: Settings, db_path: Path) -> int:
    """Run the interactive `account add` flow against already-migrated/backed-up services."""
    services = await build_services(settings, db_path)
    try:
        brands = sorted({brand for _, brand in services.accounts.available_brands()})
        if not brands:
            print("error: no providers registered", file=sys.stderr)
            return 2
        brand = _choose_brand(brands)
        if brand is None:
            return 2
        providers = services.registry.for_brand(brand)
        if not providers:
            print(f"error: no provider serves brand {brand!r}", file=sys.stderr)
            return 2
        provider = providers[0]

        label = input("Account label: ").strip()
        user = input("Portal login: ").strip()
        password = getpass.getpass("Portal password: ")

        try:
            account_id = await services.accounts.add_account(
                provider.id, brand, label, {"user": user, "password": password}
            )
        except AccountServiceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        check = await services.accounts.test_login(account_id)
        if not check.ok:
            print(f"login test failed: {check.reason}", file=sys.stderr)
            keep = input("Keep this account anyway? [y/N]: ").strip().lower()
            if keep not in ("y", "yes"):
                await services.accounts.delete_account(label)
                print("account not saved")
                return 1
        else:
            print("login ok")

        try:
            remote = await services.accounts.remote_vehicles(account_id)
        except ProviderError as exc:
            print(f"error listing vehicles: {exc}", file=sys.stderr)
            return 0
        await _select_and_add_vehicles(services, account_id, remote)
        return 0
    finally:
        await services.close()


def _run_account_add() -> int:
    """Run the `account add` subcommand: interactively add a portal account and its vehicles.

    Nothing is saved if the login test fails, unless the user explicitly confirms keeping
    it anyway; vehicles are only ever added among the ones the account actually reports.

    Returns:
        0 on success, 1 if the data directory is already locked or the login test failed
        and was not kept, 2 on any other configuration or validation error.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            return asyncio.run(_account_add_flow(settings, db_path))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1


async def _operator_set_password_flow(settings: Settings, db_path: Path) -> int:
    """Prompt twice for a password and store it."""
    try:
        first = getpass.getpass("New operator password: ")
        second = getpass.getpass("Repeat password: ")
    except EOFError:
        print("error: no password entered", file=sys.stderr)
        return 1
    if first != second:
        print("error: passwords do not match", file=sys.stderr)
        return 1
    async with OperatorAuth.connect(db_path, settings.secrets_file) as operator_auth:
        try:
            await operator_auth.set_password(first)
        except PasswordPolicyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print("password set; all sessions revoked")
    return 0


def _run_operator_command_without_lock(
    settings: Settings, db_path: Path, locked: AlreadyRunningError
) -> int:
    """Set the operator password while a server holds the data directory lock.

    Only reached when the database is already migrated to its latest revision, so this
    never races `serve`'s own use of the database. No migration or pre-migration backup
    runs here. Writing the password hash still serializes safely against `serve`'s own
    secrets-file writes (account changes, sampler token refresh), via `secrets_file_lock`
    inside `write_operator_hash`.

    Args:
        settings: the loaded settings.
        db_path: the database file to check and connect to.
        locked: the `AlreadyRunningError` that triggered this fallback, printed if the
            database turns out not to be eligible for a lock-free write.

    Returns:
        0 on success; 1 if the database is missing or not on the latest revision, the input
        was rejected (mismatch, policy violation), or the secrets file lock timed out or
        could not be written; 2 if the secrets file or the stored login state are unusable.
    """
    if asyncio.run(current_revision(db_path)) != head_revision():
        print(f"error: {locked}", file=sys.stderr)
        return 1
    try:
        return asyncio.run(_operator_set_password_flow(settings, db_path))
    except (InsecureSecretsError, ConfigError, OperatorAuthError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except SecretsLockTimeoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc.strerror or type(exc).__name__}", file=sys.stderr)
        return 1


def _run_operator_command() -> int:
    """Run `operator set-password`, normally under the data directory lock.

    If the data directory is already locked (a running `serve`), falls back to writing the
    password hash directly, without taking the lock or running a migration, but only when
    the database is already on the latest revision; see
    `_run_operator_command_without_lock`.

    Returns:
        0 on success; 1 if the data directory is locked and the fallback is not applicable
        (or itself fails to write), the pre-migration backup failed, the input was rejected
        (mismatch, policy violation) or the secrets file could not be written; 2 if settings,
        the secrets file or the stored login state are unusable, or there is no terminal to
        prompt on.
    """
    if not sys.stdin.isatty():
        print(
            "error: set-password prompts for the password and needs an interactive terminal",
            file=sys.stderr,
        )
        return 2

    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            return asyncio.run(_operator_set_password_flow(settings, db_path))
    except AlreadyRunningError as exc:
        return _run_operator_command_without_lock(settings, db_path, exc)
    except (InsecureSecretsError, ConfigError, OperatorAuthError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1
    except SecretsLockTimeoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc.strerror or type(exc).__name__}", file=sys.stderr)
        return 1


def _upgrade_with_backup_sync(settings: Settings, db_path: Path) -> None:
    """Synchronous wrapper around `_upgrade_with_backup`.

    For callers that run more than one `asyncio.run` call under the same `DataDirLock`.
    """
    asyncio.run(_upgrade_with_backup(settings, db_path))


def _format_account_line(account: AccountInfo) -> str:
    last_run = (
        f"{account.last_run_at.isoformat()} ({account.last_run_outcome})"
        if account.last_run_at
        else "never"
    )
    reason = f" — {account.state_reason}" if account.state_reason else ""
    return f"{account.label}: {account.brand}, state {account.state}{reason}, last run {last_run}"


async def _list_accounts(settings: Settings, db_path: Path) -> list[AccountInfo]:
    services = await build_services(settings, db_path)
    try:
        return await services.accounts.list_accounts()
    finally:
        await services.close()


def _run_account_list() -> int:
    """Run the `account list` subcommand.

    Returns:
        0 always, 1 if the data directory is already locked, 2 if settings or the
        secrets file fail to load.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            accounts = asyncio.run(_list_accounts(settings, db_path))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not accounts:
        print("no accounts yet")
    for account in accounts:
        print(_format_account_line(account))
    return 0


async def _preview_account_removal(
    settings: Settings, db_path: Path, label: str
) -> tuple[AccountInfo | None, list[VehicleInfo]]:
    services = await build_services(settings, db_path)
    try:
        accounts = await services.accounts.list_accounts()
        account = next((a for a in accounts if a.label == label), None)
        if account is None:
            return None, []
        vehicles = [v for v in await services.accounts.list_vehicles() if v.account_label == label]
        return account, vehicles
    finally:
        await services.close()


async def _apply_account_removal(settings: Settings, db_path: Path, label: str) -> DeletionResult:
    # No secrets are loaded: removing an account must work even if the vault key is lost.
    services = await build_services(settings, db_path)
    try:
        return await services.accounts.delete_account(label)
    finally:
        await services.close()


def _print_deletion_result(result: DeletionResult) -> None:
    if result.oldest_backup_age is not None:
        print(
            "deleted; the oldest remaining backup is "
            f"{result.oldest_backup_age} old and may still contain this data until it "
            "ages out of retention"
        )
    else:
        print("deleted; no backups exist yet")


def _run_account_remove(label: str, yes: bool) -> int:
    """Run the `account remove` subcommand.

    Without `--yes`, only prints what would be deleted; with it, actually deletes the
    account, every one of its vehicles and all their data, and its stored credentials.

    Returns:
        0 on success (including a dry preview), 1 if the data directory is already
        locked, 2 if settings/secrets fail to load or no account with `label` exists.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            if not yes:
                account, vehicles = asyncio.run(_preview_account_removal(settings, db_path, label))
                if account is None:
                    print(f"error: no account labelled {label!r}", file=sys.stderr)
                    return 2
                print(
                    f"would remove account '{label}' with {len(vehicles)} vehicle(s) "
                    "and all their data; re-run with --yes to actually delete"
                )
                return 0

            result = asyncio.run(_apply_account_removal(settings, db_path, label))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except AccountServiceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1

    _print_deletion_result(result)
    return 0


def _prompt_new_password(label: str) -> str | None:
    """Prompt twice, without echo, for an account's new portal password.

    Returns:
        The password, or `None` if input ended or the two entries differ (already reported).
    """
    try:
        first = getpass.getpass(f"New portal password for '{label}': ")
        second = getpass.getpass("Repeat password: ")
    except EOFError:
        print("error: no password entered", file=sys.stderr)
        return None
    if first != second:
        print("error: passwords do not match", file=sys.stderr)
        return None
    return first


async def _account_set_password_flow(settings: Settings, db_path: Path, label: str | None) -> int:
    """Prompt for new portal passwords and store them if the portal accepts them.

    The secrets file is deliberately not loaded up front: the stored passwords may be
    unreadable (lost vault key), which is exactly the case this command repairs. Without a
    label, every account whose password is unreadable is prompted in turn and all new
    passwords are written together, so the file never changes if the run is aborted.
    """
    services = await build_services(settings, db_path)
    try:
        if label is None:
            return await _recover_unreadable_passwords(services)
        try:
            await services.accounts.check_password_replaceable(label)
        except AccountServiceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        first = _prompt_new_password(label)
        if first is None:
            return 1
        try:
            await services.accounts.set_password(label, first)
        except LoginRejectedError as exc:
            print(f"error: {exc}; nothing was changed", file=sys.stderr)
            return 1
        except AccountServiceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    finally:
        await services.close()
    print(f"password for '{label}' replaced; the account and its data are unchanged")
    return 0


async def _recover_unreadable_passwords(services: Services) -> int:
    labels = await services.accounts.unreadable_password_labels()
    if not labels:
        print(
            "error: no stored password is unreadable; name the account whose password to "
            "replace: carchive account set-password <label>",
            file=sys.stderr,
        )
        return 2
    print(
        f"{len(labels)} account(s) have an unreadable password ({', '.join(labels)}); "
        "each needs a new one. Nothing is written until all of them are accepted."
    )
    collected: dict[str, str] = {}
    for current in labels:
        password = _prompt_new_password(current)
        if password is None:
            return 1
        try:
            await services.accounts.check_new_password(current, password)
        except LoginRejectedError as exc:
            print(f"error: {current!r}: {exc}; nothing was changed", file=sys.stderr)
            return 1
        except AccountServiceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        collected[current] = password
    try:
        await services.accounts.set_passwords(collected)
    except AccountServiceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"replaced the passwords of {len(collected)} account(s); "
        "the accounts and their data are unchanged"
    )
    return 0


def _run_account_set_password(label: str | None) -> int:
    """Run the `account set-password` subcommand.

    Args:
        label: the account to change, or `None` to replace every unreadable password.

    Returns:
        0 on success; 1 if the data directory is already locked, the pre-migration backup
        failed, the input did not match or the portal rejected the login; 2 if there is no
        terminal to prompt on, the account is unknown or has no stored credentials, or the
        settings, secrets file or vault key are unusable.
    """
    if not sys.stdin.isatty():
        print(
            "error: set-password prompts for the password and needs an interactive terminal",
            file=sys.stderr,
        )
        return 2

    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            return asyncio.run(_account_set_password_flow(settings, db_path, label))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1


async def _vehicle_sync_flow(settings: Settings, db_path: Path, label: str) -> int:
    services = await build_services(settings, db_path)
    try:
        account = await services.accounts.get_account_by_label(label)
        if account is None:
            print(f"error: no account labelled {label!r}", file=sys.stderr)
            return 2
        try:
            remote = await services.accounts.remote_vehicles(account.id)
        except ProviderError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        existing_vins = {
            v.vin for v in await services.accounts.list_vehicles() if v.account_label == label
        }
        new_remote = [v for v in remote if v.vin not in existing_vins]
        if not new_remote:
            print("no new vehicles reported")
            return 0
        await _select_and_add_vehicles(services, account.id, new_remote)
        return 0
    finally:
        await services.close()


def _run_vehicle_sync(label: str) -> int:
    """Run the `vehicle sync` subcommand: offer any vehicle an account newly reports.

    Returns:
        0 on success, 1 if the data directory is already locked or the login failed,
        2 if settings/secrets fail to load or no account with `label` exists.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            return asyncio.run(_vehicle_sync_flow(settings, db_path, label))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1


def _format_vehicle_line(vehicle: VehicleInfo) -> str:
    last_run = (
        f"{vehicle.last_run_at.isoformat()} ({vehicle.last_run_outcome})"
        if vehicle.last_run_at
        else "never"
    )
    status = "archived" if vehicle.archived else "active"
    short_id = str(vehicle.id)[:8]
    return (
        f"{short_id}  {vehicle.label}  {mask_vin(vehicle.vin)}  account {vehicle.account_label}  "
        f"{status}, last run {last_run}"
    )


async def _list_vehicles(settings: Settings, db_path: Path) -> list[VehicleInfo]:
    services = await build_services(settings, db_path)
    try:
        return await services.accounts.list_vehicles()
    finally:
        await services.close()


def _run_vehicle_list() -> int:
    """Run the `vehicle list` subcommand.

    Returns:
        0 always, 1 if the data directory is already locked, 2 if settings or the
        secrets file fail to load.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            vehicles = asyncio.run(_list_vehicles(settings, db_path))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not vehicles:
        print("no vehicles yet")
    for vehicle in vehicles:
        print(_format_vehicle_line(vehicle))
    return 0


async def _match_vehicle_prefix(
    settings: Settings, db_path: Path, prefix: str
) -> list[VehicleInfo]:
    services = await build_services(settings, db_path)
    try:
        vehicles = await services.accounts.list_vehicles()
    finally:
        await services.close()
    return [v for v in vehicles if str(v.id).startswith(prefix)]


async def _apply_vehicle_removal(
    settings: Settings, db_path: Path, vehicle_id: UUID
) -> DeletionResult:
    services = await build_services(settings, db_path)
    try:
        return await services.accounts.delete_vehicle(vehicle_id)
    finally:
        await services.close()


def _run_vehicle_remove(id_prefix: str, yes: bool) -> int:
    """Run the `vehicle remove` subcommand.

    Without `--yes`, only prints what would be deleted; with it, actually deletes the
    vehicle and all its data.

    Returns:
        0 on success (including a dry preview), 1 if the data directory is already
        locked, 2 if settings/secrets fail to load or `id_prefix` does not match exactly
        one vehicle.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            matches = asyncio.run(_match_vehicle_prefix(settings, db_path, id_prefix))
            if not matches:
                print(f"error: no vehicle id starts with {id_prefix!r}", file=sys.stderr)
                return 2
            if len(matches) > 1:
                print(
                    f"error: {id_prefix!r} matches {len(matches)} vehicles, use a longer prefix",
                    file=sys.stderr,
                )
                return 2
            vehicle = matches[0]

            if not yes:
                print(
                    f"would remove vehicle '{vehicle.label}' ({mask_vin(vehicle.vin)}) and "
                    "all its data; re-run with --yes to actually delete"
                )
                return 0

            result = asyncio.run(_apply_vehicle_removal(settings, db_path, vehicle.id))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1

    _print_deletion_result(result)
    return 0


async def _fetch_flow(
    settings: Settings, db_path: Path, account_label: str | None, now: bool
) -> bool | None:
    """Run one collection pass.

    Returns:
        Whether every processed request succeeded, or `None` if `account_label` names an
        unknown account (nothing was run).
    """
    load_secrets(settings.secrets_file)
    services = await build_services(settings, db_path)
    try:
        accounts = await services.accounts.list_accounts()
        label_by_id = {account.id: account.label for account in accounts}

        if account_label is not None:
            match = next((a for a in accounts if a.label == account_label), None)
            if match is None:
                print(f"error: no account labelled {account_label!r}", file=sys.stderr)
                return None
            account_ids = [match.id]
        elif now:
            account_ids = list(label_by_id)
        else:
            account_ids = await services.accounts.due_account_ids()

        if not account_ids:
            print("no accounts due")
            return True

        all_ok = True
        for account_id in account_ids:
            label = label_by_id.get(account_id, str(account_id))
            result = await services.collector.run_account(account_id)
            if result.login_outcome != "ok":
                print(f"account '{label}': login failed")
                all_ok = False
                continue
            if not result.request_results:
                print(f"account '{label}': nothing due")
            for request_result in result.request_results:
                description = await services.accounts.describe_request(
                    request_result.data_request_id
                )
                vin = mask_vin(description.vin) if description else "?"
                kind = description.kind if description else "?"
                print(
                    f"account '{label}' {kind} {vin}: {request_result.outcome}, "
                    f"downloaded {request_result.downloaded}"
                )
                if request_result.outcome != "ok":
                    all_ok = False
        return all_ok
    finally:
        await services.close()


def _run_fetch(account_label: str | None, now: bool) -> int:
    """Run the `fetch` subcommand: one collector pass outside the scheduler loop.

    Without `--account`/`--now`, only accounts with collection work currently due are
    run; `--now` runs every account regardless of due time; `--account` restricts to one
    account's label (combinable with `--now`).

    Returns:
        0 if every processed request succeeded, 1 if any failed or the data directory is
        already locked, 2 if settings/secrets fail to load or `--account` names an
        unknown label.
    """
    settings = _load_settings_or_print_error()
    if settings is None:
        return 2

    db_path = settings.data_dir / _DB_FILENAME
    try:
        with DataDirLock(settings.data_dir):
            _upgrade_with_backup_sync(settings, db_path)
            all_ok = asyncio.run(_fetch_flow(settings, db_path, account_label, now))
    except AlreadyRunningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (InsecureSecretsError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"error: pre-migration backup failed: {exc}", file=sys.stderr)
        return 1

    if all_ok is None:
        return 2
    return 0 if all_ok else 1


def _service_failure(exc: user_service.UserServiceError) -> int:
    """Report a failed `service` subcommand on stderr.

    Args:
        exc: the failure.

    Returns:
        2 if the host cannot run a systemd user service at all, else 1.
    """
    print(f"error: {exc}", file=sys.stderr)
    return 2 if isinstance(exc, user_service.UnsupportedEnvironmentError) else 1


def _run_service_install(no_start: bool) -> int:
    """Run the `service install` subcommand.

    Args:
        no_start: enable the unit but do not start it.

    Returns:
        0 on success (a failed lingering activation is only a warning), 1 if a step
        failed, 2 if this host cannot run a systemd user service.
    """

    def warn(message: str) -> None:
        print(message, file=sys.stderr)

    try:
        user_service.install(start=not no_start, out=print, err=warn)
    except user_service.UserServiceError as exc:
        return _service_failure(exc)
    return 0


def _run_service_uninstall() -> int:
    """Run the `service uninstall` subcommand.

    Returns:
        0 on success or if nothing was installed, 1 if a step failed, 2 if this host
        cannot run a systemd user service.
    """
    try:
        user_service.uninstall(out=print)
    except user_service.UserServiceError as exc:
        return _service_failure(exc)
    return 0


def _run_service_status() -> int:
    """Run the `service status` subcommand.

    Returns:
        0 if the service is running and lingering is on, 1 if either is missing, 2 if
        this host cannot run a systemd user service.
    """
    url: str | None = None
    try:
        settings = load_settings()
        url = _server_url(settings)
    except ConfigError:
        pass  # the URL line is optional; a broken config is reported by `check`
    try:
        report = user_service.status(url=url)
    except user_service.UserServiceError as exc:
        return _service_failure(exc)
    for line in report.render():
        print(line)
    problems = report.problems
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    """Run the Carchive CLI.

    Args:
        argv: command-line arguments, excluding the program name. Defaults to
            `sys.argv[1:]` when None.

    Returns:
        The process exit code.
    """
    # Applies to every file this process creates (database, WAL/SHM, lock, backups),
    # so secrets and vehicle data never land in a world- or group-readable file even for a
    # moment, regardless of which library created it.
    os.umask(0o077)

    parser = _build_parser()
    args = parser.parse_args(argv)

    configure_logging(verbose=args.verbose, fmt=args.log_format)

    if args.command == "version":
        print(__version__)
        return 0

    if args.command == "check":
        return _run_check()

    if args.command == "serve":
        return _run_serve()

    if args.command == "healthcheck":
        return _run_healthcheck()

    if args.command == "parse-pending":
        return _run_parse_pending()

    if args.command == "import-sampler":
        if args.verify:
            return _run_verify_sampler(args.config, args.sampler_data_dir)
        return _run_import_sampler(args.config, args.sampler_data_dir, args.apply, args.no_parse)

    if args.command == "db":
        if args.db_command == "upgrade":
            return _run_db_upgrade()
        if args.db_command == "status":
            return _run_db_status()
        parser.error("db requires a subcommand: upgrade or status")
        return 2

    if args.command == "backup":
        if args.backup_command == "create":
            return _run_backup_create(
                args.include_credentials, args.encrypt, args.allow_plaintext_credentials
            )
        if args.backup_command == "list":
            return _run_backup_list()
        if args.backup_command == "verify":
            return _run_backup_verify(args.file)
        if args.backup_command == "prune":
            return _run_backup_prune()
        if args.backup_command == "restore":
            if args.overwrite_credentials and not args.restore_credentials:
                parser.error("--overwrite-credentials requires --restore-credentials")
            return _run_backup_restore(
                args.file, args.restore_credentials, args.overwrite_credentials
            )
        parser.error("backup requires a subcommand: create, list, verify, prune or restore")
        return 2

    if args.command == "catalog":
        if args.catalog_command == "import":
            return _run_catalog_import(args.pdf, args.catalog_version, args.provider)
        if args.catalog_command == "list":
            return _run_catalog_list()
        parser.error("catalog requires a subcommand: import or list")
        return 2

    if args.command == "account":
        if args.account_command == "add":
            return _run_account_add()
        if args.account_command == "list":
            return _run_account_list()
        if args.account_command == "remove":
            return _run_account_remove(args.label, args.yes)
        if args.account_command == "set-password":
            return _run_account_set_password(args.label)
        parser.error("account requires a subcommand: add, list, remove or set-password")
        return 2

    if args.command == "operator":
        if args.operator_command == "set-password":
            return _run_operator_command()
        parser.error("operator requires a subcommand: set-password")
        return 2

    if args.command == "vehicle":
        if args.vehicle_command == "sync":
            return _run_vehicle_sync(args.label)
        if args.vehicle_command == "list":
            return _run_vehicle_list()
        if args.vehicle_command == "remove":
            return _run_vehicle_remove(args.id_prefix, args.yes)
        parser.error("vehicle requires a subcommand: sync, list or remove")
        return 2

    if args.command == "service":
        if args.service_command == "install":
            return _run_service_install(args.no_start)
        if args.service_command == "uninstall":
            return _run_service_uninstall()
        if args.service_command == "status":
            return _run_service_status()
        parser.error("service requires a subcommand: install, uninstall or status")
        return 2

    if args.command == "fetch":
        return _run_fetch(args.account, args.now)

    if args.command is None:
        parser.print_help()
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2
