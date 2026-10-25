"""`/backups`: list, create, check and download backups.

Restoring is deliberately not offered here: it replaces the live database and needs the
server stopped, so it stays a command-line operation. A backup is addressed only by the
file name of an entry of the service's own listing, never by a path from the request.

The passphrase typed into a form is registered for redaction on receipt and is never
rendered, redirected, logged or put into a message; outcomes are shown as stable message
keys.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates
from starlette.datastructures import FormData
from starlette.responses import FileResponse, Response

from carchive.config import Settings
from carchive.core.redact import redact, register_secret
from carchive.services.app_services import AppServices
from carchive.services.backup import (
    MIN_PASSPHRASE_CHARS,
    BackupError,
    BackupFile,
    BackupService,
    PassphraseProvider,
    PassphraseUnavailableError,
)

router = APIRouter()
logger = structlog.get_logger(__name__)

# Rejected rather than truncated: a silently shortened passphrase would lock the owner out.
_MAX_PASSPHRASE_CHARS = 1024
_SIZE_UNITS = ("B", "KiB", "MiB", "GiB")


@dataclass(frozen=True, slots=True)
class _Row:
    """One listed backup, prepared for the template."""

    name: str
    created_at: datetime
    size_label: str
    encrypted: bool
    credentials: bool | None
    checksum_ok: bool


def _size_label(size_bytes: int) -> str:
    value = float(size_bytes)
    for unit in _SIZE_UNITS[:-1]:
        if value < 1024:
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} {_SIZE_UNITS[-1]}"


def _load_rows(service: BackupService) -> list[_Row]:
    """List the backups with a checksum check each (blocking).

    The content is not checked: that needs the passphrase of an encrypted archive and
    decompresses everything, so it is left to the per-backup action.
    """
    rows: list[_Row] = []
    for backup in service.list_backups():
        try:
            service.verify(backup.path, content=False)
            checksum_ok = True
        except BackupError:
            checksum_ok = False
        rows.append(
            _Row(
                backup.path.name,
                backup.created_at,
                _size_label(backup.size_bytes),
                backup.encrypted,
                backup.credentials,
                checksum_ok,
            )
        )
    return rows


def _service(request: Request) -> BackupService:
    """Return the configured backup service.

    Raises:
        HTTPException: 404 if this application was built without backups.
    """
    services: AppServices = request.app.state.services
    service = services.accounts.backup
    if service is None:
        raise HTTPException(status_code=404)
    return service


async def _find(service: BackupService, name: str) -> BackupFile:
    """Return the listed backup called `name`.

    Raises:
        HTTPException: 404 if no backup in the listing has exactly that file name.
    """
    for backup in await asyncio.to_thread(service.list_backups):
        if backup.path.name == name:
            return backup
    raise HTTPException(status_code=404)


def _text(form: FormData, name: str) -> str:
    value = form.get(name, "")
    return value[: _MAX_PASSPHRASE_CHARS + 1] if isinstance(value, str) else ""


def _fixed(passphrase: str) -> PassphraseProvider:
    def provide() -> str:
        return passphrase

    return provide


def _passphrase_field(form: FormData, name: str) -> str:
    """Read a passphrase field and register it for redaction at once."""
    value = _text(form, name)
    register_secret(value)
    return value


async def _backups_page(
    request: Request,
    *,
    status_code: int = 200,
    create_message: str | None = None,
    create_name: str | None = None,
    verify_name: str | None = None,
    verify_message: str | None = None,
    include_credentials: bool | None = None,
    encrypt: bool | None = None,
    allow_plaintext_credentials: bool = False,
) -> Response:
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    settings: Settings = request.app.state.settings
    service = _service(request)
    context = {
        "backups": await asyncio.to_thread(_load_rows, service),
        "vehicle_count": await services.vehicle_count(),
        "passphrase_file_configured": settings.backup_passphrase_file is not None,
        "include_credentials": (
            settings.backup_include_credentials
            if include_credentials is None
            else include_credentials
        ),
        "encrypt": settings.backup_encrypt if encrypt is None else encrypt,
        # Deliberately not pre-filled from settings: the plaintext exception is a
        # per-request decision, off by default every time the form is shown.
        "allow_plaintext_credentials": allow_plaintext_credentials,
        "min_passphrase_length": MIN_PASSPHRASE_CHARS,
        "max_passphrase_length": _MAX_PASSPHRASE_CHARS,
        "create_message": create_message,
        "create_name": create_name,
        "verify_name": verify_name,
        "verify_message": verify_message,
    }
    return templates.TemplateResponse(request, "backups.html", context, status_code=status_code)


@router.get("/backups")
async def backups_overview(request: Request) -> Response:
    """List the backups and offer to create one."""
    return await _backups_page(request)


@router.post("/backups")
async def create_backup(request: Request) -> Response:
    """Create a backup, verify it and show the outcome as a stable message key.

    Credentials are only accepted together with encryption. The passphrase comes from the
    form (entered twice) unless `backup_passphrase_file` is configured, in which case any
    submitted passphrase is ignored. Only one backup operation runs at a time.

    Returns:
        The backups page with the outcome in `create_message`.
    """
    settings: Settings = request.app.state.settings
    service = _service(request)
    form = await request.form()
    include_credentials = form.get("include_credentials") is not None
    encrypt = form.get("encrypt") is not None
    allow_plaintext_credentials = form.get("allow_plaintext_credentials") is not None
    passphrase = _passphrase_field(form, "passphrase")
    repeat = _passphrase_field(form, "repeat")

    async def outcome(status_code: int, message: str, name: str | None = None) -> Response:
        return await _backups_page(
            request,
            status_code=status_code,
            create_message=message,
            create_name=name,
            include_credentials=include_credentials,
            encrypt=encrypt,
            allow_plaintext_credentials=allow_plaintext_credentials,
        )

    if include_credentials and not encrypt and not allow_plaintext_credentials:
        return await outcome(400, "credentials_unencrypted")
    provider: PassphraseProvider | None = None
    if encrypt and settings.backup_passphrase_file is None:
        if not passphrase:
            return await outcome(400, "passphrase_required")
        if len(passphrase) > _MAX_PASSPHRASE_CHARS:
            return await outcome(400, "too_long")
        if passphrase != repeat:
            return await outcome(400, "mismatch")
        if len(passphrase) < MIN_PASSPHRASE_CHARS:
            return await outcome(400, "too_short")
        provider = _fixed(passphrase)

    lock: asyncio.Lock = request.app.state.backup_lock
    if lock.locked():
        return await outcome(409, "busy")
    async with lock:
        derived = service.derive(
            include_credentials=include_credentials,
            encrypt=encrypt,
            allow_plaintext_credentials=allow_plaintext_credentials,
            passphrase=provider,
        )
        try:
            path = await derived.create()
        except PassphraseUnavailableError as exc:
            logger.error("backup.web_passphrase_unavailable", error=redact(str(exc)))
            return await outcome(400, "passphrase_unavailable")
        except BackupError as exc:
            logger.error("backup.web_create_failed", error=redact(str(exc)))
            return await outcome(500, "failed")
        try:
            await asyncio.to_thread(derived.verify, path)
        except BackupError as exc:
            logger.error("backup.web_verify_failed", name=path.name, error=redact(str(exc)))
            return await outcome(500, "verify_failed", path.name)
    logger.info("backup.web_created", name=path.name)
    return await outcome(200, "created", path.name)


def _verify_blocking(service: BackupService, backup: BackupFile) -> str:
    """Check a backup (blocking) and return the outcome key."""
    try:
        service.verify(backup.path, content=False)
    except BackupError:
        return "checksum_failed"
    try:
        service.verify(backup.path)
    except PassphraseUnavailableError:
        return "passphrase_unavailable"
    except BackupError:
        return "content_failed"
    return "verified"


@router.post("/backups/{name}/verify")
async def verify_backup(request: Request, name: str) -> Response:
    """Check a listed backup's checksum and, with the passphrase if needed, its content.

    Returns:
        The backups page with the outcome in `verify_message`.

    Raises:
        HTTPException: 404 if `name` is not in the listing.
    """
    settings: Settings = request.app.state.settings
    service = _service(request)
    backup = await _find(service, name)
    form = await request.form()
    passphrase = _passphrase_field(form, "passphrase")

    async def outcome(status_code: int, message: str) -> Response:
        return await _backups_page(
            request, status_code=status_code, verify_name=name, verify_message=message
        )

    provider: PassphraseProvider | None = None
    if backup.encrypted and settings.backup_passphrase_file is None:
        if not passphrase:
            return await outcome(400, "passphrase_required")
        if len(passphrase) > _MAX_PASSPHRASE_CHARS:
            return await outcome(400, "too_long")
        provider = _fixed(passphrase)

    lock: asyncio.Lock = request.app.state.backup_lock
    if lock.locked():
        return await outcome(409, "busy")
    async with lock:
        key = await asyncio.to_thread(_verify_blocking, service.derive(passphrase=provider), backup)
    logger.info("backup.web_verified", name=name, outcome=key)
    return await outcome(200 if key == "verified" else 400, key)


@router.get("/backups/download/{name}")
async def download_backup(request: Request, name: str) -> Response:
    """Stream a listed backup as a file download.

    Returns:
        The archive with an attachment disposition.

    Raises:
        HTTPException: 404 if `name` is not in the listing, or the entry is a symlink.
    """
    backup = await _find(_service(request), name)
    if backup.path.is_symlink():
        raise HTTPException(status_code=404)
    return FileResponse(
        backup.path,
        media_type="application/octet-stream",
        filename=backup.path.name,
        headers={"Cache-Control": "no-store"},
    )
