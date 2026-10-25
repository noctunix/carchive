"""Tests for the `/backups` page: listing, creating, checking and downloading backups."""

from __future__ import annotations

import itertools
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from structlog.testing import capture_logs

from carchive.config import Settings
from carchive.core.provider import ProviderRegistry
from carchive.services import backup as backup_module
from carchive.services.accounts import AccountService
from carchive.services.backup import BackupOptions, BackupService
from carchive.storage.db import Database
from carchive.web.app import create_app
from tests.web.conftest import FakeScheduler, build_services

_ORIGIN = {"Origin": "http://localhost"}
_PASSPHRASE = "web-test passphrase 7f3a"
_SECRETS = b'[credentials.main]\nuser = "user@example.org"\npassword = "enc:v2:abcdef"\n'
_START = datetime(2026, 10, 22, 3, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _cheap_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup_module, "DEFAULT_TIME_COST", 1)
    monkeypatch.setattr(backup_module, "DEFAULT_MEMORY_COST", 64)
    monkeypatch.setattr(backup_module, "DEFAULT_PARALLELISM", 1)


def _ticking_clock() -> Callable[[], datetime]:
    """A clock advancing one minute per call, so each backup gets its own file name."""
    ticks = itertools.count()
    return lambda: _START + timedelta(minutes=next(ticks))


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)


def _make_settings(
    tmp_path: Path,
    *,
    encrypt: bool = False,
    include_credentials: bool = False,
    allow_plaintext_credentials: bool = False,
    passphrase_file: Path | None = None,
) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_file=tmp_path / "cfg" / "secrets.toml",
        backup_encrypt=encrypt,
        backup_include_credentials=include_credentials,
        backup_allow_plaintext_credentials=allow_plaintext_credentials,
        backup_passphrase_file=passphrase_file,
    )


def _make_credentials(settings: Settings) -> None:
    _write_private(settings.secrets_file, _SECRETS)
    _write_private(settings.secrets_file.parent / "vault.key", bytes(range(32)))


def _make_service(db: Database, tmp_path: Path, settings: Settings) -> BackupService:
    return BackupService(
        tmp_path / "carchive.sqlite3",
        settings.effective_backup_dir,
        db,
        clock=_ticking_clock(),
        options=BackupOptions(secrets_path=settings.secrets_file),
    )


def _make_app(db: Database, settings: Settings, service: BackupService | None) -> FastAPI:
    accounts = AccountService(db, ProviderRegistry(), settings, backup=service)
    return create_app(build_services(db, FakeScheduler(), accounts), settings)


def _client(app: FastAPI, *, signed_in: bool = True) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    if signed_in:
        return httpx.AsyncClient(transport=transport, base_url="http://localhost")
    return httpx.AsyncClient(transport=transport, base_url="http://localhost", cookies={})


async def _post(
    client: httpx.AsyncClient, path: str, data: dict[str, str] | None = None
) -> httpx.Response:
    await client.get("/backups")
    form = {"csrf_token": client.cookies.get("csrf_token") or "", **(data or {})}
    return await client.post(path, data=form, headers=_ORIGIN)


def _names(page: str) -> list[str]:
    return re.findall(r'href="/backups/download/([^"]+)"', page)


def _create_form(**fields: str) -> dict[str, str]:
    return fields


async def test_backups_page_requires_a_session(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app, signed_in=False) as client:
        response = await client.get("/backups")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_backups_post_requires_a_session(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app, signed_in=False) as client:
        response = await client.post("/backups", data={}, headers=_ORIGIN)

    assert response.status_code in (401, 403)
    assert not settings.effective_backup_dir.exists()


async def test_backups_empty_list_and_navigation(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        response = await client.get("/backups")

    assert response.status_code == 200
    assert "No backups yet." in response.text
    assert 'href="/backups"' in response.text
    assert "carchive backup restore" in response.text


async def test_backups_not_available_without_a_backup_service(db: Database, tmp_path: Path) -> None:
    app = _make_app(db, _make_settings(tmp_path), None)

    async with _client(app) as client:
        response = await client.get("/backups")

    assert response.status_code == 404


async def test_create_unencrypted_backup_and_list_it(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        created = await _post(client, "/backups")
        listing = await client.get("/backups")

    assert created.status_code == 200
    assert "Backup created: carchive-20261022T030000000000Z.sqlite3.gz" in created.text
    names = _names(listing.text)
    assert names == ["carchive-20261022T030000000000Z.sqlite3.gz"]
    assert (settings.effective_backup_dir / names[0]).is_file()
    assert 'status-badge-positive">ok</span>' in listing.text
    assert 'status-badge-negative">no</span>' in listing.text


async def test_create_encrypted_backup_with_passphrase(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    service = _make_service(db, tmp_path, settings)
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        created = await _post(
            client,
            "/backups",
            _create_form(encrypt="on", passphrase=_PASSPHRASE, repeat=_PASSPHRASE),
        )
        listing = await client.get("/backups")

    assert created.status_code == 200
    assert "Backup created: carchive-20261022T030000000000Z.sqlite3.gz.enc" in created.text
    assert _names(listing.text) == ["carchive-20261022T030000000000Z.sqlite3.gz.enc"]
    assert 'status-badge-positive">yes</span>' in listing.text
    assert 'status-badge-unknown">unknown</span>' in listing.text
    [backup] = service.list_backups()
    assert backup.encrypted
    service.derive(passphrase=lambda: _PASSPHRASE).verify(backup.path)


@pytest.mark.parametrize(
    ("passphrase", "repeat", "message"),
    [
        (_PASSPHRASE, _PASSPHRASE + "x", "The passphrases do not match."),
        ("short", "short", "at least 16 characters"),
        ("", "", "Enter a passphrase to encrypt the backup."),
        ("p" * 2000, "p" * 2000, "at most 1024 characters"),
    ],
)
async def test_create_encrypted_rejects_bad_passphrase(
    db: Database, tmp_path: Path, passphrase: str, repeat: str, message: str
) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        response = await _post(
            client, "/backups", _create_form(encrypt="on", passphrase=passphrase, repeat=repeat)
        )

    assert response.status_code == 400
    assert message in response.text
    assert passphrase not in response.text or passphrase == ""
    assert not list(settings.effective_backup_dir.glob("carchive-*"))


async def test_credentials_without_encryption_are_rejected(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path, allow_plaintext_credentials=True)
    _make_credentials(settings)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        response = await _post(client, "/backups", _create_form(include_credentials="on"))

    assert response.status_code == 400
    assert "only be included in an encrypted backup" in response.text
    assert not list(settings.effective_backup_dir.glob("carchive-*"))


async def test_plaintext_credentials_checkbox_allows_an_unencrypted_backup(
    db: Database, tmp_path: Path
) -> None:
    settings = _make_settings(tmp_path)
    _make_credentials(settings)
    service = _make_service(db, tmp_path, settings)
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        response = await _post(
            client,
            "/backups",
            _create_form(include_credentials="on", allow_plaintext_credentials="on"),
        )

    assert response.status_code == 200
    assert "Backup created: carchive-20261022T030000000000Z.tar.gz" in response.text
    [backup] = service.list_backups()
    assert backup.encrypted is False
    assert backup.credentials is True


async def test_plaintext_credentials_checkbox_off_by_default_is_still_rejected(
    db: Database, tmp_path: Path
) -> None:
    settings = _make_settings(tmp_path)
    _make_credentials(settings)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        response = await _post(client, "/backups", _create_form(include_credentials="on"))

    assert response.status_code == 400
    assert "only be included in an encrypted backup" in response.text
    assert not list(settings.effective_backup_dir.glob("carchive-*"))


async def test_encrypted_backup_with_credentials(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    _make_credentials(settings)
    service = _make_service(db, tmp_path, settings)
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        response = await _post(
            client,
            "/backups",
            _create_form(
                include_credentials="on", encrypt="on", passphrase=_PASSPHRASE, repeat=_PASSPHRASE
            ),
        )

    assert response.status_code == 200
    assert "Backup created: carchive-20261022T030000000000Z.tar.gz.enc" in response.text


async def test_missing_credential_files_report_a_stable_failure(
    db: Database, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))
    caplog.set_level(logging.DEBUG, logger="carchive")

    async with _client(app) as client:
        response = await _post(
            client,
            "/backups",
            _create_form(
                include_credentials="on", encrypt="on", passphrase=_PASSPHRASE, repeat=_PASSPHRASE
            ),
        )

    assert response.status_code == 500
    notices = re.findall(r'<p class="notice-error">(.*?)</p>', response.text)
    assert notices == ["The backup could not be created. See the server log."]
    assert not list(settings.effective_backup_dir.glob("carchive-*"))
    assert _PASSPHRASE not in caplog.text


async def test_form_defaults_come_from_the_settings(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path, encrypt=True, include_credentials=True)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        response = await client.get("/backups")

    assert re.search(r'name="encrypt"\s+checked', response.text)
    assert re.search(r'name="include_credentials"\s+checked', response.text)
    assert 'name="passphrase"' in response.text
    assert "value=" not in response.text.split('name="passphrase"')[1].split(">")[0]


async def test_passphrase_file_replaces_the_form_fields(db: Database, tmp_path: Path) -> None:
    passphrase_file = tmp_path / "pass.txt"
    _write_private(passphrase_file, b"file based passphrase\n")
    settings = _make_settings(tmp_path, passphrase_file=passphrase_file)
    service = BackupService(
        tmp_path / "carchive.sqlite3",
        settings.effective_backup_dir,
        db,
        clock=_ticking_clock(),
        options=backup_module.options_from_settings(settings),
    )
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        page = await client.get("/backups")
        created = await _post(
            client, "/backups", _create_form(encrypt="on", passphrase="ignored passphrase")
        )

    assert 'name="passphrase"' not in page.text
    assert created.status_code == 200
    [backup] = service.list_backups()
    assert backup.encrypted
    service.verify(backup.path)


async def test_unreadable_passphrase_file_is_a_stable_failure(db: Database, tmp_path: Path) -> None:
    passphrase_file = tmp_path / "missing.txt"
    settings = _make_settings(tmp_path, passphrase_file=passphrase_file)
    service = BackupService(
        tmp_path / "carchive.sqlite3",
        settings.effective_backup_dir,
        db,
        options=backup_module.options_from_settings(settings),
    )
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        response = await _post(client, "/backups", _create_form(encrypt="on"))

    assert response.status_code == 400
    assert "configured passphrase file cannot be used" in response.text
    assert str(passphrase_file) not in response.text


async def test_download_streams_only_listed_files(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))
    backup_dir = settings.effective_backup_dir

    async with _client(app) as client:
        await _post(client, "/backups")
        [name] = _names((await client.get("/backups")).text)
        (backup_dir / "notes.txt").write_text("not a backup")
        (tmp_path / "outside.bin").write_bytes(b"outside")
        (backup_dir / "carchive-20200101T000000Z.sqlite3.gz").symlink_to(tmp_path / "outside.bin")

        ok = await client.get(f"/backups/download/{name}")
        sidecar = await client.get(f"/backups/download/{name}.sha256")
        foreign = await client.get("/backups/download/notes.txt")
        parent = await client.get("/backups/download/%2e%2e")
        encoded = await client.get("/backups/download/..%2Foutside.bin")
        absolute = await client.get("/backups/download/%2Fetc%2Fpasswd")
        symlink = await client.get("/backups/download/carchive-20200101T000000Z.sqlite3.gz")

    assert ok.status_code == 200
    assert ok.content == (backup_dir / name).read_bytes()
    assert ok.headers["content-disposition"].startswith("attachment;")
    assert name in ok.headers["content-disposition"]
    assert ok.headers["cache-control"] == "no-store"
    for rejected in (sidecar, foreign, parent, encoded, absolute, symlink):
        assert rejected.status_code == 404
        assert b"outside" not in rejected.content


async def test_download_requires_a_session(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    service = _make_service(db, tmp_path, settings)
    await service.create()
    app = _make_app(db, settings, service)
    [backup] = service.list_backups()

    async with _client(app, signed_in=False) as client:
        response = await client.get(f"/backups/download/{backup.path.name}")

    assert response.status_code == 303


async def _encrypted_backup(service: BackupService) -> str:
    path = await service.derive(encrypt=True, passphrase=lambda: _PASSPHRASE).create()
    return path.name


async def test_verify_encrypted_with_right_and_wrong_passphrase(
    db: Database, tmp_path: Path
) -> None:
    settings = _make_settings(tmp_path)
    service = _make_service(db, tmp_path, settings)
    name = await _encrypted_backup(service)
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        wrong = await _post(client, f"/backups/{name}/verify", {"passphrase": "wrong passphrase"})
        missing = await _post(client, f"/backups/{name}/verify")
        right = await _post(client, f"/backups/{name}/verify", {"passphrase": _PASSPHRASE})

    assert wrong.status_code == 400
    assert "passphrase is wrong or the archive is damaged" in wrong.text
    assert missing.status_code == 400
    assert "Enter the passphrase to check" in missing.text
    assert right.status_code == 200
    assert f"{name} is intact." in right.text
    for response in (wrong, missing, right):
        assert _PASSPHRASE not in response.text
        assert "wrong passphrase" not in response.text


async def test_verify_unencrypted_needs_no_passphrase(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    service = _make_service(db, tmp_path, settings)
    path = await service.create()
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        response = await _post(client, f"/backups/{path.name}/verify")

    assert response.status_code == 200
    assert f"{path.name} is intact." in response.text


async def test_verify_reports_a_damaged_checksum(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    service = _make_service(db, tmp_path, settings)
    path = await service.create()
    path.write_bytes(path.read_bytes() + b"x")
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        response = await _post(client, f"/backups/{path.name}/verify")
        listing = await client.get("/backups")

    assert response.status_code == 400
    assert "checksum is missing or does not match" in response.text
    assert 'status-badge-negative">failed</span>' in listing.text.split("Checksum")[1]


async def test_verify_unknown_name_is_404(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        response = await _post(client, "/backups/carchive-20200101T000000Z.sqlite3.gz/verify")
        traversal = await _post(client, "/backups/..%2Fcarchive.sqlite3/verify")

    assert response.status_code == 404
    assert traversal.status_code == 404


async def test_post_without_csrf_token_is_rejected(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    service = _make_service(db, tmp_path, settings)
    path = await service.create()
    app = _make_app(db, settings, service)

    async with _client(app) as client:
        await client.get("/backups")
        create = await client.post("/backups", data={}, headers=_ORIGIN)
        verify = await client.post(f"/backups/{path.name}/verify", data={}, headers=_ORIGIN)
        wrong = await client.post("/backups", data={"csrf_token": "not-the-token"}, headers=_ORIGIN)

    assert create.status_code == 403
    assert verify.status_code == 403
    assert wrong.status_code == 403
    assert len(service.list_backups()) == 1


async def test_passphrase_never_reaches_responses_or_logs(
    db: Database, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _make_settings(tmp_path)
    service = _make_service(db, tmp_path, settings)
    app = _make_app(db, settings, service)
    caplog.set_level(logging.DEBUG, logger="carchive")

    with capture_logs() as events:
        async with _client(app) as client:
            created = await _post(
                client,
                "/backups",
                _create_form(encrypt="on", passphrase=_PASSPHRASE, repeat="x" * 9),
            )
            created_ok = await _post(
                client,
                "/backups",
                _create_form(encrypt="on", passphrase=_PASSPHRASE, repeat=_PASSPHRASE),
            )
            [name] = _names(created_ok.text)
            checked = await _post(client, f"/backups/{name}/verify", {"passphrase": _PASSPHRASE})
            listing = await client.get("/backups")

    for response in (created, created_ok, checked, listing):
        assert _PASSPHRASE not in response.text
        assert _PASSPHRASE not in str(response.headers)
    assert _PASSPHRASE not in caplog.text
    assert _PASSPHRASE not in str(events)


async def test_concurrent_operation_is_refused(db: Database, tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    app = _make_app(db, settings, _make_service(db, tmp_path, settings))

    async with _client(app) as client:
        await app.state.backup_lock.acquire()
        try:
            response = await _post(client, "/backups")
        finally:
            app.state.backup_lock.release()

    assert response.status_code == 409
    assert "Another backup operation is running" in response.text
    assert not list(settings.effective_backup_dir.glob("carchive-*"))
