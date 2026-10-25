"""Tests for the `/accounts` overview, password replacement and delete-confirmation routes."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from carchive.config import Settings, load_secrets, vault_key_path
from carchive.core.models import RemoteVehicle
from carchive.core.provider import ProviderRegistry
from carchive.services.accounts import AccountService
from carchive.services.backup import BackupService
from carchive.storage.db import Database
from carchive.web.app import create_app
from tests.services.fakes import FakeProvider
from tests.web.conftest import FakeScheduler, build_services

_ORIGIN = {"Origin": "http://localhost"}


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def _app_with_fake_provider(
    db: Database,
    settings: Settings,
    fake_provider: FakeProvider,
    *,
    backup: BackupService | None = None,
) -> FastAPI:
    registry = ProviderRegistry()
    registry.register(fake_provider)
    accounts = AccountService(db, registry, settings, backup=backup)
    return create_app(build_services(db, FakeScheduler(), accounts), settings)


async def _add_account_with_vehicle(client: httpx.AsyncClient, label: str = "myacct") -> str:
    await client.get("/setup")
    csrf = client.cookies.get("csrf_token")
    account_response = await client.post(
        "/setup",
        data={
            "csrf_token": csrf,
            "provider_choice": "fake|fake",
            "label": label,
            "user": "user",
            "password": "s3cret-password",
        },
        headers=_ORIGIN,
    )
    match = re.search(r'name="token" value="([^"]+)"', account_response.text)
    assert match is not None, account_response.text
    await client.post(
        "/setup/vehicles",
        data={"csrf_token": csrf, "token": match.group(1), "vin": "WAUZZZ4V0JA123456"},
        headers=_ORIGIN,
    )
    assert csrf is not None
    return csrf


async def test_accounts_lists_accounts(db: Database, settings: Settings) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        response = await client.get("/accounts")

    assert response.status_code == 200
    assert "myacct" in response.text


async def test_accounts_groups_vehicles_under_their_account(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        response = await client.get("/accounts")

    assert response.status_code == 200
    account_pos = response.text.index("myacct")
    vehicle_pos = response.text.index("/vehicles/")
    assert account_pos < vehicle_pos, "vehicle link must appear within its account's block"


async def test_accounts_with_no_vehicles_shows_empty_message(
    db: Database, settings: Settings
) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        await client.post(
            "/setup",
            data={
                "csrf_token": csrf,
                "provider_choice": "fake|fake",
                "label": "myacct",
                "user": "user",
                "password": "s3cret-password",
            },
            headers=_ORIGIN,
        )
        response = await client.get("/accounts")

    assert response.status_code == 200
    assert "No vehicles yet." in response.text


async def test_accounts_empty_shows_setup_link(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/accounts")

    assert response.status_code == 200
    assert 'href="/setup"' in response.text


async def test_accounts_delete_confirmation_lists_what_would_be_removed(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        response = await client.get("/accounts/myacct/delete")

    assert response.status_code == 200
    assert "myacct" in response.text


async def test_accounts_delete_unknown_label_is_404(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/accounts/does-not-exist/delete")

    assert response.status_code == 404


async def test_accounts_delete_requires_csrf_token(db: Database, settings: Settings) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        response = await client.post("/accounts/myacct/delete", headers=_ORIGIN)

    assert response.status_code == 403


async def test_accounts_delete_removes_it_and_reports_no_backups(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        csrf = await _add_account_with_vehicle(client)
        delete_response = await client.post(
            "/accounts/myacct/delete", data={"csrf_token": csrf}, headers=_ORIGIN
        )
        listing = await client.get("/accounts")

    assert delete_response.status_code == 200
    assert "myacct" not in listing.text


async def test_accounts_delete_reports_oldest_backup_age(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    old_time = datetime.now(UTC) - timedelta(days=2)
    archive = backup_dir / f"carchive-{old_time.strftime('%Y%m%dT%H%M%SZ')}.sqlite3.gz"
    archive.write_bytes(b"not a real backup, only the name is read here")
    backup = BackupService(tmp_path / "data" / "carchive.sqlite3", backup_dir, None)
    app = _app_with_fake_provider(db, settings, fake_provider, backup=backup)

    async with _client(app) as client:
        csrf = await _add_account_with_vehicle(client)
        response = await client.post(
            "/accounts/myacct/delete", data={"csrf_token": csrf}, headers=_ORIGIN
        )

    assert response.status_code == 200
    assert "2" in response.text


async def test_accounts_german_translation(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        client.cookies.set("lang", "de")
        response = await client.get("/accounts")

    assert response.status_code == 200
    assert "Konten" in response.text


_NEW_PORTAL_PASSWORD = "brand-new-portal-passphrase"


async def _app_pair(db: Database, settings: Settings) -> tuple[FastAPI, FastAPI, str]:
    """Add an account via one app; the second app portal only accepts the new password."""
    first = _app_with_fake_provider(
        db, settings, FakeProvider(user="user", password="s3cret-password")
    )
    async with _client(first) as client:
        csrf = await _add_account_with_vehicle(client)
    second = _app_with_fake_provider(
        db, settings, FakeProvider(user="user", password=_NEW_PORTAL_PASSWORD)
    )
    return first, second, csrf


async def _post_password(
    app: FastAPI, label: str, password: str, repeat: str | None = None
) -> httpx.Response:
    async with _client(app) as client:
        await client.get(f"/accounts/{label}/password")
        return await client.post(
            f"/accounts/{label}/password",
            data={
                "csrf_token": client.cookies.get("csrf_token"),
                "password": password,
                "repeat": password if repeat is None else repeat,
            },
            headers=_ORIGIN,
        )


async def test_account_password_form_shows_up(db: Database, settings: Settings) -> None:
    app, _, _ = await _app_pair(db, settings)

    async with _client(app) as client:
        page = await client.get("/accounts/myacct/password")

    assert 'action="/accounts/myacct/password"' in page.text
    assert "s3cret-password" not in page.text


async def test_account_password_form_unknown_account_is_404(
    db: Database, settings: Settings
) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/accounts/does-not-exist/password")

    assert response.status_code == 404


async def test_set_account_password_replaces_it_and_shows_nothing_secret(
    db: Database, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    _, app, _ = await _app_pair(db, settings)

    response = await _post_password(app, "myacct", _NEW_PORTAL_PASSWORD)

    assert response.status_code == 200
    assert "Portal password replaced" in response.text
    assert "Restart" not in response.text
    assert _NEW_PORTAL_PASSWORD not in response.text
    assert _NEW_PORTAL_PASSWORD not in caplog.text
    assert load_secrets(settings.secrets_file)["myacct"] == {
        "user": "user",
        "password": _NEW_PORTAL_PASSWORD,
    }
    assert _NEW_PORTAL_PASSWORD not in settings.secrets_file.read_text()


async def test_set_account_password_requires_csrf_token(db: Database, settings: Settings) -> None:
    _, app, _ = await _app_pair(db, settings)

    async with _client(app) as client:
        response = await client.post(
            "/accounts/myacct/password",
            data={"password": _NEW_PORTAL_PASSWORD, "repeat": _NEW_PORTAL_PASSWORD},
            headers=_ORIGIN,
        )

    assert response.status_code == 403
    assert load_secrets(settings.secrets_file)["myacct"]["password"] == "s3cret-password"


async def test_set_account_password_unknown_account_is_404(
    db: Database, settings: Settings
) -> None:
    _, app, _ = await _app_pair(db, settings)

    response = await _post_password(app, "does-not-exist", _NEW_PORTAL_PASSWORD)

    assert response.status_code == 404


async def test_set_account_password_mismatch_and_empty(db: Database, settings: Settings) -> None:
    _, app, _ = await _app_pair(db, settings)

    mismatch = await _post_password(app, "myacct", _NEW_PORTAL_PASSWORD, "different")
    empty = await _post_password(app, "myacct", "")

    assert mismatch.status_code == 400
    assert "The new passwords do not match." in mismatch.text
    assert empty.status_code == 400
    assert "must be 1 to 1024 characters" in empty.text
    assert _NEW_PORTAL_PASSWORD not in mismatch.text
    assert load_secrets(settings.secrets_file)["myacct"]["password"] == "s3cret-password"


async def test_set_account_password_rejected_by_portal_changes_nothing(
    db: Database, settings: Settings
) -> None:
    app, _, _ = await _app_pair(db, settings)

    response = await _post_password(app, "myacct", "not-the-portal-one")

    assert response.status_code == 400
    assert "The portal did not accept the login" in response.text
    assert "not-the-portal-one" not in response.text
    assert load_secrets(settings.secrets_file)["myacct"]["password"] == "s3cret-password"


async def test_set_account_password_recovers_a_lost_vault_key(
    db: Database, settings: Settings
) -> None:
    _, app, _ = await _app_pair(db, settings)
    vault_key_path(settings.secrets_file).unlink()

    response = await _post_password(app, "myacct", _NEW_PORTAL_PASSWORD)

    assert response.status_code == 200
    assert load_secrets(settings.secrets_file)["myacct"]["password"] == _NEW_PORTAL_PASSWORD


async def test_set_account_password_reports_unreadable_storage(
    db: Database, settings: Settings
) -> None:
    _, app, _ = await _app_pair(db, settings)
    vault_key_path(settings.secrets_file).chmod(0o644)

    response = await _post_password(app, "myacct", _NEW_PORTAL_PASSWORD)

    assert response.status_code == 500
    assert "The password could not be stored" in response.text
    assert _NEW_PORTAL_PASSWORD not in response.text


async def test_set_account_password_messages_are_translated(
    db: Database, settings: Settings
) -> None:
    _, app, _ = await _app_pair(db, settings)

    async with _client(app) as client:
        client.cookies.set("lang", "de")
        await client.get("/accounts/myacct/password")
        response = await client.post(
            "/accounts/myacct/password",
            data={
                "csrf_token": client.cookies.get("csrf_token"),
                "password": _NEW_PORTAL_PASSWORD,
                "repeat": _NEW_PORTAL_PASSWORD,
            },
            headers=_ORIGIN,
        )

    assert "Portal-Passwort ersetzt" in response.text
