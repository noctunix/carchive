"""Tests for the `/setup` wizard routes."""

from __future__ import annotations

import re

import httpx
from fastapi import FastAPI

from carchive.config import Settings
from carchive.core.models import RemoteVehicle
from carchive.core.provider import ProviderRegistry
from carchive.services.accounts import AccountService
from carchive.storage.db import Database
from carchive.web.app import create_app
from tests.services.fakes import FakeProvider
from tests.web.conftest import FakeScheduler, build_services

_ORIGIN = {"Origin": "http://localhost"}


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def _app_with_fake_provider(
    db: Database, settings: Settings, fake_provider: FakeProvider
) -> FastAPI:
    registry = ProviderRegistry()
    registry.register(fake_provider)
    accounts = AccountService(db, registry, settings)
    return create_app(build_services(db, FakeScheduler(), accounts), settings)


def _extract_token(html: str) -> str:
    match = re.search(r'name="token" value="([^"]+)"', html)
    assert match is not None, html
    return match.group(1)


async def test_setup_page_shows_tutorial_and_form(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/setup")

    assert response.status_code == 200
    assert "Portal" in response.text or "portal" in response.text.lower()
    assert 'name="provider_choice"' in response.text


async def test_setup_account_creates_account_and_shows_vehicles(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
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

    assert response.status_code == 200
    assert "WAU" in response.text
    assert "s3cret-password" not in response.text


async def test_setup_account_login_failure_shows_error_without_the_password(
    db: Database, settings: Settings
) -> None:
    app = _app_with_fake_provider(
        db, settings, FakeProvider(user="user", password="s3cret-password")
    )

    async with _client(app) as client:
        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            "/setup",
            data={
                "csrf_token": csrf,
                "provider_choice": "fake|fake",
                "label": "myacct",
                "user": "user",
                "password": "wrong-canary-password",
            },
            headers=_ORIGIN,
        )

    assert response.status_code == 400
    assert "wrong-canary-password" not in response.text


async def test_setup_account_unknown_brand_shows_error(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            "/setup",
            data={
                "csrf_token": csrf,
                "provider_choice": "nope|nope",
                "label": "myacct",
                "user": "user",
                "password": "s3cret-password",
            },
            headers=_ORIGIN,
        )

    assert response.status_code == 400


async def test_setup_requires_csrf_token(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.post(
            "/setup",
            data={"provider_choice": "fake|fake", "label": "myacct"},
            headers=_ORIGIN,
        )

    assert response.status_code == 403


async def test_setup_vehicles_adds_selected_vehicles_and_shows_confirmation(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        account_response = await client.post(
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
        token = _extract_token(account_response.text)

        response = await client.post(
            "/setup/vehicles",
            data={"csrf_token": csrf, "token": token, "vin": "WAUZZZ4V0JA123456"},
            headers=_ORIGIN,
        )

    assert response.status_code == 200
    assert "1" in response.text


async def test_setup_vehicles_token_is_single_use(db: Database, settings: Settings) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        account_response = await client.post(
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
        token = _extract_token(account_response.text)
        form = {"csrf_token": csrf, "token": token, "vin": "WAUZZZ4V0JA123456"}

        first = await client.post("/setup/vehicles", data=form, headers=_ORIGIN)
        second = await client.post("/setup/vehicles", data=form, headers=_ORIGIN)

    assert first.status_code == 200
    assert second.status_code == 400


async def test_setup_vehicles_rejects_unknown_token(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            "/setup/vehicles",
            data={"csrf_token": csrf, "token": "does-not-exist", "vin": "x"},
            headers=_ORIGIN,
        )

    assert response.status_code == 400


async def test_setup_link_disappears_from_navigation_once_a_vehicle_exists(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app_with_fake_provider(db, settings, fake_provider)

    async with _client(app) as client:
        before = await client.get("/")
        assert "/setup" in before.text

        await client.get("/setup")
        csrf = client.cookies.get("csrf_token")
        account_response = await client.post(
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
        token = _extract_token(account_response.text)
        await client.post(
            "/setup/vehicles",
            data={"csrf_token": csrf, "token": token, "vin": "WAUZZZ4V0JA123456"},
            headers=_ORIGIN,
        )

        after = await client.get("/")

    assert '"/setup"' not in after.text.replace("href=", "").replace("'", '"')


async def test_setup_german_translation(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        client.cookies.set("lang", "de")
        response = await client.get("/setup")

    assert response.status_code == 200
    assert "Einrichten" in response.text or "einrichten" in response.text.lower()
