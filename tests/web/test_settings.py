"""Tests for the `/settings` page: dictionary catalog and operator password."""

from __future__ import annotations

import httpx
from fastapi import FastAPI

from carchive.config import Settings
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


async def test_settings_shows_catalog_security_and_language(
    db: Database, settings: Settings
) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/settings")

    assert response.status_code == 200
    assert "Dictionary catalog" in response.text
    assert "Security" in response.text
    assert "Language" in response.text
    assert '<a href="/accounts">' in response.text
    assert '<a href="/lang/de">' in response.text


async def test_settings_language_switch_redirects_back_to_settings(
    db: Database, settings: Settings
) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/lang/de", headers={"Referer": "http://localhost/settings"})

    assert response.status_code == 303
    assert response.headers["location"] == "/settings"


async def test_settings_german_translation(db: Database, settings: Settings) -> None:
    app = _app_with_fake_provider(db, settings, FakeProvider())

    async with _client(app) as client:
        client.cookies.set("lang", "de")
        response = await client.get("/settings")

    assert response.status_code == 200
    assert "Einstellungen" in response.text
