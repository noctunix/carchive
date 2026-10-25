"""Tests for the `/settings/catalog/import` upload route."""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from carchive.config import Settings
from carchive.core.provider import ProviderRegistry
from carchive.logging_setup import configure_logging
from carchive.services.accounts import AccountService
from carchive.storage.db import Database
from carchive.web.app import create_app
from tests.services.fakes import FakeProvider
from tests.services.pdf_fixtures import CONTINUOUS_HEADER, build_dictionary_pdf
from tests.web.conftest import FakeScheduler, build_services

_ORIGIN = {"Origin": "http://localhost"}


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def _app(db: Database, settings: Settings, *, catalog_import: bool = True) -> FastAPI:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    registry = ProviderRegistry()
    provider = FakeProvider()
    provider.capabilities = dataclasses.replace(
        provider.capabilities, catalog_import=catalog_import
    )
    registry.register(provider)
    accounts = AccountService(db, registry, settings)
    return create_app(build_services(db, FakeScheduler(), accounts), settings)


def _build_pdf(path: Path, key: str = "11111111-1111-1111-1111-111111111111") -> None:
    build_dictionary_pdf(
        path,
        title="List of Continuous Data",
        header=CONTINUOUS_HEADER,
        rows=[[key, "mileage", "odometer reading", "km", "int", "General"]],
    )


async def test_settings_shows_catalog_import_form_when_a_provider_supports_it(
    db: Database, settings: Settings
) -> None:
    app = _app(db, settings)
    async with _client(app) as client:
        response = await client.get("/settings")

    assert response.status_code == 200
    assert "No catalog imported yet." in response.text
    assert 'enctype="multipart/form-data"' in response.text


async def test_settings_hides_catalog_import_form_without_a_capable_provider(
    db: Database, settings: Settings
) -> None:
    app = _app(db, settings, catalog_import=False)
    async with _client(app) as client:
        response = await client.get("/settings")

    assert response.status_code == 200
    assert 'enctype="multipart/form-data"' not in response.text


async def test_import_without_csrf_token_is_rejected(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    app = _app(db, settings)
    pdf_path = tmp_path / "dict.pdf"
    _build_pdf(pdf_path)

    async with _client(app) as client:
        response = await client.post(
            "/settings/catalog/import",
            data={"provider_id": "fake", "catalog_version": "1.0"},
            files={"file": ("dict.pdf", pdf_path.read_bytes(), "application/pdf")},
            headers=_ORIGIN,
        )

    assert response.status_code == 403
    assert list(settings.data_dir.iterdir()) == []


async def test_import_succeeds_and_leaves_no_temp_file(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    app = _app(db, settings)
    pdf_path = tmp_path / "dict.pdf"
    _build_pdf(pdf_path)

    async with _client(app) as client:
        await client.get("/settings")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            f"/settings/catalog/import?csrf_token={csrf}",
            data={"provider_id": "fake", "catalog_version": "1.0"},
            files={"file": ("dict.pdf", pdf_path.read_bytes(), "application/pdf")},
            headers=_ORIGIN,
        )
        listing = await client.get("/settings")

    assert response.status_code == 200
    assert "1 new entries" in response.text or "new entries" in response.text
    assert "1.0" in listing.text
    assert list(settings.data_dir.iterdir()) == []


async def test_import_derives_version_from_filename_when_left_empty(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    app = _app(db, settings)
    pdf_path = tmp_path / "20260724_DataDictionary_V6.0_Continuous_Data.pdf"
    _build_pdf(pdf_path)

    async with _client(app) as client:
        await client.get("/settings")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            f"/settings/catalog/import?csrf_token={csrf}",
            data={"provider_id": "fake", "catalog_version": ""},
            files={"file": (pdf_path.name, pdf_path.read_bytes(), "application/pdf")},
            headers=_ORIGIN,
        )

    assert response.status_code == 200
    assert "6.0" in response.text


async def test_import_rejects_a_pdf_with_no_recognizable_kind(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    app = _app(db, settings)
    pdf_path = tmp_path / "dict.pdf"
    build_dictionary_pdf(
        pdf_path,
        title="Some Other Document",
        header=CONTINUOUS_HEADER,
        rows=[["11111111-1111-1111-1111-111111111111", "a", "desc", "%", "float", "Cluster A"]],
    )

    async with _client(app) as client:
        await client.get("/settings")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            f"/settings/catalog/import?csrf_token={csrf}",
            data={"provider_id": "fake", "catalog_version": "1.0"},
            files={"file": ("dict.pdf", pdf_path.read_bytes(), "application/pdf")},
            headers=_ORIGIN,
        )

    assert response.status_code == 400
    assert list(settings.data_dir.iterdir()) == []


async def test_import_rejects_an_oversized_upload(
    db: Database, settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import carchive.web.routes.settings as settings_routes

    monkeypatch.setattr(settings_routes, "_MAX_CATALOG_UPLOAD_BYTES", 10)
    app = _app(db, settings)
    pdf_path = tmp_path / "dict.pdf"
    _build_pdf(pdf_path)

    async with _client(app) as client:
        await client.get("/settings")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            f"/settings/catalog/import?csrf_token={csrf}",
            data={"provider_id": "fake", "catalog_version": "1.0"},
            files={"file": ("dict.pdf", pdf_path.read_bytes(), "application/pdf")},
            headers=_ORIGIN,
        )

    assert response.status_code == 413
    assert list(settings.data_dir.iterdir()) == []


async def test_catalog_import_german_translation(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    app = _app(db, settings)
    pdf_path = tmp_path / "dict.pdf"
    _build_pdf(pdf_path)

    async with _client(app) as client:
        client.cookies.set("lang", "de")
        await client.get("/settings")
        csrf = client.cookies.get("csrf_token")
        response = await client.post(
            f"/settings/catalog/import?csrf_token={csrf}",
            data={"provider_id": "fake", "catalog_version": "1.0"},
            files={"file": ("dict.pdf", pdf_path.read_bytes(), "application/pdf")},
            headers=_ORIGIN,
        )
        settings_page = await client.get("/settings")

    assert "Katalog-Import" in response.text
    assert "Dictionary-Katalog" in settings_page.text


async def test_upload_csrf_token_is_masked_if_the_request_path_is_ever_logged(
    db: Database, settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real token from a real upload request must never show up in captured logs.

    uvicorn's own access logger (not exercised here, since no real server is bound in
    this test) logs each request's full path, including this route's query-string CSRF
    token; this reproduces that log line through `logging_setup.configure_logging`'s
    pipeline with the exact token a real upload used, via the standard logger name
    uvicorn's access log uses.
    """
    configure_logging(verbose=False, fmt="json")

    app = _app(db, settings)
    pdf_path = tmp_path / "dict.pdf"
    _build_pdf(pdf_path)

    async with _client(app) as client:
        await client.get("/settings")
        csrf = client.cookies.get("csrf_token")
        assert csrf
        request_path = f"/settings/catalog/import?csrf_token={csrf}"
        response = await client.post(
            request_path,
            data={"provider_id": "fake", "catalog_version": "1.0"},
            files={"file": ("dict.pdf", pdf_path.read_bytes(), "application/pdf")},
            headers=_ORIGIN,
        )
    assert response.status_code == 200

    # No real server runs in this test; this stands in for uvicorn's own access logger,
    # which would otherwise log the request line with the token still in the query string.
    logging.getLogger("uvicorn.access").info(
        '%s - "POST %s HTTP/1.1" %s', "127.0.0.1:12345", request_path, response.status_code
    )

    output = capsys.readouterr().err
    assert csrf not in output
    assert "csrf_token=***" in output
