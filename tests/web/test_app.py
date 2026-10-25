"""Tests for `carchive.web.app.create_app`."""

from __future__ import annotations

import asyncio
import time
from uuid import UUID

import httpx
from fastapi import FastAPI

from carchive.config import Settings
from carchive.services.accounts import AccountService
from carchive.services.scheduler import Scheduler
from carchive.storage.db import Database
from carchive.web.app import create_app
from tests.web.conftest import FakeScheduler, build_services


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


async def test_healthz_reports_ok_when_db_and_scheduler_are_healthy(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    services = build_services(db, FakeScheduler(), accounts)
    services.mark_scheduler_running(True)
    app = create_app(services, settings)

    async with _client(app) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "db": "ok", "scheduler": "running"}


async def test_healthz_reports_error_when_scheduler_is_not_running(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    services = build_services(db, FakeScheduler(), accounts)
    app = create_app(services, settings)

    async with _client(app) as client:
        response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json()["scheduler"] == "stopped"


async def test_healthz_reports_error_when_db_is_unavailable(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    services = build_services(db, FakeScheduler(), accounts)
    services.mark_scheduler_running(True)
    app = create_app(services, settings)
    await db.close()

    async with _client(app) as client:
        response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json()["db"] == "error"


async def test_security_headers_present_on_a_normal_page(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)

    async with _client(app) as client:
        response = await client.get("/")

    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_unknown_host_header_is_rejected(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)

    async with _client(app) as client:
        response = await client.get("/", headers={"Host": "evil.example"})

    assert response.status_code == 400


async def test_404_page_has_no_path_or_detail(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)

    async with _client(app) as client:
        response = await client.get("/this-route-does-not-exist")

    assert response.status_code == 404
    assert "this-route-does-not-exist" not in response.text
    assert "Traceback" not in response.text


async def test_language_defaults_to_english(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)

    async with _client(app) as client:
        response = await client.get("/")

    assert "Dashboard" in response.text


async def test_language_negotiated_from_cookie(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)

    async with _client(app) as client:
        client.cookies.set("lang", "de")
        response = await client.get("/")

    assert "Übersicht" in response.text


async def test_language_negotiated_from_accept_language_header(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)

    async with _client(app) as client:
        response = await client.get("/", headers={"accept-language": "de-DE,de;q=0.9,en;q=0.8"})

    assert "Übersicht" in response.text


async def test_dashboard_reports_no_vehicles_yet(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)

    async with _client(app) as client:
        response = await client.get("/")

    assert "No vehicles yet" in response.text


async def test_lifespan_starts_and_stops_the_scheduler(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    scheduler = FakeScheduler()
    services = build_services(db, scheduler, accounts)
    app = create_app(services, settings)

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0)  # let the scheduler's task actually start running
        assert scheduler.run_calls == 1
        assert services.scheduler_running() is True

    assert services.scheduler_running() is False


class _NoopCollector:
    """A collector that must never run: there is no due account in an empty database."""

    async def run_account(self, account_id: UUID) -> None:
        raise AssertionError("no account should be due in an empty database")


async def test_lifespan_shutdown_is_prompt_even_mid_poll_interval(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    """Regression test: shutdown must not wait out the scheduler's poll interval (60 s).

    Exercises the real `Scheduler`, not `FakeScheduler`, since the bug this guards against
    was in `Scheduler.run`'s sleep ignoring the `stop` event, not in the lifespan itself.
    """
    scheduler = Scheduler(_NoopCollector(), db, poll_cap_s=60.0)  # type: ignore[arg-type]
    services = build_services(db, scheduler, accounts)
    app = create_app(services, settings)

    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    await asyncio.sleep(0.05)  # let the scheduler enter its 60s sleep before shutting down

    started = time.monotonic()
    await lifespan.__aexit__(None, None, None)
    elapsed = time.monotonic() - started

    assert elapsed < 2.0


async def test_app_version_appears_in_the_topbar(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    services = build_services(db, FakeScheduler(), accounts)
    app = create_app(services, settings, version="1.2.3")

    async with _client(app) as client:
        response = await client.get("/")

    assert "v1.2.3" in response.text


async def test_app_version_defaults_to_dev_when_not_given(
    db: Database, settings: Settings, accounts: AccountService
) -> None:
    services = build_services(db, FakeScheduler(), accounts)
    app = create_app(services, settings)

    async with _client(app) as client:
        response = await client.get("/")

    assert "vdev" in response.text
