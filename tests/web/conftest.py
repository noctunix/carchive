"""Shared fixtures for web layer tests."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import httpx
import pytest

from carchive.config import Settings
from carchive.core.provider import ProviderRegistry
from carchive.services.accounts import AccountService
from carchive.services.app_services import AppServices, SchedulerLike
from carchive.services.operator_auth import LoginThrottle, OperatorAuth
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.web.auth import SESSION_COOKIE_NAME

OPERATOR_PASSWORD = "synthetic-operator-password"


class FakeScheduler:
    """A `services.app_services.SchedulerLike` that just waits for the stop event."""

    def __init__(self) -> None:
        self.run_calls = 0

    async def run(self, stop: asyncio.Event) -> None:
        self.run_calls += 1
        await stop.wait()


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


@pytest.fixture(autouse=True)
def _isolated_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every XDG/Carchive env var at a fresh tmp dir, never the real home."""
    monkeypatch.delenv("CARCHIVE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data")


@pytest.fixture
def accounts(db: Database, settings: Settings) -> AccountService:
    """A plain `AccountService` with no providers registered, for tests that only need
    something to pass to `AppServices` and do not exercise account management itself.
    """
    return AccountService(db, ProviderRegistry(), settings)


@pytest.fixture
def operator_auth(db: Database, tmp_path: Path) -> OperatorAuth:
    """A login backend on the test database with its own secrets file."""
    return OperatorAuth(db, tmp_path / "auth" / "secrets.toml")


@pytest.fixture
def login_throttle() -> LoginThrottle:
    return LoginThrottle()


_ACTIVE_LOGIN: tuple[OperatorAuth, LoginThrottle] | None = None


def build_services(db: Database, scheduler: SchedulerLike, accounts: AccountService) -> AppServices:
    """Build `AppServices` wired to the current test's login backend and throttle."""
    assert _ACTIVE_LOGIN is not None, "build_services needs the _signed_in_web_clients fixture"
    return AppServices(db, scheduler, accounts, *_ACTIVE_LOGIN)


@pytest.fixture(autouse=True)
async def _signed_in_web_clients(
    operator_auth: OperatorAuth, login_throttle: LoginThrottle, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Make every web test client signed in unless the test brings its own `cookies`.

    The operator password is set up front and each `httpx.AsyncClient` starts with a valid
    session cookie; a test that passes `cookies=` (even an empty dict) keeps full control.
    """
    await operator_auth.set_password(OPERATOR_PASSWORD)
    session = await operator_auth.create_session()
    monkeypatch.setattr(sys.modules[__name__], "_ACTIVE_LOGIN", (operator_auth, login_throttle))

    original_client_init = httpx.AsyncClient.__init__

    def client_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
        if "cookies" not in kwargs:
            kwargs["cookies"] = {SESSION_COOKIE_NAME: session.token}
        original_client_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", client_init)
