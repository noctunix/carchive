"""Tests for `VwGroupProvider`."""

from __future__ import annotations

import httpx
import pytest

from carchive.core.errors import AuthenticationError
from carchive.core.provider import Provider
from carchive.providers.vwgroup import login
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.providers.vwgroup.parser import VwGroupParser
from carchive.providers.vwgroup.provider import VwGroupProvider
from carchive.providers.vwgroup.session import VwGroupDeliverySession


def test_provider_satisfies_the_protocol() -> None:
    # Assigning to a `Provider`-typed variable makes this a static check under mypy: it
    # only passes if `VwGroupProvider` structurally satisfies the protocol.
    instance: Provider = VwGroupProvider()
    assert instance.id == "vwgroup-euda"
    assert instance.brands == {"volkswagen", "audi", "skoda", "seat", "cupra"}
    assert instance.capabilities.delivery is True
    assert instance.capabilities.stream is False
    assert {f.name for f in instance.credential_fields} == {"user", "password"}


async def test_open_delivery_session_returns_a_logged_in_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_login(client: httpx.AsyncClient, brand: str, user: str, password: str) -> None:
        return None

    monkeypatch.setattr(login, "perform_login", fake_login)

    provider = VwGroupProvider()
    session = await provider.open_delivery_session("audi", {"user": "u", "password": "p"})
    try:
        assert isinstance(session, VwGroupDeliverySession)
    finally:
        await session.aclose()


async def test_open_delivery_session_closes_the_client_on_failed_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[httpx.AsyncClient] = []
    real_async_client = httpx.AsyncClient

    def recording_factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        client = real_async_client(*args, **kwargs)  # type: ignore[arg-type]
        created.append(client)
        return client

    async def failing_login(
        client: httpx.AsyncClient, brand: str, user: str, password: str
    ) -> None:
        raise AuthenticationError("bad password")

    monkeypatch.setattr(httpx, "AsyncClient", recording_factory)
    monkeypatch.setattr(login, "perform_login", failing_login)

    provider = VwGroupProvider()
    with pytest.raises(AuthenticationError):
        await provider.open_delivery_session("audi", {"user": "u", "password": "p"})

    assert len(created) == 1
    assert created[0].is_closed


async def test_open_stream_session_is_not_implemented() -> None:
    provider = VwGroupProvider()
    with pytest.raises(NotImplementedError):
        await provider.open_stream_session("audi", {"user": "u", "password": "p"})


def test_parser_and_mapper_are_wired_up() -> None:
    provider = VwGroupProvider()
    assert isinstance(provider.parser(), VwGroupParser)
    assert isinstance(provider.mapper(), VwGroupMapper)
