"""Tests for `VwGroupDeliverySession`, against `httpx.MockTransport` fixtures only."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime

import httpx
import pytest

from carchive.core.errors import (
    AuthenticationError,
    NeedsAttentionError,
    ProviderError,
    RateLimitedError,
    TransientError,
)
from carchive.core.models import RemoteDataRequest, RemoteDelivery
from carchive.providers.vwgroup import session as session_module
from carchive.providers.vwgroup.session import VwGroupDeliverySession


def _scripted_transport(
    responses: Sequence[httpx.Response | Exception],
) -> httpx.MockTransport:
    remaining = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        if not remaining:
            raise AssertionError(f"no more scripted responses for {request.method} {request.url}")
        outcome = remaining.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return httpx.MockTransport(handler)


def _session(
    responses: Sequence[httpx.Response | Exception],
    min_interval_s: float = 0.0,
    relogin: Callable[[], Awaitable[None]] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    clock: Callable[[], float] | None = None,
) -> tuple[VwGroupDeliverySession, dict[str, int]]:
    client = httpx.AsyncClient(transport=_scripted_transport(responses))
    calls = {"relogin": 0}

    async def default_relogin() -> None:
        calls["relogin"] += 1

    session = VwGroupDeliverySession(
        client,
        relogin if relogin is not None else default_relogin,
        min_interval_s=min_interval_s,
        sleep=sleep,
        clock=clock,
    )
    return session, calls


# --------------------------------------------------------------------------
# Pacing
# --------------------------------------------------------------------------


async def test_requests_are_spaced_by_the_minimum_interval() -> None:
    now = [100.0]
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    session, _ = _session(
        [httpx.Response(200, json={"vehicles": []})] * 3,
        min_interval_s=1.0,
        sleep=sleep,
        clock=lambda: now[0],
    )
    await session.list_vehicles()
    now[0] += 0.25
    await session.list_vehicles()
    now[0] += 5.0
    await session.list_vehicles()
    assert waits == [0.75]
    await session.aclose()


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------


async def test_rate_limit_waits_for_the_hint_and_retries() -> None:
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    responses = [
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(429, text="Rate limit is exceeded. Try again in 12 seconds."),
        httpx.Response(200, json={"vehicles": []}),
    ]
    session, _ = _session(responses, sleep=sleep, clock=lambda: 0.0)
    await session.list_vehicles()
    assert waits == [7.0, 12.0]
    await session.aclose()


async def test_rate_limit_gives_up_when_the_hint_is_too_long() -> None:
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    session, _ = _session(
        [httpx.Response(429, headers={"Retry-After": "600"})], sleep=sleep, clock=lambda: 0.0
    )
    with pytest.raises(RateLimitedError) as exc_info:
        await session.list_vehicles()
    assert waits == []
    assert exc_info.value.retry_after_s == 600.0
    await session.aclose()


async def test_rate_limit_gives_up_after_the_retry_budget() -> None:
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    session, _ = _session([httpx.Response(429)] * 4, sleep=sleep, clock=lambda: 0.0)
    with pytest.raises(RateLimitedError):
        await session.list_vehicles()
    assert waits == [60.0, 60.0, 60.0]
    await session.aclose()


# --------------------------------------------------------------------------
# Re-login on an expired session
# --------------------------------------------------------------------------


async def test_relogin_happens_exactly_once_on_401() -> None:
    session, calls = _session(
        [httpx.Response(401), httpx.Response(200, json={"vehicles": []})], clock=lambda: 0.0
    )
    await session.list_vehicles()
    assert calls["relogin"] == 1
    await session.aclose()


async def test_relogin_failing_again_raises_authentication_error_exactly_once() -> None:
    session, calls = _session([httpx.Response(403), httpx.Response(403)], clock=lambda: 0.0)
    with pytest.raises(AuthenticationError):
        await session.list_vehicles()
    assert calls["relogin"] == 1
    await session.aclose()


# --------------------------------------------------------------------------
# Network/server errors
# --------------------------------------------------------------------------


async def test_5xx_response_raises_transient_error() -> None:
    session, _ = _session([httpx.Response(503)], clock=lambda: 0.0)
    with pytest.raises(TransientError):
        await session.list_vehicles()
    await session.aclose()


async def test_network_error_raises_transient_error() -> None:
    session, _ = _session([httpx.ConnectError("refused")], clock=lambda: 0.0)
    with pytest.raises(TransientError):
        await session.list_vehicles()
    await session.aclose()


async def test_list_vehicles_rejects_an_unexpected_4xx_status() -> None:
    session, _ = _session([httpx.Response(400, text="Bad Request")], clock=lambda: 0.0)
    with pytest.raises(NeedsAttentionError, match="status 400") as exc_info:
        await session.list_vehicles()
    assert "Bad Request" not in str(exc_info.value)
    await session.aclose()


async def test_list_vehicles_rejects_a_non_json_body() -> None:
    session, _ = _session([httpx.Response(200, text="<html>not json</html>")], clock=lambda: 0.0)
    with pytest.raises(NeedsAttentionError, match="not valid JSON") as exc_info:
        await session.list_vehicles()
    assert "<html>" not in str(exc_info.value)
    await session.aclose()


# --------------------------------------------------------------------------
# Data requests
# --------------------------------------------------------------------------


async def test_list_data_requests_skips_a_dataset_kind_the_vehicle_has_none_of() -> None:
    responses = [
        httpx.Response(400, text="Invalid identifier provided."),  # "all"
        httpx.Response(200, json={"Identifier": "ident-partial"}),  # "partial"
    ]
    session, _ = _session(responses, clock=lambda: 0.0)
    requests = await session.list_data_requests("VIN1")
    assert requests == [RemoteDataRequest(vin="VIN1", kind="partial", remote_id="ident-partial")]
    await session.aclose()


# --------------------------------------------------------------------------
# Deliveries
# --------------------------------------------------------------------------


async def test_list_deliveries_parses_placeholders_and_dates_from_the_name() -> None:
    body = {
        "files": [
            {"name": "20261022093937_VIN1.zip"},
            {"name": "20261022092341_VIN1_no_content_found.zip"},
        ]
    }
    session, _ = _session([httpx.Response(200, json=body)], clock=lambda: 0.0)
    deliveries = await session.list_deliveries(
        RemoteDataRequest(vin="VIN1", kind="partial", remote_id="ident")
    )
    assert deliveries == [
        RemoteDelivery(
            remote_name="20261022092341_VIN1_no_content_found.zip",
            delivered_at=datetime(2026, 10, 22, 9, 23, 41, tzinfo=UTC),
            has_content=False,
        ),
        RemoteDelivery(
            remote_name="20261022093937_VIN1.zip",
            delivered_at=datetime(2026, 10, 22, 9, 39, 37, tzinfo=UTC),
            has_content=True,
        ),
    ]
    await session.aclose()


async def test_list_deliveries_rejects_an_unrecognized_shape() -> None:
    session, _ = _session([httpx.Response(200, json={"unexpected": 1})], clock=lambda: 0.0)
    with pytest.raises(NeedsAttentionError, match="unexpected") as exc_info:
        await session.list_deliveries(
            RemoteDataRequest(vin="VIN1", kind="partial", remote_id="ident")
        )
    assert "1" not in str(exc_info.value)  # the value, not just the key, must never appear
    await session.aclose()


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------


async def test_download_returns_the_raw_bytes() -> None:
    session, _ = _session([httpx.Response(200, content=b"zip-bytes")], clock=lambda: 0.0)
    data = await session.download(
        RemoteDataRequest(vin="VIN1", kind="partial", remote_id="ident"),
        RemoteDelivery(remote_name="x.zip", delivered_at=None, has_content=True),
    )
    assert data == b"zip-bytes"
    await session.aclose()


async def test_download_rejects_a_404_instead_of_returning_it_as_the_payload() -> None:
    session, _ = _session(
        [httpx.Response(404, content=b"<html>not found</html>")], clock=lambda: 0.0
    )
    with pytest.raises(ProviderError, match="404") as exc_info:
        await session.download(
            RemoteDataRequest(vin="VIN1", kind="partial", remote_id="ident"),
            RemoteDelivery(remote_name="x.zip", delivered_at=None, has_content=True),
        )
    assert "not found" not in str(exc_info.value)
    await session.aclose()


async def test_download_rejects_a_400_instead_of_returning_it_as_the_payload() -> None:
    session, _ = _session(
        [httpx.Response(400, content=b"Invalid identifier provided.")], clock=lambda: 0.0
    )
    with pytest.raises(ProviderError, match="400") as exc_info:
        await session.download(
            RemoteDataRequest(vin="VIN1", kind="partial", remote_id="ident"),
            RemoteDelivery(remote_name="x.zip", delivered_at=None, has_content=True),
        )
    assert "Invalid identifier" not in str(exc_info.value)
    await session.aclose()


async def test_download_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_module, "MAX_DOWNLOAD_BYTES", 4)
    session, _ = _session([httpx.Response(200, content=b"too-large")], clock=lambda: 0.0)
    with pytest.raises(ProviderError, match="size limit"):
        await session.download(
            RemoteDataRequest(vin="VIN1", kind="partial", remote_id="ident"),
            RemoteDelivery(remote_name="x.zip", delivered_at=None, has_content=True),
        )
    await session.aclose()
