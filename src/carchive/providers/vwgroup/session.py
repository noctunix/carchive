"""An authenticated session with the VW-group EU Data Act portal.

Implements `core.provider.DeliverySession`: listing vehicles, resolving the per-vehicle data
requests, listing their deliveries and downloading them. All requests go through one retry
and pacing policy, ported from `eu_data_act_sampler.py`'s `PortalClient`: a minimum spacing
between requests, bounded waiting on `429` responses, and one re-login attempt on `401`/`403`.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from carchive.core.errors import (
    AuthenticationError,
    NeedsAttentionError,
    ProviderError,
    RateLimitedError,
    TransientError,
)
from carchive.core.models import RemoteDataRequest, RemoteDelivery, RemoteVehicle
from carchive.providers.vwgroup.login import PORTAL_BASE_URL

# The portal keeps at most 30 files per data request, cancelling a request whose files are
# not downloaded within 7 days; both independent of this session, recorded here only because
# the collector (not built yet) needs the portal's own dataset-type labels to poll each one.
DATASET_KINDS = ("all", "partial")

# (connect, read, write, pool) seconds for every portal API request, independent of whatever
# timeout the passed-in client happens to be configured with.
REQUEST_TIMEOUT = httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=15.0)

# The largest real delivery seen so far is a 17 MB JSON document (inside its ZIP); this
# leaves ample room while still bounding memory use against a broken or hostile response.
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024

RATE_LIMIT_MAX_WAIT_S = 120.0
RATE_LIMIT_DEFAULT_WAIT_S = 60.0
RATE_LIMIT_MAX_RETRIES = 3
_RETRY_IN_SECONDS = re.compile(r"try again in (\d+) seconds", re.IGNORECASE)

PLACEHOLDER_SUFFIX = "_no_content_found.zip"
_NAME_TIMESTAMP = re.compile(r"^(\d{14})_")


def _delivery_base_url(vin: str, remote_id: str) -> str:
    return f"{PORTAL_BASE_URL}/proxy_api/euda-apim/datadelivery/vehicles/{vin}/{remote_id}"


def _delivered_at_from_name(name: str) -> datetime | None:
    """Parse a delivery's `YYYYmmddHHMMSS_...` name prefix as a UTC timestamp."""
    match = _NAME_TIMESTAMP.match(name)
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def _retry_after_seconds(headers: httpx.Headers, text: str) -> float:
    header = headers.get("Retry-After", "")
    if header.strip().isdigit():
        return float(header)
    match = _RETRY_IN_SECONDS.search(text)
    return float(match.group(1)) if match else RATE_LIMIT_DEFAULT_WAIT_S


async def _read_bounded(resp: httpx.Response) -> bytes:
    """Read a streamed response body, aborting once it exceeds `MAX_DOWNLOAD_BYTES`.

    The declared `Content-Length` can lie, so the read itself is bounded, not just the
    header.

    Raises:
        ProviderError: if more than `MAX_DOWNLOAD_BYTES` bytes are read.
    """
    received = 0
    chunks: list[bytes] = []
    async for chunk in resp.aiter_bytes():
        received += len(chunk)
        if received > MAX_DOWNLOAD_BYTES:
            raise ProviderError("download exceeds the size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _json(resp: httpx.Response, what: str) -> Any:
    """Decode a JSON response body, never trusting the portal's status or payload shape.

    Args:
        resp: the response to decode.
        what: a short, log-safe description of the request, used in the error message.

    Returns:
        The decoded JSON value, a `dict` or a `list`.

    Raises:
        NeedsAttentionError: if the response is not `2xx`, the body is not valid JSON, or
            the decoded value is neither a JSON object nor a list.
    """
    if not 200 <= resp.status_code < 300:
        raise NeedsAttentionError(f"unexpected response for {what}: status {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        raise NeedsAttentionError(f"unexpected response for {what}: not valid JSON") from None
    if not isinstance(data, dict | list):
        raise NeedsAttentionError(f"unexpected response for {what}: unexpected JSON shape")
    return data


def _parse_vehicle_list(data: Any) -> list[RemoteVehicle]:
    raw = data if isinstance(data, list) else data.get("vehicles", [])
    vehicles = []
    for entry in raw:
        vin = entry.get("vin") or entry.get("vehicleIdentificationNumber", "")
        if not vin:
            continue
        name = next(
            (
                entry[k]
                for k in ("nickName", "vehicleNickname", "nickname", "modelName")
                if entry.get(k)
            ),
            "",
        )
        vehicles.append(RemoteVehicle(vin=vin, name=name))
    return vehicles


def _parse_delivery_list(data: Any) -> list[RemoteDelivery]:
    if isinstance(data, dict) and "files" not in data:
        raise NeedsAttentionError(
            f"unrecognized delivery list shape, top-level keys: {sorted(data)}"
        )
    raw = data if isinstance(data, list) else data.get("files", [])
    deliveries = [
        RemoteDelivery(
            remote_name=entry["name"],
            delivered_at=_delivered_at_from_name(entry["name"]),
            has_content=not entry["name"].lower().endswith(PLACEHOLDER_SUFFIX),
        )
        for entry in raw
        if entry.get("name")
    ]
    deliveries.sort(key=lambda d: d.remote_name)
    return deliveries


class VwGroupDeliverySession:
    """A logged-in session with the VW-group portal; satisfies `core.provider.DeliverySession`.

    Args:
        client: an already logged-in `httpx.AsyncClient`.
        relogin: called to re-authenticate `client` once, if a request comes back `401`
            or `403` (the portal session is short-lived).
        min_interval_s: minimum spacing enforced between two portal API requests.
        sleep: injectable async sleep, used for pacing and rate-limit waits.
        clock: injectable monotonic clock, used for pacing.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        relogin: Callable[[], Awaitable[None]],
        min_interval_s: float = 1.0,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._client = client
        self._relogin = relogin
        self._min_interval_s = min_interval_s
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._clock = clock if clock is not None else time.monotonic
        self._last_request_at: float | None = None

    async def _pace(self) -> None:
        if self._last_request_at is None:
            return
        remaining = self._min_interval_s - (self._clock() - self._last_request_at)
        if remaining > 0:
            await self._sleep(remaining)

    async def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send one request, mapping network failures and 5xx responses to `TransientError`."""
        try:
            resp = await self._client.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        except httpx.TimeoutException as exc:
            raise TransientError(f"timeout contacting the portal ({type(exc).__name__})") from exc
        except httpx.TransportError as exc:
            raise TransientError(
                f"network error contacting the portal ({type(exc).__name__})"
            ) from exc
        if resp.status_code >= 500:
            raise TransientError(f"portal returned {resp.status_code}")
        return resp

    async def _request_with_rate_limit(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        wait = 0.0
        for attempt in range(RATE_LIMIT_MAX_RETRIES + 1):
            await self._pace()
            resp = await self._send(method, url, **kwargs)
            self._last_request_at = self._clock()
            if resp.status_code != 429:
                return resp
            wait = _retry_after_seconds(resp.headers, resp.text)
            if attempt == RATE_LIMIT_MAX_RETRIES or wait > RATE_LIMIT_MAX_WAIT_S:
                raise RateLimitedError(retry_after_s=wait)
            await self._sleep(wait)
        raise RateLimitedError(retry_after_s=wait)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Perform one portal API request, re-logging in once on an expired session."""
        resp = await self._request_with_rate_limit(method, url, **kwargs)
        if resp.status_code in (401, 403):
            await self._relogin()
            resp = await self._request_with_rate_limit(method, url, **kwargs)
            if resp.status_code in (401, 403):
                raise AuthenticationError("portal session expired and re-login did not fix it")
        return resp

    async def list_vehicles(self) -> list[RemoteVehicle]:
        """Return the vehicles linked to the logged-in portal account."""
        resp = await self._request(
            "GET",
            f"{PORTAL_BASE_URL}/proxy_api/consent/me/vehicles",
            params={"viewPosition": "FRONT_LEFT"},
            headers={"Accept": "application/json"},
        )
        return _parse_vehicle_list(_json(resp, "vehicle list"))

    async def list_data_requests(self, vin: str) -> list[RemoteDataRequest]:
        """Return the data requests (`all`, `partial`) the portal resolves for `vin`.

        A dataset kind the portal does not resolve for this vehicle (404 or another 4xx,
        e.g. `400 Invalid identifier provided.`) is skipped, not an error: which kinds exist
        varies per account.
        """
        requests = []
        for kind in DATASET_KINDS:
            resp = await self._request(
                "GET",
                f"{PORTAL_BASE_URL}/proxy_api/euda-apim/datarequest/vehicles/{vin}/metadata/{kind}",
                headers={"Accept": "application/json"},
            )
            if 400 <= resp.status_code < 500:
                continue
            data = _json(resp, f"data request metadata for '{kind}'")
            remote_id = str(data.get("Identifier", "")) if isinstance(data, dict) else ""
            if not remote_id:
                raise ProviderError(f"portal returned no data request identifier for '{kind}'")
            requests.append(RemoteDataRequest(vin=vin, kind=kind, remote_id=remote_id))
        return requests

    async def list_deliveries(self, request: RemoteDataRequest) -> list[RemoteDelivery]:
        """Return the deliveries currently listed for `request`, oldest first."""
        resp = await self._request(
            "GET",
            f"{_delivery_base_url(request.vin, request.remote_id)}/list",
            headers={"Accept": "application/json", "type": request.kind},
        )
        if resp.status_code == 404:
            return []
        return _parse_delivery_list(_json(resp, "delivery list"))

    async def download(self, request: RemoteDataRequest, delivery: RemoteDelivery) -> bytes:
        """Download the raw ZIP bytes of `delivery`, streamed and size-bounded.

        Raises:
            ProviderError: if the download exceeds `MAX_DOWNLOAD_BYTES`.
            AuthenticationError: if the session is still unauthenticated after one re-login.
            RateLimitedError: if the portal keeps answering `429` past the retry budget.
            TransientError: on a timeout, connection failure or 5xx response.
        """
        url = f"{_delivery_base_url(request.vin, request.remote_id)}/download"
        headers = {"filename": delivery.remote_name, "type": request.kind}
        for relogin_attempt in range(2):
            data = await self._stream_once(url, headers)
            if data is not None:
                return data
            if relogin_attempt == 0:
                await self._relogin()
        raise AuthenticationError("portal session expired and re-login did not fix it")

    async def _stream_once(self, url: str, headers: dict[str, str]) -> bytes | None:
        """Download once, respecting pacing and rate limits.

        Returns:
            The downloaded bytes, or `None` if the portal answered `401`/`403` (the caller
            re-logs in and retries).
        """
        wait = 0.0
        for attempt in range(RATE_LIMIT_MAX_RETRIES + 1):
            await self._pace()
            try:
                async with self._client.stream(
                    "GET", url, headers=headers, timeout=REQUEST_TIMEOUT
                ) as resp:
                    self._last_request_at = self._clock()
                    if resp.status_code in (401, 403):
                        return None
                    if resp.status_code == 429:
                        body = (await resp.aread()).decode("utf-8", errors="replace")
                        wait = _retry_after_seconds(resp.headers, body)
                    elif resp.status_code >= 500:
                        raise TransientError(f"portal returned {resp.status_code}")
                    elif 200 <= resp.status_code < 300:
                        return await _read_bounded(resp)
                    else:
                        raise ProviderError(f"portal returned {resp.status_code}")
            except httpx.TimeoutException as exc:
                raise TransientError(
                    f"timeout contacting the portal ({type(exc).__name__})"
                ) from exc
            except httpx.TransportError as exc:
                raise TransientError(
                    f"network error contacting the portal ({type(exc).__name__})"
                ) from exc
            if attempt == RATE_LIMIT_MAX_RETRIES or wait > RATE_LIMIT_MAX_WAIT_S:
                raise RateLimitedError(retry_after_s=wait)
            await self._sleep(wait)
        raise RateLimitedError(retry_after_s=wait)

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
