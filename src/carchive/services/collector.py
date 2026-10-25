"""Collector service: one account login per run, every due data request processed.

Ported behavior from `eu_data_act_sampler.py`, generalized to any `core.provider.Provider`:
download every listed delivery (placeholders included) oldest first, never lose one to the
portal's limited listing window, and turn provider failures into visible, bounded retry
schedules instead of silent gaps.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncConnection

from carchive.core.errors import (
    AuthenticationError,
    NeedsAttentionError,
    ProviderError,
    RateLimitedError,
    TransientError,
)
from carchive.core.models import DataPoint, RemoteDataRequest, RemoteDelivery
from carchive.core.provider import (
    DeliverySession,
    ParseContext,
    PayloadParser,
    Provider,
    ProviderRegistry,
    SignalMapper,
)
from carchive.core.redact import mask_vin, redact
from carchive.core.signals import associate_source_ids
from carchive.storage.db import Database
from carchive.storage.records import DataRequestRecord, VehicleRecord
from carchive.storage.repositories import (
    AccountRepository,
    CollectorRunRepository,
    DataPointRepository,
    DataRequestRepository,
    DeliveryRepository,
    SignalValueRepository,
    VehicleRepository,
)

logger = structlog.get_logger(__name__)

# Minutes of backoff by number of consecutive non-`ok` runs of a data request (1st failure,
# 2nd, ...), capped at the last entry for every failure beyond it.
_BACKOFF_MINUTES = (15, 30, 60, 120, 240, 360)
_NEEDS_ATTENTION_DELAY = timedelta(hours=6)
_JITTER_S = 60.0
_MAX_MESSAGE_LEN = 300


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _backoff_delay(consecutive_failures: int) -> timedelta:
    """Return the backoff delay for the given number of consecutive non-`ok` runs."""
    index = min(max(consecutive_failures, 1), len(_BACKOFF_MINUTES)) - 1
    return timedelta(minutes=_BACKOFF_MINUTES[index])


def _short_message(text: str) -> str:
    """Redact and truncate `text` to fit the `collector_runs.message` column."""
    return redact(text)[:_MAX_MESSAGE_LEN]


def _parser_for(provider: Provider) -> PayloadParser | None:
    """Return `provider`'s payload parser, or `None` if it has not implemented one yet."""
    try:
        return provider.parser()
    except NotImplementedError:
        return None


def _mapper_for(provider: Provider) -> SignalMapper | None:
    """Return `provider`'s signal mapper, or `None` if it has not implemented one yet."""
    try:
        return provider.mapper()
    except NotImplementedError:
        return None


@dataclass(frozen=True, slots=True)
class RequestRunResult:
    """The outcome of collecting one data request during an account run."""

    data_request_id: UUID
    outcome: str
    downloaded: int


@dataclass(frozen=True, slots=True)
class AccountRunResult:
    """The outcome of one account run: at most one login, then every due request.

    Attributes:
        login_outcome: `"ok"` if a session was opened (or no login was attempted because
            credentials were missing), `"login_failed"` otherwise.
        request_results: one entry per data request that was actually processed; empty if
            the login itself failed.
    """

    account_id: UUID
    login_outcome: str
    request_results: tuple[RequestRunResult, ...]


class Collector:
    """Collects due data requests for one account per `run_account` call.

    Args:
        db: the database to read and write through.
        registry: looks up the `Provider` for an account's `provider_id`.
        credentials_for: resolves an account's `credential_ref` to the credentials its
            provider expects; raises `KeyError` if the reference is unknown.
        max_downloads: maximum number of not-yet-stored deliveries downloaded per data
            request per run, to bound catch-up after an outage.
        interval_s: polling interval assigned to newly discovered data requests, and
            re-applied to existing ones on every discovery pass (so a changed setting takes
            effect without manual intervention).
        clock: returns the current UTC time; overridable for tests.
        rng: source of the jitter added to successful requests' next due time.
    """

    def __init__(
        self,
        db: Database,
        registry: ProviderRegistry,
        credentials_for: Callable[[str], Mapping[str, str]],
        *,
        max_downloads: int = 50,
        interval_s: int = 900,
        clock: Callable[[], datetime] = _utcnow,
        rng: random.Random | None = None,
    ) -> None:
        self._db = db
        self._registry = registry
        self._credentials_for = credentials_for
        self._max_downloads = max_downloads
        self._interval_s = interval_s
        self._clock = clock
        self._rng = rng if rng is not None else random.Random()
        self._accounts = AccountRepository()
        self._vehicles = VehicleRepository()
        self._requests = DataRequestRepository()
        self._deliveries = DeliveryRepository()
        self._data_points = DataPointRepository()
        self._signal_values = SignalValueRepository()
        self._runs = CollectorRunRepository()

    async def run_account(self, account_id: UUID) -> AccountRunResult:
        """Run one collection pass for `account_id`: at most one login, then due requests.

        Args:
            account_id: the account to collect for.

        Returns:
            The outcome of the login and of every data request that was processed.

        Raises:
            ValueError: if no account with `account_id` exists.
        """
        now = self._clock()
        async with self._db.read() as conn:
            account = await self._accounts.get(conn, account_id)
        if account is None:
            raise ValueError(f"no account with id {account_id}")

        try:
            credentials = self._credentials_for(account.credential_ref)
        except KeyError:
            reason = f"no credentials found for reference {account.credential_ref!r}"
            await self._record_login_failure(account_id, now, reason)
            await self._set_account_state(account_id, "needs_attention", reason)
            return AccountRunResult(account_id, "login_failed", ())

        provider = self._registry.get(account.provider_id)

        try:
            session = await provider.open_delivery_session(account.brand, credentials)
        except (AuthenticationError, NeedsAttentionError) as exc:
            reason = _short_message(str(exc))
            await self._record_login_failure(account_id, now, reason)
            await self._set_account_state(account_id, "needs_attention", reason)
            await self._delay_all_requests(account_id, now + _NEEDS_ATTENTION_DELAY)
            return AccountRunResult(account_id, "login_failed", ())
        except TransientError as exc:
            reason = _short_message(str(exc))
            await self._record_login_failure(account_id, now, reason)
            await self._backoff_all_requests(account_id, now)
            return AccountRunResult(account_id, "login_failed", ())

        results: list[RequestRunResult] = []
        try:
            if account.state == "needs_attention":
                await self._set_account_state(account_id, "active", None)

            parser = _parser_for(provider)
            mapper = _mapper_for(provider)

            async with self._db.read() as conn:
                active_vehicles = await self._vehicles.list_active_for_account(conn, account_id)
            vehicle_by_id = {vehicle.id: vehicle for vehicle in active_vehicles}

            for vehicle in active_vehicles:
                await self._discover_requests(session, account_id, vehicle)

            async with self._db.read() as conn:
                due = await self._requests.list_due(conn, now)
            due_for_account = sorted(
                (request for request in due if request.vehicle_id in vehicle_by_id),
                key=lambda request: (request.vehicle_id, request.kind),
            )

            for request in due_for_account:
                vehicle = vehicle_by_id[request.vehicle_id]
                remote_request = RemoteDataRequest(
                    vin=vehicle.vin, kind=request.kind, remote_id=request.remote_id or ""
                )
                try:
                    result = await self._run_one_request(
                        session,
                        provider,
                        parser,
                        mapper,
                        account_id,
                        request,
                        vehicle,
                        remote_request,
                    )
                except RateLimitedError as exc:
                    await self._handle_rate_limited(account_id, request, exc)
                    results.append(RequestRunResult(request.id, "rate_limited", 0))
                    break
                except NeedsAttentionError as exc:
                    await self._handle_request_needs_attention(account_id, request, exc)
                    results.append(RequestRunResult(request.id, "error", 0))
                except ProviderError as exc:
                    await self._handle_request_error(account_id, request, exc)
                    results.append(RequestRunResult(request.id, "error", 0))
                else:
                    results.append(result)
        finally:
            await session.aclose()

        return AccountRunResult(account_id, "ok", tuple(results))

    async def _discover_requests(
        self, session: DeliverySession, account_id: UUID, vehicle: VehicleRecord
    ) -> None:
        """Resolve and upsert `vehicle`'s data requests; records and skips a non-fatal error.

        Raises:
            RateLimitedError: propagated so the caller aborts the whole account run.
        """
        started_at = self._clock()
        try:
            remote_requests = await session.list_data_requests(vehicle.vin)
        except RateLimitedError:
            raise
        except ProviderError as exc:
            message = _short_message(
                f"data request discovery failed for {mask_vin(vehicle.vin)}: {exc}"
            )
            logger.warning("collector.discovery_failed", account_id=str(account_id))
            async with self._db.write() as conn:
                await self._runs.add(
                    conn,
                    account_id=account_id,
                    data_request_id=None,
                    started_at=started_at,
                    finished_at=self._clock(),
                    outcome="error",
                    listed=None,
                    placeholders=None,
                    downloaded=None,
                    with_content=None,
                    pending=None,
                    oldest_pending_age_s=None,
                    message=message,
                )
            return

        async with self._db.write() as conn:
            for remote in remote_requests:
                await self._requests.upsert(
                    conn,
                    vehicle_id=vehicle.id,
                    kind=remote.kind,
                    remote_id=remote.remote_id,
                    interval_s=self._interval_s,
                )

    async def _run_one_request(
        self,
        session: DeliverySession,
        provider: Provider,
        parser: PayloadParser | None,
        mapper: SignalMapper | None,
        account_id: UUID,
        request: DataRequestRecord,
        vehicle: VehicleRecord,
        remote_request: RemoteDataRequest,
    ) -> RequestRunResult:
        started_at = self._clock()
        listed = await session.list_deliveries(remote_request)
        placeholders = sum(1 for delivery in listed if not delivery.has_content)

        to_fetch: list[RemoteDelivery] = []
        for delivery in listed:
            async with self._db.read() as conn:
                already_stored = await self._deliveries.exists(
                    conn, request.id, delivery.remote_name
                )
            if not already_stored:
                to_fetch.append(delivery)
        to_fetch.sort(key=lambda delivery: delivery.remote_name)

        downloaded = 0
        with_content = 0
        for delivery in to_fetch[: self._max_downloads]:
            payload = await session.download(remote_request, delivery)
            await self._store_delivery(parser, mapper, request, vehicle, delivery, payload)
            downloaded += 1
            if delivery.has_content:
                with_content += 1

        still_pending = to_fetch[downloaded:]
        pending = len(still_pending)
        oldest_pending_age_s = self._oldest_pending_age_s(still_pending, started_at)
        self._warn_if_at_risk(account_id, request, provider, pending, oldest_pending_age_s)

        finished_at = self._clock()
        next_due = finished_at + timedelta(
            seconds=request.interval_s + self._rng.uniform(-_JITTER_S, _JITTER_S)
        )
        async with self._db.write() as conn:
            await self._runs.add(
                conn,
                account_id=account_id,
                data_request_id=request.id,
                started_at=started_at,
                finished_at=finished_at,
                outcome="ok",
                listed=len(listed),
                placeholders=placeholders,
                downloaded=downloaded,
                with_content=with_content,
                pending=pending,
                oldest_pending_age_s=oldest_pending_age_s,
                message=None,
            )
            await self._requests.mark_success(conn, request.id, finished_at)
            await self._requests.set_next_due(conn, request.id, next_due)
            if request.state != "active":
                await self._requests.set_state(conn, request.id, "active", None)

        return RequestRunResult(request.id, "ok", downloaded)

    async def _store_delivery(
        self,
        parser: PayloadParser | None,
        mapper: SignalMapper | None,
        request: DataRequestRecord,
        vehicle: VehicleRecord,
        delivery: RemoteDelivery,
        payload: bytes,
    ) -> None:
        """Store one delivery and, if a parser is available, its data points, atomically.

        Parsing runs in a worker thread and completes before the write transaction opens, so
        a large payload never blocks the event loop (and every other coroutine sharing it,
        including the web server) for the whole parse, nor holds the single writer lock while
        doing CPU-bound work unrelated to the database.
        """
        sha256 = hashlib.sha256(payload).hexdigest()
        parse_state = "empty" if not delivery.has_content else "pending"
        fetched_at = self._clock()

        points: list[DataPoint] | None = None
        parse_failed = False
        if delivery.has_content and parser is not None:
            context = ParseContext(
                vin=vehicle.vin,
                request_kind=request.kind,
                delivered_at=delivery.delivered_at,
                fetched_at=fetched_at,
            )
            try:
                points = await asyncio.to_thread(lambda: list(parser.parse(payload, context)))
            except Exception as exc:  # a broken payload must never abort the whole run
                logger.warning(
                    "collector.parse_failed",
                    vin=mask_vin(vehicle.vin),
                    data_request_id=str(request.id),
                    error=_short_message(str(exc)),
                )
                parse_failed = True

        async with self._db.write() as conn:
            delivery_id = await self._deliveries.add(
                conn,
                data_request_id=request.id,
                import_batch_id=None,
                remote_name=delivery.remote_name,
                delivered_at=delivery.delivered_at,
                fetched_at=fetched_at,
                has_content=delivery.has_content,
                sha256=sha256,
                size_bytes=len(payload),
                parse_state=parse_state,
                parser_version=None,
                raw_payload=payload,
            )
            if parse_failed:
                await self._deliveries.set_parse_state(conn, delivery_id, "failed")
            elif points is not None:
                result = await self._data_points.upsert_many(
                    conn,
                    vehicle_id=vehicle.id,
                    delivery_id=delivery_id,
                    points=points,
                    seen_at=fetched_at,
                )
                if mapper is not None and result.new_points:
                    await self._map_and_store_signals(conn, vehicle.id, mapper, result.new_points)
                # `points` is only ever set once a parser has run, so one must exist here.
                parser_version = parser.parser_version if parser is not None else None
                await self._deliveries.set_parse_state(conn, delivery_id, "parsed", parser_version)

    async def _map_and_store_signals(
        self,
        conn: AsyncConnection,
        vehicle_id: UUID,
        mapper: SignalMapper,
        new_points: Sequence[tuple[UUID, DataPoint]],
    ) -> None:
        """Map newly stored points to signal values and store them, never losing the delivery.

        A broken mapper must not lose the data points it failed to interpret: the points
        themselves are already committed by the caller's transaction, only the derived
        signal values are skipped on failure.
        """
        try:
            values = list(mapper.map([point for _, point in new_points]))
            paired = associate_source_ids(new_points, values)
            await self._signal_values.add_many(
                conn, vehicle_id=vehicle_id, values_with_source_ids=paired
            )
        except Exception as exc:  # a broken mapper must never abort the whole run
            logger.warning("collector.mapping_failed", error=_short_message(str(exc)))

    def _oldest_pending_age_s(
        self, pending: Sequence[RemoteDelivery], now: datetime
    ) -> float | None:
        ages = [
            (now - delivery.delivered_at).total_seconds()
            for delivery in pending
            if delivery.delivered_at is not None
        ]
        return max(ages) if ages else None

    def _warn_if_at_risk(
        self,
        account_id: UUID,
        request: DataRequestRecord,
        provider: Provider,
        pending: int,
        oldest_pending_age_s: float | None,
    ) -> None:
        """Log structured warnings when a request nears the portal's listing/retention limits."""
        capabilities = provider.capabilities
        backlog_threshold = (
            capabilities.max_listed_files - 5 if capabilities.max_listed_files else 25
        )
        if pending >= backlog_threshold:
            logger.warning(
                "collector.backlog_at_risk",
                account_id=str(account_id),
                data_request_id=str(request.id),
                pending=pending,
                threshold=backlog_threshold,
            )

        retention_threshold_days = (
            capabilities.retention_days - 2 if capabilities.retention_days else 5
        )
        if (
            oldest_pending_age_s is not None
            and oldest_pending_age_s >= retention_threshold_days * 86400
        ):
            logger.warning(
                "collector.retention_at_risk",
                account_id=str(account_id),
                data_request_id=str(request.id),
                oldest_pending_age_s=oldest_pending_age_s,
                threshold_days=retention_threshold_days,
            )

    async def _record_login_failure(
        self, account_id: UUID, started_at: datetime, reason: str
    ) -> None:
        finished_at = self._clock()
        async with self._db.write() as conn:
            await self._runs.add(
                conn,
                account_id=account_id,
                data_request_id=None,
                started_at=started_at,
                finished_at=finished_at,
                outcome="login_failed",
                listed=None,
                placeholders=None,
                downloaded=None,
                with_content=None,
                pending=None,
                oldest_pending_age_s=None,
                message=reason,
            )

    async def _set_account_state(
        self, account_id: UUID, state: str, state_reason: str | None
    ) -> None:
        async with self._db.write() as conn:
            await self._accounts.set_state(conn, account_id, state, state_reason)

    async def _delay_all_requests(self, account_id: UUID, next_due_at: datetime) -> None:
        async with self._db.write() as conn:
            vehicles = await self._vehicles.list_for_account(conn, account_id)
            for vehicle in vehicles:
                for request in await self._requests.list_for_vehicle(conn, vehicle.id):
                    await self._requests.set_next_due(conn, request.id, next_due_at)

    async def _backoff_all_requests(self, account_id: UUID, now: datetime) -> None:
        async with self._db.write() as conn:
            vehicles = await self._vehicles.list_for_account(conn, account_id)
            for vehicle in vehicles:
                for request in await self._requests.list_for_vehicle(conn, vehicle.id):
                    failures = await self._runs.count_consecutive_non_ok(conn, request.id)
                    await self._requests.set_next_due(
                        conn, request.id, now + _backoff_delay(failures)
                    )

    async def _handle_rate_limited(
        self, account_id: UUID, request: DataRequestRecord, exc: RateLimitedError
    ) -> None:
        started_at = self._clock()
        reason = _short_message(str(exc))
        async with self._db.write() as conn:
            await self._runs.add(
                conn,
                account_id=account_id,
                data_request_id=request.id,
                started_at=started_at,
                finished_at=started_at,
                outcome="rate_limited",
                listed=None,
                placeholders=None,
                downloaded=None,
                with_content=None,
                pending=None,
                oldest_pending_age_s=None,
                message=reason,
            )
            next_due = started_at + timedelta(
                seconds=max(exc.retry_after_s or 0.0, request.interval_s)
            )
            await self._requests.set_next_due(conn, request.id, next_due)

    async def _handle_request_needs_attention(
        self, account_id: UUID, request: DataRequestRecord, exc: NeedsAttentionError
    ) -> None:
        now = self._clock()
        reason = _short_message(exc.reason)
        logger.warning(
            "collector.request_needs_attention",
            data_request_id=str(request.id),
            account_id=str(account_id),
            reason=reason,
        )
        async with self._db.write() as conn:
            await self._requests.set_state(conn, request.id, "needs_attention", reason)
            await self._runs.add(
                conn,
                account_id=account_id,
                data_request_id=request.id,
                started_at=now,
                finished_at=now,
                outcome="error",
                listed=None,
                placeholders=None,
                downloaded=None,
                with_content=None,
                pending=None,
                oldest_pending_age_s=None,
                message=reason,
            )
            await self._requests.set_next_due(conn, request.id, now + _NEEDS_ATTENTION_DELAY)

    async def _handle_request_error(
        self, account_id: UUID, request: DataRequestRecord, exc: ProviderError
    ) -> None:
        now = self._clock()
        reason = _short_message(str(exc))
        async with self._db.write() as conn:
            await self._runs.add(
                conn,
                account_id=account_id,
                data_request_id=request.id,
                started_at=now,
                finished_at=now,
                outcome="error",
                listed=None,
                placeholders=None,
                downloaded=None,
                with_content=None,
                pending=None,
                oldest_pending_age_s=None,
                message=reason,
            )
            failures = await self._runs.count_consecutive_non_ok(conn, request.id)
            await self._requests.set_next_due(conn, request.id, now + _backoff_delay(failures))
