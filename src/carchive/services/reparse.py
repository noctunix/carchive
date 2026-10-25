"""Re-parsing: pending deliveries, and signal values for a new mapping version.

A delivery stays `pending` when it was stored before its provider had a parser (or a parser
run failed to even start); `Reparser.parse_pending` catches it up without re-downloading
anything, using the `raw_payload` already on disk. `Reparser.remap` recomputes
`signal_values` from already-stored `data_points` when a provider's `SignalMapper` gets a
new `mapping_version`, so a mapping fix never requires re-fetching history.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncConnection

from carchive.core.models import DataPoint
from carchive.core.provider import ParseContext, PayloadParser, Provider, ProviderRegistry
from carchive.core.redact import mask_vin, redact
from carchive.core.signals import associate_source_ids
from carchive.storage.db import Database
from carchive.storage.records import UpsertResult
from carchive.storage.repositories import (
    AccountRepository,
    DataPointRepository,
    DeliveryRepository,
    SignalValueRepository,
    VehicleRepository,
)

logger = structlog.get_logger(__name__)

_MAX_MESSAGE_LEN = 300


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _short_message(text: str) -> str:
    """Redact and truncate `text`, matching `services.collector`'s message handling."""
    return redact(text)[:_MAX_MESSAGE_LEN]


def _parse_to_list(parser: PayloadParser, payload: bytes, context: ParseContext) -> list[DataPoint]:
    """Run `parser.parse` and materialize its result.

    A plain function binds its arguments by value, unlike a lambda defined inside a loop,
    which would close over the loop variable itself rather than the value it held then.
    """
    return list(parser.parse(payload, context))


@dataclass(frozen=True, slots=True)
class ReparseResult:
    """Outcome of one `Reparser.parse_pending` run."""

    parsed: int
    failed: int


@dataclass(frozen=True, slots=True)
class RemapResult:
    """Outcome of one `Reparser.remap` run."""

    vehicles: int
    values_written: int


class Reparser:
    """Re-parses pending deliveries and recomputes signal values for stored data points.

    Args:
        db: the database to read and write through.
        registry: looks up the `Provider` that owns a delivery's or vehicle's account.
        clock: returns the current UTC time; overridable for tests.
    """

    def __init__(
        self,
        db: Database,
        registry: ProviderRegistry,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._db = db
        self._registry = registry
        self._clock = clock
        self._deliveries = DeliveryRepository()
        self._data_points = DataPointRepository()
        self._signal_values = SignalValueRepository()
        self._vehicles = VehicleRepository()
        self._accounts = AccountRepository()

    async def parse_pending(self, limit: int | None = None) -> ReparseResult:
        """Parse every delivery still at `parse_state = 'pending'`, oldest first.

        Each delivery is parsed and stored in isolation: a failure on one (unknown
        provider, broken payload, parse error) marks only that delivery `failed` and moves
        on, the same error handling the collector itself applies to a fresh download.

        Args:
            limit: the maximum number of deliveries to process, or `None` for all of them.

        Returns:
            How many deliveries were parsed successfully versus marked `failed`.
        """
        async with self._db.read() as conn:
            pending = await self._deliveries.list_pending(conn, limit=limit)

        parsed = 0
        failed = 0
        for delivery in pending:
            try:
                provider = self._registry.get(delivery.provider_id)
            except KeyError:
                logger.warning("reparse.unknown_provider", provider_id=delivery.provider_id)
                await self._mark_failed(delivery.delivery_id)
                failed += 1
                continue

            try:
                parser = provider.parser()
            except NotImplementedError:
                # still no parser for this provider; leave it pending for a later run
                continue

            payload = delivery.raw_payload
            if payload is None:
                logger.warning(
                    "reparse.no_raw_payload",
                    vin=mask_vin(delivery.vin),
                    delivery_id=str(delivery.delivery_id),
                )
                await self._mark_failed(delivery.delivery_id)
                failed += 1
                continue

            context = ParseContext(
                vin=delivery.vin,
                request_kind=delivery.request_kind,
                delivered_at=delivery.delivered_at,
                fetched_at=delivery.fetched_at,
            )
            try:
                points = await asyncio.to_thread(
                    functools.partial(_parse_to_list, parser, payload, context)
                )
            except Exception as exc:  # a broken payload must never abort the whole batch
                logger.warning(
                    "reparse.parse_failed",
                    vin=mask_vin(delivery.vin),
                    error=_short_message(str(exc)),
                )
                await self._mark_failed(delivery.delivery_id)
                failed += 1
                continue

            seen_at = self._clock()
            async with self._db.write() as conn:
                result = await self._data_points.upsert_many(
                    conn,
                    vehicle_id=delivery.vehicle_id,
                    delivery_id=delivery.delivery_id,
                    points=points,
                    seen_at=seen_at,
                )
                if result.new_points:
                    await self._map_and_store_signals(conn, provider, delivery.vehicle_id, result)
                await self._deliveries.set_parse_state(
                    conn, delivery.delivery_id, "parsed", parser.parser_version
                )
            parsed += 1

        return ReparseResult(parsed=parsed, failed=failed)

    async def _map_and_store_signals(
        self,
        conn: AsyncConnection,
        provider: Provider,
        vehicle_id: UUID,
        result: UpsertResult,
    ) -> None:
        """Map newly stored points to signal values; a mapping failure never loses them."""
        try:
            mapper = provider.mapper()
        except NotImplementedError:
            return
        try:
            values = list(mapper.map([point for _, point in result.new_points]))
            paired = associate_source_ids(result.new_points, values)
            await self._signal_values.add_many(
                conn, vehicle_id=vehicle_id, values_with_source_ids=paired
            )
        except Exception as exc:  # a broken mapper must never abort the whole batch
            logger.warning("reparse.mapping_failed", error=_short_message(str(exc)))

    async def _mark_failed(self, delivery_id: UUID) -> None:
        async with self._db.write() as conn:
            await self._deliveries.set_parse_state(conn, delivery_id, "failed")

    async def remap(self, mapping_version: str) -> RemapResult:
        """Recompute `signal_values` from stored `data_points` for `mapping_version`.

        Only touches vehicles whose provider's currently registered `SignalMapper` reports
        exactly `mapping_version`; a vehicle whose provider has since moved to a different
        version is skipped, since remapping it would silently mix mapping versions.

        Args:
            mapping_version: the mapping version to (re)compute values for.

        Returns:
            How many vehicles were processed and how many new signal value rows were
            written; already-present rows (same source point, signal and mapping version)
            are left untouched, so running this twice in a row writes nothing the second
            time.
        """
        async with self._db.read() as conn:
            all_vehicles = await self._vehicles.list_all(conn)

        vehicles_processed = 0
        values_written = 0
        for vehicle in all_vehicles:
            async with self._db.read() as conn:
                account = await self._accounts.get(conn, vehicle.account_id)
            if account is None:
                continue
            try:
                provider = self._registry.get(account.provider_id)
            except KeyError:
                continue
            try:
                mapper = provider.mapper()
            except NotImplementedError:
                continue
            if mapper.mapping_version != mapping_version:
                continue

            async with self._db.read() as conn:
                points = await self._data_points.list_for_vehicle(conn, vehicle.id)
            if not points:
                continue

            values = list(mapper.map([point for _, point in points]))
            paired = associate_source_ids(points, values)
            async with self._db.write() as conn:
                written = await self._signal_values.add_many(
                    conn, vehicle_id=vehicle.id, values_with_source_ids=paired
                )
            vehicles_processed += 1
            values_written += written

        return RemapResult(vehicles=vehicles_processed, values_written=values_written)
