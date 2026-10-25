"""Deliveries: what arrived, when, and whether it carried any new values.

A delivery's values are not stored on the delivery itself: `data_points` only keeps a
canonical row per distinct value and credits it to the delivery that first reported it
(`first_delivery_id`). Showing a later delivery's full content therefore means re-parsing
its still-stored `raw_payload` and classifying each value by its `dedup_key` against what is
already on record, the same way `services.reparse.Reparser` catches up a pending delivery.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import structlog

from carchive.core.models import DataPoint
from carchive.core.provider import ParseContext, PayloadParser, ProviderRegistry
from carchive.core.redact import mask_vin, redact
from carchive.storage.db import Database
from carchive.storage.dedup import dedup_key as compute_dedup_key
from carchive.storage.records import DeliveryDetailRecord, DeliverySummaryRecord
from carchive.storage.repositories import (
    AccountRepository,
    DataPointRepository,
    DeliveryRepository,
    VehicleRepository,
)

logger = structlog.get_logger(__name__)

_LIST_PAGE_SIZE = 50
_VALUE_PAGE_SIZE = 200
_MAX_QUERY_LEN = 200
_MAX_MESSAGE_LEN = 300


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _short_message(text: str) -> str:
    """Redact and truncate `text`, matching `services.reparse`'s message handling."""
    return redact(text)[:_MAX_MESSAGE_LEN]


def _parse_to_list(parser: PayloadParser, payload: bytes, context: ParseContext) -> list[DataPoint]:
    """Run `parser.parse` and materialize its result in the worker thread, not the caller."""
    return list(parser.parse(payload, context))


@dataclass(frozen=True, slots=True)
class DeliveryRow:
    """One row of the deliveries list, with the delivery's age alongside its timestamp."""

    id: UUID
    kind: str
    source: str
    remote_name: str
    delivered_at: datetime | None
    delivered_age_s: float | None
    fetched_at: datetime
    has_content: bool
    size_bytes: int
    parse_state: str
    raw_available: bool
    new_point_count: int
    new_captured_min: datetime | None
    new_captured_max: datetime | None


@dataclass(frozen=True, slots=True)
class DeliveryListPage:
    """One page of a vehicle's deliveries, newest-delivered first."""

    items: tuple[DeliveryRow, ...]
    total: int
    page: int
    total_pages: int


@dataclass(frozen=True, slots=True)
class DeliveryValueRow:
    """One value found in a delivery's payload, classified against what was already known.

    Attributes:
        status: `"new"` if this delivery is the value's first source, `"known"` if some
            earlier delivery already reported it.
        first_seen_at: when this value was first stored, for either status.
        first_delivery_id: the delivery that first reported this value; set only for
            `"known"` rows (a `"new"` row's first delivery is the one being shown).
    """

    key: str
    field_name: str
    value_raw: str | None
    captured_at: datetime | None
    captured_at_quality: str
    status: str
    first_seen_at: datetime | None
    first_delivery_id: UUID | None


@dataclass(frozen=True, slots=True)
class DeliverySummaryStats:
    """Aggregate counts and timing for the values a delivery's detail page covers.

    Attributes:
        known_values: how many values were already known before this delivery, or `None`
            if unknown because the delivery could not be re-parsed (see `DeliveryDetail.degraded`).
        captured_max_age_s: `captured_max`'s age relative to the delivery's `delivered_at`
            (or `fetched_at` if `delivered_at` is unknown), or `None` if `captured_max` is.
    """

    total_values: int
    new_values: int
    known_values: int | None
    captured_min: datetime | None
    captured_max: datetime | None
    captured_max_age_s: float | None


@dataclass(frozen=True, slots=True)
class DeliveryDetail:
    """Everything the delivery detail page renders.

    Attributes:
        degraded: `True` if the value list could only be built from what `data_points`
            already credits to this delivery, rather than from a fresh re-parse; the
            search and "only new" filters then have no effect, since only this delivery's
            own new values are visible either way.
        limited_reason: why the detail is degraded: `"placeholder"` (the portal delivered
            no content), `"purged"` (raw payload no longer stored), `"no_parser"` or
            `"parse_failed"`; `None` if not degraded.
    """

    id: UUID
    vehicle_id: UUID
    kind: str
    source: str
    remote_name: str
    delivered_at: datetime | None
    fetched_at: datetime
    has_content: bool
    size_bytes: int
    parse_state: str
    raw_available: bool
    summary: DeliverySummaryStats
    values: tuple[DeliveryValueRow, ...]
    page: int
    total_pages: int
    degraded: bool
    limited_reason: str | None = None


def _value_sort_key(row: DeliveryValueRow) -> tuple[bool, float, str]:
    """Order values newest-captured first, undated values last, field name breaking ties."""
    has_time = row.captured_at is not None
    rank = -row.captured_at.timestamp() if has_time and row.captured_at is not None else 0.0
    return (not has_time, rank, row.field_name)


class DeliveryBrowser:
    """Builds the deliveries list and a delivery's classified value detail.

    Args:
        db: the database to read deliveries and data points from.
        registry: looks up a vehicle's provider to re-parse a delivery's raw payload.
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
        self._vehicles = VehicleRepository()
        self._accounts = AccountRepository()
        self._deliveries = DeliveryRepository()
        self._data_points = DataPointRepository()

    async def list(self, vehicle_id: UUID, *, page: int = 1) -> DeliveryListPage | None:
        """Build the paginated deliveries list for `vehicle_id`.

        Args:
            vehicle_id: the vehicle to list deliveries for.
            page: the 1-based page of results to show.

        Returns:
            The matching page, or `None` if `vehicle_id` does not exist.
        """
        page = max(page, 1)
        async with self._db.read() as conn:
            vehicle = await self._vehicles.get(conn, vehicle_id)
            if vehicle is None:
                return None
            offset = (page - 1) * _LIST_PAGE_SIZE
            records, total = await self._deliveries.list_for_vehicle(
                conn, vehicle_id, limit=_LIST_PAGE_SIZE, offset=offset
            )

        now = self._clock()
        items = tuple(self._row(record, now) for record in records)
        total_pages = max(1, (total + _LIST_PAGE_SIZE - 1) // _LIST_PAGE_SIZE)
        return DeliveryListPage(items=items, total=total, page=page, total_pages=total_pages)

    def _row(self, record: DeliverySummaryRecord, now: datetime) -> DeliveryRow:
        age = (now - record.delivered_at).total_seconds() if record.delivered_at else None
        return DeliveryRow(
            id=record.id,
            kind=record.kind,
            source=record.source,
            remote_name=record.remote_name,
            delivered_at=record.delivered_at,
            delivered_age_s=age,
            fetched_at=record.fetched_at,
            has_content=record.has_content,
            size_bytes=record.size_bytes,
            parse_state=record.parse_state,
            raw_available=record.raw_available,
            new_point_count=record.new_point_count,
            new_captured_min=record.new_captured_min,
            new_captured_max=record.new_captured_max,
        )

    async def detail(
        self, delivery_id: UUID, *, only_new: bool, query: str, page: int
    ) -> DeliveryDetail | None:
        """Build the classified value detail for one delivery.

        Args:
            delivery_id: the delivery to show.
            only_new: if `True`, show only values this delivery was the first to report.
            query: a case-insensitive substring filter over the field name, capped at
                `_MAX_QUERY_LEN` characters.
            page: the 1-based page of values to show.

        Returns:
            The delivery's detail, or `None` if `delivery_id` does not exist.
        """
        query = query.strip()[:_MAX_QUERY_LEN]
        page = max(page, 1)

        async with self._db.read() as conn:
            record = await self._deliveries.get_detail(conn, delivery_id)
        if record is None:
            return None

        if not record.has_content:
            reason = "placeholder"
        elif not record.raw_available:
            reason = "purged"
        else:
            fresh = await self._detail_from_raw(record, only_new=only_new, query=query, page=page)
            if isinstance(fresh, DeliveryDetail):
                return fresh
            reason = fresh

        return await self._detail_from_stored_points(record, page=page, reason=reason)

    async def _detail_from_raw(
        self, record: DeliveryDetailRecord, *, only_new: bool, query: str, page: int
    ) -> DeliveryDetail | str:
        """Re-parse `record`'s raw payload and classify every value in it.

        Returns:
            The full detail, or the `DeliveryDetail.limited_reason` why it could not be
            built (the caller then falls back to the values already on record).
        """
        async with self._db.read() as conn:
            vehicle = await self._vehicles.get(conn, record.vehicle_id)
            account = await self._accounts.get(conn, vehicle.account_id) if vehicle else None
            payload = await self._deliveries.get_raw_payload(conn, record.id)

        if payload is None:
            # Purged concurrently, between `get_detail` and this read.
            return "purged"
        if vehicle is None or account is None:
            logger.warning("deliveries.orphan_delivery", delivery_id=str(record.id))
            return "no_parser"

        try:
            provider = self._registry.get(account.provider_id)
            parser = provider.parser()
        except (KeyError, NotImplementedError) as exc:
            logger.info(
                "deliveries.no_parser", provider_id=account.provider_id, error=redact(str(exc))
            )
            return "no_parser"

        context = ParseContext(
            vin=vehicle.vin,
            request_kind=record.kind,
            delivered_at=record.delivered_at,
            fetched_at=record.fetched_at,
        )
        try:
            points = await asyncio.to_thread(
                functools.partial(_parse_to_list, parser, payload, context)
            )
        except Exception as exc:  # a broken payload must never crash the detail page
            logger.warning(
                "deliveries.parse_failed", vin=mask_vin(vehicle.vin), error=_short_message(str(exc))
            )
            return "parse_failed"

        keys = [
            compute_dedup_key(point.key, point.field_name, point.captured_at, point.value_raw)
            for point in points
        ]
        async with self._db.read() as conn:
            first_seen = await self._data_points.first_seen_by_dedup_keys(
                conn, record.vehicle_id, keys
            )

        rows = [
            self._classify(point, key, record.id, first_seen)
            for point, key in zip(points, keys, strict=True)
        ]
        summary = self._summarize(rows, record)

        filtered = rows
        if query:
            needle = query.lower()
            filtered = [row for row in filtered if needle in row.field_name.lower()]
        if only_new:
            filtered = [row for row in filtered if row.status == "new"]
        filtered.sort(key=_value_sort_key)

        total = len(filtered)
        total_pages = max(1, (total + _VALUE_PAGE_SIZE - 1) // _VALUE_PAGE_SIZE)
        page = min(page, total_pages)
        offset = (page - 1) * _VALUE_PAGE_SIZE
        page_rows = tuple(filtered[offset : offset + _VALUE_PAGE_SIZE])

        return DeliveryDetail(
            id=record.id,
            vehicle_id=record.vehicle_id,
            kind=record.kind,
            source=record.source,
            remote_name=record.remote_name,
            delivered_at=record.delivered_at,
            fetched_at=record.fetched_at,
            has_content=record.has_content,
            size_bytes=record.size_bytes,
            parse_state=record.parse_state,
            raw_available=record.raw_available,
            summary=summary,
            values=page_rows,
            page=page,
            total_pages=total_pages,
            degraded=False,
        )

    def _classify(
        self,
        point: DataPoint,
        dedup: str,
        delivery_id: UUID,
        first_seen: dict[str, tuple[UUID, datetime]],
    ) -> DeliveryValueRow:
        seen = first_seen.get(dedup)
        if seen is None:
            # Not found at all is unexpected for a successfully parsed delivery (every point
            # should already be in `data_points`); fail closed by calling it new rather than
            # claiming knowledge the database does not actually have.
            status, first_seen_at, first_delivery_id = "new", None, None
        elif seen[0] == delivery_id:
            status, first_seen_at, first_delivery_id = "new", seen[1], None
        else:
            status, first_seen_at, first_delivery_id = "known", seen[1], seen[0]
        return DeliveryValueRow(
            key=point.key,
            field_name=point.field_name,
            value_raw=point.value_raw,
            captured_at=point.captured_at,
            captured_at_quality=str(point.captured_at_quality),
            status=status,
            first_seen_at=first_seen_at,
            first_delivery_id=first_delivery_id,
        )

    def _summarize(
        self, rows: Sequence[DeliveryValueRow], record: DeliveryDetailRecord
    ) -> DeliverySummaryStats:
        total = len(rows)
        new = sum(1 for row in rows if row.status == "new")
        valid_times = [
            row.captured_at
            for row in rows
            if row.captured_at is not None and row.captured_at_quality != "invalid"
        ]
        captured_min = min(valid_times) if valid_times else None
        captured_max = max(valid_times) if valid_times else None
        reference = record.delivered_at or record.fetched_at
        age = (reference - captured_max).total_seconds() if captured_max is not None else None
        return DeliverySummaryStats(
            total_values=total,
            new_values=new,
            known_values=total - new,
            captured_min=captured_min,
            captured_max=captured_max,
            captured_max_age_s=age,
        )

    async def _detail_from_stored_points(
        self, record: DeliveryDetailRecord, *, page: int, reason: str
    ) -> DeliveryDetail:
        offset = (page - 1) * _VALUE_PAGE_SIZE
        async with self._db.read() as conn:
            stored, total = await self._data_points.list_first_seen_in_delivery(
                conn, record.id, limit=_VALUE_PAGE_SIZE, offset=offset
            )
        total_pages = max(1, (total + _VALUE_PAGE_SIZE - 1) // _VALUE_PAGE_SIZE)
        page = min(page, total_pages)

        rows = tuple(
            DeliveryValueRow(
                key=point.key,
                field_name=point.field_name,
                value_raw=point.value_raw,
                captured_at=point.captured_at,
                captured_at_quality=point.captured_at_quality,
                status="new",
                first_seen_at=point.first_seen_at,
                first_delivery_id=None,
            )
            for point in stored
        )
        valid_times = [
            row.captured_at
            for row in rows
            if row.captured_at is not None and row.captured_at_quality != "invalid"
        ]
        captured_max = max(valid_times) if valid_times else None
        reference = record.delivered_at or record.fetched_at
        age = (reference - captured_max).total_seconds() if captured_max is not None else None
        summary = DeliverySummaryStats(
            total_values=total,
            new_values=total,
            known_values=None,
            captured_min=min(valid_times) if valid_times else None,
            captured_max=captured_max,
            captured_max_age_s=age,
        )

        return DeliveryDetail(
            id=record.id,
            vehicle_id=record.vehicle_id,
            kind=record.kind,
            source=record.source,
            remote_name=record.remote_name,
            delivered_at=record.delivered_at,
            fetched_at=record.fetched_at,
            has_content=record.has_content,
            size_bytes=record.size_bytes,
            parse_state=record.parse_state,
            raw_available=record.raw_available,
            summary=summary,
            values=rows,
            page=page,
            total_pages=total_pages,
            degraded=True,
            limited_reason=reason,
        )
