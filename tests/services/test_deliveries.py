"""Tests for `carchive.services.deliveries`."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from carchive.core.models import DataPoint, TimestampQuality
from carchive.core.provider import ProviderRegistry
from carchive.services.deliveries import DeliveryBrowser
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import (
    AccountRepository,
    DataPointRepository,
    DataRequestRepository,
    DeliveryRepository,
    VehicleRepository,
)
from tests.services.fakes import FakeParser, FakeProvider

_NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)
_VIN = "WAUZZZ4V0JA123456"


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


def _registry(provider: FakeProvider) -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(provider)
    return registry


async def _seed_vehicle(db: Database) -> UUID:
    accounts = AccountRepository()
    vehicles = VehicleRepository()
    account_id = uuid4()
    vehicle_id = uuid4()
    async with db.write() as conn:
        await accounts.add(
            conn,
            id=account_id,
            provider_id="fake",
            brand="fake",
            label=f"acc-{account_id}",
            credential_ref="ref",
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
        await vehicles.add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin=_VIN,
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
    return vehicle_id


async def _seed_delivery(
    db: Database,
    vehicle_id: UUID,
    *,
    remote_name: str,
    delivered_at: datetime | None,
    has_content: bool = True,
    parse_state: str = "parsed",
    raw_payload: bytes | None,
) -> UUID:
    requests = DataRequestRepository()
    deliveries = DeliveryRepository()
    async with db.write() as conn:
        request_id = await requests.upsert(
            conn, vehicle_id=vehicle_id, kind="partial", remote_id="r1", interval_s=900
        )
        delivery_id = await deliveries.add(
            conn,
            data_request_id=request_id,
            import_batch_id=None,
            remote_name=remote_name,
            delivered_at=delivered_at,
            fetched_at=delivered_at or _NOW,
            has_content=has_content,
            sha256="a" * 64,
            size_bytes=len(raw_payload or b""),
            parse_state=parse_state,
            parser_version="fake-parser-1" if parse_state == "parsed" else None,
            raw_payload=raw_payload,
        )
    return delivery_id


async def test_list_returns_none_for_unknown_vehicle(db: Database) -> None:
    browser = DeliveryBrowser(db, _registry(FakeProvider()), clock=lambda: _NOW)
    assert await browser.list(uuid4(), page=1) is None


async def test_list_orders_newest_delivered_first(db: Database) -> None:
    vehicle_id = await _seed_vehicle(db)
    older = await _seed_delivery(
        db,
        vehicle_id,
        remote_name="older.zip",
        delivered_at=_NOW - timedelta(days=2),
        raw_payload=b"x",
    )
    newer = await _seed_delivery(
        db,
        vehicle_id,
        remote_name="newer.zip",
        delivered_at=_NOW - timedelta(days=1),
        raw_payload=b"y",
    )

    browser = DeliveryBrowser(db, _registry(FakeProvider()), clock=lambda: _NOW)
    page = await browser.list(vehicle_id, page=1)

    assert page is not None
    assert [row.id for row in page.items] == [newer, older]
    assert page.items[0].delivered_age_s == timedelta(days=1).total_seconds()


async def test_detail_returns_none_for_unknown_delivery(db: Database) -> None:
    browser = DeliveryBrowser(db, _registry(FakeProvider()), clock=lambda: _NOW)
    result = await browser.detail(uuid4(), only_new=False, query="", page=1)
    assert result is None


async def _point(key: str, field_name: str, value_raw: str, captured_at: datetime) -> DataPoint:
    return DataPoint(
        key=key,
        field_name=field_name,
        value_raw=value_raw,
        captured_at=captured_at,
        captured_at_quality=TimestampQuality.EXACT,
    )


async def test_detail_classifies_new_and_known_values(db: Database) -> None:
    vehicle_id = await _seed_vehicle(db)
    known_point = await _point("k1", "mileage", "100", _NOW - timedelta(days=1))
    first_payload = b"first"
    first_delivery = await _seed_delivery(
        db,
        vehicle_id,
        remote_name="first.zip",
        delivered_at=_NOW - timedelta(days=1),
        raw_payload=first_payload,
    )
    points = DataPointRepository()
    async with db.write() as conn:
        await points.upsert_many(
            conn,
            vehicle_id=vehicle_id,
            delivery_id=first_delivery,
            points=[known_point],
            seen_at=_NOW - timedelta(days=1),
        )

    new_point = await _point("k2", "soc", "80", _NOW)
    second_payload = b"second"
    second_delivery = await _seed_delivery(
        db, vehicle_id, remote_name="second.zip", delivered_at=_NOW, raw_payload=second_payload
    )

    provider = FakeProvider()
    provider.set_parser(FakeParser(points_by_payload={second_payload: [known_point, new_point]}))
    browser = DeliveryBrowser(db, _registry(provider), clock=lambda: _NOW)

    detail = await browser.detail(second_delivery, only_new=False, query="", page=1)

    assert detail is not None
    assert detail.degraded is False
    assert detail.summary.total_values == 2
    assert detail.summary.new_values == 1
    assert detail.summary.known_values == 1

    by_field = {row.field_name: row for row in detail.values}
    assert by_field["mileage"].status == "known"
    assert by_field["mileage"].first_delivery_id == first_delivery
    assert by_field["soc"].status == "new"
    assert by_field["soc"].first_delivery_id is None


async def test_detail_only_new_filter(db: Database) -> None:
    vehicle_id = await _seed_vehicle(db)
    known_point = await _point("k1", "mileage", "100", _NOW - timedelta(days=1))
    first_payload = b"first"
    first_delivery = await _seed_delivery(
        db,
        vehicle_id,
        remote_name="first.zip",
        delivered_at=_NOW - timedelta(days=1),
        raw_payload=first_payload,
    )
    points = DataPointRepository()
    async with db.write() as conn:
        await points.upsert_many(
            conn,
            vehicle_id=vehicle_id,
            delivery_id=first_delivery,
            points=[known_point],
            seen_at=_NOW - timedelta(days=1),
        )

    new_point = await _point("k2", "soc", "80", _NOW)
    second_payload = b"second"
    second_delivery = await _seed_delivery(
        db, vehicle_id, remote_name="second.zip", delivered_at=_NOW, raw_payload=second_payload
    )
    provider = FakeProvider()
    provider.set_parser(FakeParser(points_by_payload={second_payload: [known_point, new_point]}))
    browser = DeliveryBrowser(db, _registry(provider), clock=lambda: _NOW)

    only_new = await browser.detail(second_delivery, only_new=True, query="", page=1)
    assert only_new is not None
    assert [row.field_name for row in only_new.values] == ["soc"]

    searched = await browser.detail(second_delivery, only_new=False, query="mile", page=1)
    assert searched is not None
    assert [row.field_name for row in searched.values] == ["mileage"]


async def test_detail_falls_back_when_raw_payload_is_purged(db: Database) -> None:
    vehicle_id = await _seed_vehicle(db)
    delivery_id = await _seed_delivery(
        db, vehicle_id, remote_name="purged.zip", delivered_at=_NOW, raw_payload=None
    )
    point = await _point("k1", "mileage", "100", _NOW)
    points = DataPointRepository()
    async with db.write() as conn:
        await points.upsert_many(
            conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
        )

    browser = DeliveryBrowser(db, _registry(FakeProvider()), clock=lambda: _NOW)
    detail = await browser.detail(delivery_id, only_new=False, query="", page=1)

    assert detail is not None
    assert detail.degraded is True
    assert detail.summary.known_values is None
    assert [row.field_name for row in detail.values] == ["mileage"]
    assert detail.values[0].status == "new"


async def test_detail_falls_back_when_parser_raises(db: Database) -> None:
    vehicle_id = await _seed_vehicle(db)
    payload = b"broken"
    delivery_id = await _seed_delivery(
        db, vehicle_id, remote_name="broken.zip", delivered_at=_NOW, raw_payload=payload
    )
    point = await _point("k1", "mileage", "100", _NOW)
    points = DataPointRepository()
    async with db.write() as conn:
        await points.upsert_many(
            conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
        )

    provider = FakeProvider()
    provider.set_parser(FakeParser(fail_on={payload}))
    browser = DeliveryBrowser(db, _registry(provider), clock=lambda: _NOW)

    detail = await browser.detail(delivery_id, only_new=False, query="", page=1)

    assert detail is not None
    assert detail.degraded is True
    assert [row.field_name for row in detail.values] == ["mileage"]


async def test_detail_falls_back_when_no_parser_is_registered(db: Database) -> None:
    vehicle_id = await _seed_vehicle(db)
    payload = b"payload"
    delivery_id = await _seed_delivery(
        db, vehicle_id, remote_name="f.zip", delivered_at=_NOW, raw_payload=payload
    )

    browser = DeliveryBrowser(db, _registry(FakeProvider()), clock=lambda: _NOW)
    detail = await browser.detail(delivery_id, only_new=False, query="", page=1)

    assert detail is not None
    assert detail.degraded is True
    assert detail.values == ()


async def test_detail_paginates_values(db: Database) -> None:
    vehicle_id = await _seed_vehicle(db)
    payload = b"many"
    delivery_id = await _seed_delivery(
        db, vehicle_id, remote_name="many.zip", delivered_at=_NOW, raw_payload=payload
    )
    many_points = [await _point(f"k{i}", f"f{i}", str(i), _NOW) for i in range(3)]
    provider = FakeProvider()
    provider.set_parser(FakeParser(points_by_payload={payload: many_points}))
    browser = DeliveryBrowser(db, _registry(provider), clock=lambda: _NOW)

    from carchive.services import deliveries as deliveries_module

    original = deliveries_module._VALUE_PAGE_SIZE
    deliveries_module._VALUE_PAGE_SIZE = 2
    try:
        first_page = await browser.detail(delivery_id, only_new=False, query="", page=1)
        second_page = await browser.detail(delivery_id, only_new=False, query="", page=2)
    finally:
        deliveries_module._VALUE_PAGE_SIZE = original

    assert first_page is not None and second_page is not None
    assert len(first_page.values) == 2
    assert len(second_page.values) == 1
    assert first_page.total_pages == 2
