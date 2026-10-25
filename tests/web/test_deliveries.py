"""Tests for the `/deliveries` routes."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI
from sqlalchemy import insert

from carchive.config import Settings
from carchive.core.models import DataPoint, TimestampQuality
from carchive.core.provider import ProviderRegistry
from carchive.services.accounts import AccountService
from carchive.storage.db import Database
from carchive.storage.dedup import dedup_key as compute_dedup_key
from carchive.storage.schema import accounts, data_points, data_requests, deliveries, vehicles
from carchive.web.app import create_app
from tests.services.fakes import FakeParser, FakeProvider
from tests.web.conftest import FakeScheduler, build_services

_NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def _app(db: Database, settings: Settings, provider: FakeProvider | None = None) -> FastAPI:
    registry = ProviderRegistry()
    registry.register(provider or FakeProvider())
    account_service = AccountService(db, registry, settings)
    return create_app(build_services(db, FakeScheduler(), account_service), settings)


async def _seed_vehicle(db: Database) -> UUID:
    account_id = uuid4()
    vehicle_id = uuid4()
    async with db.write() as conn:
        await conn.execute(
            insert(accounts).values(
                id=account_id,
                provider_id="fake",
                brand="fake",
                label="acc",
                credential_ref="ref",
                state="active",
                state_reason=None,
                created_at=_NOW,
            )
        )
        await conn.execute(
            insert(vehicles).values(
                id=vehicle_id,
                account_id=account_id,
                vin="X" * 17,
                label="My Car",
                brand="fake",
                model=None,
                created_at=_NOW,
                archived_at=None,
            )
        )
    return vehicle_id


async def _add_delivery(
    db: Database,
    vehicle_id: UUID,
    *,
    remote_name: str = "f.zip",
    has_content: bool = True,
    raw_payload: bytes | None = None,
    parse_state: str = "parsed",
) -> UUID:
    delivery_id = uuid4()
    async with db.write() as conn:
        existing_request = (
            await conn.execute(
                data_requests.select().where(data_requests.c.vehicle_id == vehicle_id)
            )
        ).first()
        if existing_request is not None:
            request_id = existing_request.id
        else:
            request_id = uuid4()
            await conn.execute(
                insert(data_requests).values(
                    id=request_id,
                    vehicle_id=vehicle_id,
                    kind="partial",
                    remote_id="r",
                    interval_s=900,
                    next_due_at=None,
                    state="active",
                    state_reason=None,
                    last_success_at=None,
                )
            )
        await conn.execute(
            insert(deliveries).values(
                id=delivery_id,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name=remote_name,
                delivered_at=_NOW,
                fetched_at=_NOW,
                has_content=has_content,
                sha256="a" * 64,
                size_bytes=len(raw_payload or b""),
                parse_state=parse_state,
                parser_version="fake-parser-1" if parse_state == "parsed" else None,
                raw_payload=raw_payload,
            )
        )
    return delivery_id


async def _add_data_point(
    db: Database, vehicle_id: UUID, delivery_id: UUID, point: DataPoint
) -> None:
    """Store `point` as if it had first been delivered by `delivery_id`."""
    key = compute_dedup_key(point.key, point.field_name, point.captured_at, point.value_raw)
    async with db.write() as conn:
        await conn.execute(
            insert(data_points).values(
                id=uuid4(),
                vehicle_id=vehicle_id,
                key=point.key,
                field_name=point.field_name,
                field_generic=point.field_name,
                value_raw=point.value_raw,
                value_type="num",
                value_num=float(point.value_raw) if point.value_raw else None,
                value_text=None,
                value_bool=None,
                value_time=None,
                captured_at=point.captured_at,
                captured_at_quality=str(point.captured_at_quality),
                first_delivery_id=delivery_id,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
                seen_count=1,
                dedup_key=key,
            )
        )


async def test_deliveries_list_without_vehicles_points_to_setup(
    db: Database, settings: Settings
) -> None:
    app = _app(db, settings)
    async with _client(app) as client:
        response = await client.get("/deliveries")

    assert response.status_code == 200
    assert "No vehicles yet" in response.text


async def test_deliveries_list_shows_a_delivery(db: Database, settings: Settings) -> None:
    vehicle_id = await _seed_vehicle(db)
    delivery_id = await _add_delivery(db, vehicle_id, raw_payload=b"x")
    point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="12345",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    await _add_data_point(db, vehicle_id, delivery_id, point)
    app = _app(db, settings)

    async with _client(app) as client:
        response = await client.get(f"/deliveries?vehicle_id={vehicle_id}")

    assert response.status_code == 200
    assert "f.zip" in response.text


async def test_deliveries_list_unknown_vehicle_is_404(db: Database, settings: Settings) -> None:
    await _seed_vehicle(db)
    app = _app(db, settings)

    async with _client(app) as client:
        response = await client.get(f"/deliveries?vehicle_id={uuid4()}")

    assert response.status_code == 404


async def test_deliveries_list_paginates(db: Database, settings: Settings) -> None:
    vehicle_id = await _seed_vehicle(db)
    await _add_delivery(db, vehicle_id, raw_payload=b"x")
    app = _app(db, settings)

    async with _client(app) as client:
        response = await client.get(f"/deliveries?vehicle_id={vehicle_id}&page=0")

    assert response.status_code == 200


async def test_delivery_detail_classifies_new_and_known_values(
    db: Database, settings: Settings
) -> None:
    vehicle_id = await _seed_vehicle(db)
    known_point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="12345",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    first_delivery = await _add_delivery(db, vehicle_id, remote_name="first.zip", raw_payload=b"a")
    await _add_data_point(db, vehicle_id, first_delivery, known_point)

    payload = b"payload"
    second_delivery = await _add_delivery(
        db, vehicle_id, remote_name="second.zip", raw_payload=payload
    )
    new_point = DataPoint(
        key="k2",
        field_name="soc",
        value_raw="80",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    provider = FakeProvider()
    provider.set_parser(FakeParser(points_by_payload={payload: [known_point, new_point]}))
    app = _app(db, settings, provider)

    async with _client(app) as client:
        response = await client.get(f"/deliveries/{second_delivery}")

    assert response.status_code == 200
    assert "mileage" in response.text
    assert "soc" in response.text


async def test_delivery_detail_only_new_filter_hides_known_values(
    db: Database, settings: Settings
) -> None:
    vehicle_id = await _seed_vehicle(db)
    known_point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="12345",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    first_delivery = await _add_delivery(db, vehicle_id, remote_name="first.zip", raw_payload=b"a")
    await _add_data_point(db, vehicle_id, first_delivery, known_point)

    payload = b"payload"
    second_delivery = await _add_delivery(
        db, vehicle_id, remote_name="second.zip", raw_payload=payload
    )
    new_point = DataPoint(
        key="k2",
        field_name="soc",
        value_raw="80",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    provider = FakeProvider()
    provider.set_parser(FakeParser(points_by_payload={payload: [known_point, new_point]}))
    app = _app(db, settings, provider)

    async with _client(app) as client:
        response = await client.get(f"/deliveries/{second_delivery}?only_new=true")

    assert response.status_code == 200
    assert "soc" in response.text
    assert "mileage" not in response.text


async def test_delivery_detail_unknown_id_is_404(db: Database, settings: Settings) -> None:
    app = _app(db, settings)
    async with _client(app) as client:
        response = await client.get(f"/deliveries/{uuid4()}")

    assert response.status_code == 404


async def test_delivery_detail_degraded_when_raw_payload_is_purged(
    db: Database, settings: Settings
) -> None:
    vehicle_id = await _seed_vehicle(db)
    delivery_id = await _add_delivery(db, vehicle_id, raw_payload=None)
    point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="12345",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    await _add_data_point(db, vehicle_id, delivery_id, point)
    app = _app(db, settings)

    async with _client(app) as client:
        response = await client.get(f"/deliveries/{delivery_id}")

    assert response.status_code == 200
    assert "mileage" in response.text


async def test_deliveries_german_translation(db: Database, settings: Settings) -> None:
    app = _app(db, settings)
    async with _client(app) as client:
        client.cookies.set("lang", "de")
        response = await client.get("/deliveries")

    assert response.status_code == 200
    assert "Noch keine Fahrzeuge" in response.text


async def test_deliveries_without_session_redirects_to_login(
    db: Database, settings: Settings
) -> None:
    app = _app(db, settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost", cookies={}
    ) as client:
        response = await client.get("/deliveries")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
