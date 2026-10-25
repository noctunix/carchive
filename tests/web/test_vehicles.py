"""Tests for the `/vehicles/{id}` detail and deletion routes."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import uuid4

import httpx
from fastapi import FastAPI
from sqlalchemy import insert, select

from carchive.config import Settings
from carchive.core.models import RemoteVehicle
from carchive.core.provider import ProviderRegistry
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.services.accounts import AccountService
from carchive.storage.db import Database
from carchive.storage.schema import data_points, data_requests, deliveries, signal_values, vehicles
from carchive.web.app import create_app
from tests.services.fakes import FakeProvider
from tests.web.conftest import FakeScheduler, build_services

_ORIGIN = {"Origin": "http://localhost"}
_NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def _app(db: Database, settings: Settings, fake_provider: FakeProvider) -> FastAPI:
    registry = ProviderRegistry()
    fake_provider.set_mapper(VwGroupMapper())
    registry.register(fake_provider)
    accounts = AccountService(db, registry, settings)
    return create_app(build_services(db, FakeScheduler(), accounts), settings)


async def _seed_signal_value(
    db: Database, vehicle_id: object, *, signal: str, source_field: str, value: float
) -> None:
    async with db.write() as conn:
        request_id = uuid4()
        await conn.execute(
            insert(data_requests).values(
                id=request_id,
                vehicle_id=vehicle_id,
                kind="partial",
                remote_id="r1",
                interval_s=900,
                next_due_at=None,
                state="active",
                state_reason=None,
                last_success_at=None,
            )
        )
        delivery_id = uuid4()
        await conn.execute(
            insert(deliveries).values(
                id=delivery_id,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name="d1.zip",
                delivered_at=_NOW,
                fetched_at=_NOW,
                has_content=True,
                sha256="0" * 64,
                size_bytes=1,
                parse_state="parsed",
                parser_version="v1",
                raw_payload=None,
            )
        )
        point_id = uuid4()
        await conn.execute(
            insert(data_points).values(
                id=point_id,
                vehicle_id=vehicle_id,
                key=source_field,
                field_name=source_field,
                value_raw=str(value),
                value_type="num",
                value_num=value,
                value_text=None,
                value_bool=None,
                value_time=None,
                captured_at=_NOW,
                captured_at_quality="exact",
                first_delivery_id=delivery_id,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
                seen_count=1,
                dedup_key="dedup-1",
            )
        )
        await conn.execute(
            insert(signal_values).values(
                id=uuid4(),
                vehicle_id=vehicle_id,
                signal=signal,
                value_num=value,
                value_text=None,
                value_bool=None,
                unit="km",
                captured_at=_NOW,
                captured_at_quality="exact",
                source_data_point_id=point_id,
                mapping_version="v1",
            )
        )


async def _add_account_with_vehicle(client: httpx.AsyncClient) -> None:
    await client.get("/setup")
    csrf = client.cookies.get("csrf_token")
    account_response = await client.post(
        "/setup",
        data={
            "csrf_token": csrf,
            "provider_choice": "fake|fake",
            "label": "myacct",
            "user": "user",
            "password": "s3cret-password",
        },
        headers=_ORIGIN,
    )
    match = re.search(r'name="token" value="([^"]+)"', account_response.text)
    assert match is not None, account_response.text
    await client.post(
        "/setup/vehicles",
        data={"csrf_token": csrf, "token": match.group(1), "vin": "WAUZZZ4V0JA123456"},
        headers=_ORIGIN,
    )


async def test_vehicle_detail_shows_label_and_signals_section(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        async with db.read() as conn:
            vehicle_row = (await conn.execute(select(vehicles))).first()
        assert vehicle_row is not None
        response = await client.get(f"/vehicles/{vehicle_row.id}")

    assert response.status_code == 200
    assert vehicle_row.label in response.text
    assert "No signal values yet." in response.text


async def test_vehicle_detail_unknown_id_is_404(db: Database, settings: Settings) -> None:
    app = _app(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get(f"/vehicles/{uuid4()}")

    assert response.status_code == 404


async def test_vehicle_detail_shows_translated_label_and_raw_signal_name_small(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        async with db.read() as conn:
            vehicle_row = (await conn.execute(select(vehicles))).first()
        assert vehicle_row is not None
        await _seed_signal_value(
            db, vehicle_row.id, signal="vehicle.odometer", source_field="mileage", value=4321.0
        )
        response = await client.get(f"/vehicles/{vehicle_row.id}")

    assert response.status_code == 200
    assert "Odometer" in response.text
    assert '<span class="raw-signal">vehicle.odometer</span>' in response.text
    assert "4,321" in response.text


async def test_vehicle_delete_confirmation_and_deletion(db: Database, settings: Settings) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        csrf = client.cookies.get("csrf_token")
        async with db.read() as conn:
            vehicle_row = (await conn.execute(select(vehicles))).first()
        assert vehicle_row is not None
        vehicle_id = vehicle_row.id

        confirm = await client.get(f"/vehicles/{vehicle_id}/delete")
        delete_response = await client.post(
            f"/vehicles/{vehicle_id}/delete", data={"csrf_token": csrf}, headers=_ORIGIN
        )
        after = await client.get("/accounts")

    assert confirm.status_code == 200
    assert delete_response.status_code == 200
    assert "No vehicles yet" in after.text


async def test_vehicle_delete_unknown_id_is_404(db: Database, settings: Settings) -> None:
    app = _app(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get(f"/vehicles/{uuid4()}/delete")

    assert response.status_code == 404
