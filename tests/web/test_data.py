"""Tests for the `/data` data explorer routes."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import uuid4

import httpx
from fastapi import FastAPI
from sqlalchemy import insert

from carchive.config import Settings
from carchive.core.provider import ProviderRegistry
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.services.accounts import AccountService
from carchive.storage.db import Database
from carchive.storage.schema import (
    accounts,
    data_points,
    data_requests,
    deliveries,
    vehicles,
)
from carchive.web.app import create_app
from tests.services.fakes import FakeProvider
from tests.web.conftest import FakeScheduler, build_services

_NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def _app(db: Database, settings: Settings) -> FastAPI:
    registry = ProviderRegistry()
    provider = FakeProvider()
    provider.set_mapper(VwGroupMapper())
    registry.register(provider)
    account_service = AccountService(db, registry, settings)
    return create_app(build_services(db, FakeScheduler(), account_service), settings)


async def _seed_vehicle_with_point(db: Database) -> str:
    account_id = uuid4()
    vehicle_id = uuid4()
    request_id = uuid4()
    delivery_id = uuid4()
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
                remote_name="f.zip",
                delivered_at=_NOW,
                fetched_at=_NOW,
                has_content=True,
                sha256="a" * 64,
                size_bytes=1,
                parse_state="parsed",
                parser_version="v1",
                raw_payload=None,
            )
        )
        await conn.execute(
            insert(data_points).values(
                id=uuid4(),
                vehicle_id=vehicle_id,
                key="k1",
                field_name="mileage",
                field_generic="mileage",
                value_raw="12345",
                value_type="num",
                value_num=12345.0,
                value_text=None,
                value_bool=None,
                value_time=None,
                captured_at=_NOW,
                captured_at_quality="exact",
                first_delivery_id=delivery_id,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
                seen_count=1,
                dedup_key="dedup1",
            )
        )
        await conn.execute(
            insert(data_points).values(
                id=uuid4(),
                vehicle_id=vehicle_id,
                key="k2",
                field_name="powerCurve.0.soc",
                field_generic="powerCurve.[*].soc",
                value_raw="42",
                value_type="num",
                value_num=42.0,
                value_text=None,
                value_bool=None,
                value_time=None,
                captured_at=_NOW,
                captured_at_quality="exact",
                first_delivery_id=delivery_id,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
                seen_count=1,
                dedup_key="dedup2",
            )
        )
    return str(vehicle_id)


async def test_data_explorer_without_vehicles_points_to_setup(
    db: Database, settings: Settings
) -> None:
    app = _app(db, settings)
    async with _client(app) as client:
        response = await client.get("/data")

    assert response.status_code == 200
    assert "No vehicles yet" in response.text


async def test_data_explorer_hints_when_no_catalog_is_imported(
    db: Database, settings: Settings
) -> None:
    await _seed_vehicle_with_point(db)
    app = _app(db, settings)

    async with _client(app) as client:
        response = await client.get("/data")

    assert response.status_code == 200
    assert "mileage" in response.text
    assert "No dictionary catalog has been imported" in response.text


async def test_data_explorer_search_filters_fields(db: Database, settings: Settings) -> None:
    vehicle_id = await _seed_vehicle_with_point(db)
    app = _app(db, settings)

    async with _client(app) as client:
        matching = await client.get(f"/data?vehicle_id={vehicle_id}&q=mile")
        not_matching = await client.get(f"/data?vehicle_id={vehicle_id}&q=nope")

    assert "mileage" in matching.text
    assert "mileage" not in not_matching.text
    assert "No fields match this filter" in not_matching.text


async def test_data_explorer_unknown_vehicle_is_404(db: Database, settings: Settings) -> None:
    await _seed_vehicle_with_point(db)
    app = _app(db, settings)

    async with _client(app) as client:
        response = await client.get(f"/data?vehicle_id={uuid4()}")

    assert response.status_code == 404


async def test_field_history_shows_values(db: Database, settings: Settings) -> None:
    vehicle_id = await _seed_vehicle_with_point(db)
    app = _app(db, settings)

    async with _client(app) as client:
        response = await client.get(f"/data/{vehicle_id}/field?name=mileage")

    assert response.status_code == 200
    assert "12345" in response.text


async def test_field_history_unknown_vehicle_is_404(db: Database, settings: Settings) -> None:
    app = _app(db, settings)
    async with _client(app) as client:
        response = await client.get(f"/data/{uuid4()}/field?name=mileage")

    assert response.status_code == 404


async def test_data_explorer_german_translation(db: Database, settings: Settings) -> None:
    app = _app(db, settings)
    async with _client(app) as client:
        client.cookies.set("lang", "de")
        response = await client.get("/data")

    assert response.status_code == 200
    assert "Noch keine Fahrzeuge" in response.text


async def test_data_explorer_link_to_an_indexed_field_round_trips(
    db: Database, settings: Settings
) -> None:
    vehicle_id = await _seed_vehicle_with_point(db)
    app = _app(db, settings)

    async with _client(app) as client:
        listing = await client.get(f"/data?vehicle_id={vehicle_id}")
        match = re.search(r'href="(/data/[^"]+/field\?name=powerCurve[^"]+)"', listing.text)
        assert match is not None, listing.text
        detail = await client.get(match.group(1).replace("&amp;", "&"))

    assert detail.status_code == 200
    assert "42" in detail.text
