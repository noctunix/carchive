"""Tests for the `/` dashboard and `/partials/dashboard` routes."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
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
from carchive.storage.schema import (
    accounts,
    collector_runs,
    data_points,
    data_requests,
    deliveries,
    signal_values,
    vehicles,
)
from carchive.web.app import create_app
from tests.services.fakes import FakeProvider
from tests.web.conftest import FakeScheduler, build_services

_ORIGIN = {"Origin": "http://localhost"}
_NOW = datetime.now(UTC) - timedelta(hours=1)  # relative, so "fresh" stays true as real time passes


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def _app(db: Database, settings: Settings, fake_provider: FakeProvider) -> FastAPI:
    registry = ProviderRegistry()
    fake_provider.set_mapper(VwGroupMapper())
    registry.register(fake_provider)
    accounts = AccountService(db, registry, settings)
    return create_app(build_services(db, FakeScheduler(), accounts), settings)


async def _add_account_with_vehicle(client: httpx.AsyncClient) -> str:
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
    assert csrf is not None
    return csrf


async def _seed_signal_value(
    db: Database,
    *,
    signal: str,
    source_field: str,
    value: float | str,
    unit: str | None = None,
) -> None:
    """Give the one vehicle already in `db` a single, fresh reading for `signal`."""
    is_numeric = isinstance(value, (int, float))
    async with db.write() as conn:
        vehicle_row = (await conn.execute(select(vehicles))).first()
        assert vehicle_row is not None
        request_id = uuid4()
        await conn.execute(
            insert(data_requests).values(
                id=request_id,
                vehicle_id=vehicle_row.id,
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
                vehicle_id=vehicle_row.id,
                key=source_field,
                field_name=source_field,
                value_raw=str(value),
                value_type="num" if is_numeric else "text",
                value_num=float(value) if is_numeric else None,
                value_text=None if is_numeric else str(value),
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
                vehicle_id=vehicle_row.id,
                signal=signal,
                value_num=float(value) if is_numeric else None,
                value_text=None if is_numeric else str(value),
                value_bool=None,
                unit=unit,
                captured_at=_NOW,
                captured_at_quality="exact",
                source_data_point_id=point_id,
                mapping_version="v1",
            )
        )


async def _seed_odometer_reading(db: Database) -> None:
    """Give the one vehicle already in `db` a single, fresh `vehicle.odometer` reading."""
    await _seed_signal_value(
        db, signal="vehicle.odometer", source_field="mileage", value=4321.0, unit="km"
    )


async def test_dashboard_empty_shows_setup_link(db: Database, settings: Settings) -> None:
    app = _app(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "No vehicles yet" in response.text
    assert 'href="/setup"' in response.text


async def test_dashboard_shows_vehicle_card_with_value_and_freshness(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        await _seed_odometer_reading(db)
        response = await client.get("/")

    assert response.status_code == 200
    assert "4,321" in response.text  # locale-formatted (en_US), not the raw "4321.0"
    assert "freshness-fresh" in response.text
    assert "fresh" in response.text  # the text marker, not only the CSS class


async def test_dashboard_age_rendered_in_german_and_english(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        await _seed_odometer_reading(db)
        english = await client.get("/")
        client.cookies.set("lang", "de")
        german = await client.get("/")

    assert "ago" in english.text
    assert "vor" in german.text


async def test_partial_dashboard_route_returns_only_the_card_area(
    db: Database, settings: Settings
) -> None:
    app = _app(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/partials/dashboard")

    assert response.status_code == 200
    assert "<nav" not in response.text
    assert 'id="dashboard-cards"' in response.text


async def test_dashboard_page_has_htmx_polling_and_no_indicator_styles(
    db: Database, settings: Settings
) -> None:
    app = _app(db, settings, FakeProvider())

    async with _client(app) as client:
        response = await client.get("/")

    assert 'hx-get="/partials/dashboard"' in response.text
    assert 'hx-trigger="every 60s"' in response.text
    assert '"includeIndicatorStyles": false' in response.text


async def test_dashboard_shows_account_needing_attention(db: Database, settings: Settings) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        async with db.write() as conn:
            await conn.execute(
                accounts.update().values(state="needs_attention", state_reason="login expired")
            )
        response = await client.get("/")

    assert "login expired" in response.text


async def test_dashboard_shows_translated_signal_label_not_raw_name(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        await _seed_odometer_reading(db)
        english = await client.get("/")
        client.cookies.set("lang", "de")
        german = await client.get("/")

    assert "Odometer" in english.text
    assert "Kilometerstand" in german.text
    assert "vehicle.odometer" not in english.text


async def test_dashboard_formats_numbers_per_locale(db: Database, settings: Settings) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        await _seed_signal_value(
            db, signal="battery.soc", source_field="currentSOCInPct", value=62.345, unit="%"
        )
        english = await client.get("/")
        client.cookies.set("lang", "de")
        german = await client.get("/")

    assert "62.3" in english.text  # one decimal, English grouping
    assert "62,3" in german.text  # one decimal, German decimal comma


async def test_dashboard_formats_charging_power_with_two_decimals(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        await _seed_signal_value(
            db, signal="charging.power", source_field="chargePowerInKW", value=11.567, unit="kW"
        )
        response = await client.get("/")

    assert "11.57" in response.text


async def test_dashboard_formats_whole_numbers_without_decimals(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        await _seed_odometer_reading(db)  # 4321.0
        response = await client.get("/")

    assert "4,321" in response.text
    assert "4,321.0" not in response.text


async def test_dashboard_shows_known_brand_display_name(db: Database, settings: Settings) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        async with db.write() as conn:
            await conn.execute(accounts.update().values(brand="audi"))
            await conn.execute(vehicles.update().values(brand="audi"))
        response = await client.get("/")

    assert "Audi" in response.text
    assert "audi" not in response.text  # case-sensitive: the raw lowercase id is gone


async def test_dashboard_shows_capitalized_fallback_for_unknown_brand(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        response = await client.get("/")

    assert "Fake" in response.text  # brand "fake" is not in the known-brand table


async def test_dashboard_marks_enum_values_as_raw_portal_values(
    db: Database, settings: Settings
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        await _seed_signal_value(
            db,
            signal="charging.state",
            source_field="chargingState",
            value="notReadyForCharging",
        )
        response = await client.get("/")

    assert "notReadyForCharging" in response.text
    assert "raw-value" in response.text


async def test_dashboard_renders_portal_unavailable_notice_without_crashing(
    db: Database, settings: Settings
) -> None:
    """Regression test: the notice's params must match the template's %(count)s placeholder."""
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    app = _app(db, settings, fake_provider)

    async with _client(app) as client:
        await _add_account_with_vehicle(client)
        async with db.read() as conn:
            account_row = (await conn.execute(select(accounts))).first()
            vehicle_row = (await conn.execute(select(vehicles))).first()
        assert account_row is not None
        assert vehicle_row is not None
        async with db.write() as conn:
            request_id = uuid4()
            await conn.execute(
                insert(data_requests).values(
                    id=request_id,
                    vehicle_id=vehicle_row.id,
                    kind="partial",
                    remote_id="r1",
                    interval_s=900,
                    next_due_at=None,
                    state="active",
                    state_reason=None,
                    last_success_at=None,
                )
            )
        async with db.write() as conn:
            for i in range(3):
                await conn.execute(
                    insert(collector_runs).values(
                        id=uuid4(),
                        account_id=account_row.id,
                        data_request_id=request_id,
                        started_at=_NOW - timedelta(minutes=i),
                        finished_at=_NOW - timedelta(minutes=i),
                        outcome="error",
                        listed=0,
                        placeholders=0,
                        downloaded=0,
                        with_content=0,
                        pending=None,
                        oldest_pending_age_s=None,
                        message=None,
                    )
                )
        response = await client.get("/")

    assert response.status_code == 200
    assert "failed on the last 3 runs in a row" in response.text
