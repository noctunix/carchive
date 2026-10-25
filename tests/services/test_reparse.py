"""Tests for `carchive.services.reparse`."""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import AsyncGenerator, Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from carchive.core.models import DataPoint, SignalValue, TimestampQuality
from carchive.core.provider import ProviderRegistry
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.providers.vwgroup.parser import VwGroupParser
from carchive.services.reparse import Reparser
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import (
    AccountRepository,
    DataRequestRepository,
    DeliveryRepository,
    SignalValueRepository,
    VehicleRepository,
)
from tests.services.fakes import FakeParser, FakeProvider

_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
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


async def _seed_pending_delivery(
    db: Database, *, raw_payload: bytes | None, remote_name: str = "f.zip"
) -> tuple[UUID, UUID]:
    accounts = AccountRepository()
    vehicles = VehicleRepository()
    requests = DataRequestRepository()
    deliveries = DeliveryRepository()
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
        request_id = await requests.upsert(
            conn, vehicle_id=vehicle_id, kind="partial", remote_id="r1", interval_s=900
        )
        delivery_id = await deliveries.add(
            conn,
            data_request_id=request_id,
            import_batch_id=None,
            remote_name=remote_name,
            delivered_at=_NOW,
            fetched_at=_NOW,
            has_content=True,
            sha256="a" * 64,
            size_bytes=len(raw_payload or b""),
            parse_state="pending",
            parser_version=None,
            raw_payload=raw_payload,
        )
    return vehicle_id, delivery_id


def _vwgroup_zip(vin: str, records: list[dict[str, object]]) -> bytes:
    document = {"vin": vin, "Data": records}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dataset.json", json.dumps(document))
    return buf.getvalue()


async def _parse_state(db: Database, delivery_id: UUID) -> str:
    from sqlalchemy import select

    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        row = (
            await conn.execute(
                select(deliveries_table.c.parse_state).where(deliveries_table.c.id == delivery_id)
            )
        ).first()
    assert row is not None
    return str(row.parse_state)


async def test_parse_pending_parses_and_maps_a_real_delivery(db: Database) -> None:
    payload = _vwgroup_zip(
        _VIN,
        [
            {
                "key": "k1",
                "dataFieldName": "mileage",
                "timestampUtc": "2026-10-01T00:00:00Z",
                "value": "12345",
            }
        ],
    )
    vehicle_id, delivery_id = await _seed_pending_delivery(db, raw_payload=payload)
    provider = FakeProvider()
    provider.set_parser(VwGroupParser())
    provider.set_mapper(VwGroupMapper())

    reparser = Reparser(db, _registry(provider), clock=lambda: _NOW)
    result = await reparser.parse_pending()

    assert result.parsed == 1
    assert result.failed == 0
    assert await _parse_state(db, delivery_id) == "parsed"

    signal_values = SignalValueRepository()
    async with db.read() as conn:
        grouped = await signal_values.latest_for_vehicle(conn, vehicle_id)
    assert grouped["vehicle.odometer"][0].value_num == 12345.0


async def test_parse_pending_marks_broken_payload_failed(db: Database) -> None:
    _, delivery_id = await _seed_pending_delivery(db, raw_payload=b"not a zip")
    provider = FakeProvider()
    provider.set_parser(VwGroupParser())
    provider.set_mapper(VwGroupMapper())

    reparser = Reparser(db, _registry(provider), clock=lambda: _NOW)
    result = await reparser.parse_pending()

    assert result.parsed == 0
    assert result.failed == 1
    assert await _parse_state(db, delivery_id) == "failed"


async def test_parse_pending_unknown_provider_marks_failed(db: Database) -> None:
    _, delivery_id = await _seed_pending_delivery(db, raw_payload=b"anything")
    reparser = Reparser(db, ProviderRegistry(), clock=lambda: _NOW)

    result = await reparser.parse_pending()

    assert result.failed == 1
    assert await _parse_state(db, delivery_id) == "failed"


async def test_parse_pending_leaves_delivery_pending_without_a_parser(db: Database) -> None:
    _, delivery_id = await _seed_pending_delivery(db, raw_payload=b"anything")
    provider = FakeProvider()  # no parser configured

    reparser = Reparser(db, _registry(provider), clock=lambda: _NOW)
    result = await reparser.parse_pending()

    assert result.parsed == 0
    assert result.failed == 0
    assert await _parse_state(db, delivery_id) == "pending"


async def test_parse_pending_respects_limit(db: Database) -> None:
    point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="1",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    await _seed_pending_delivery(db, raw_payload=b"good", remote_name="a.zip")
    await _seed_pending_delivery(db, raw_payload=b"good", remote_name="b.zip")
    provider = FakeProvider()
    provider.set_parser(FakeParser(points_by_payload={b"good": [point]}))

    reparser = Reparser(db, _registry(provider), clock=lambda: _NOW)
    result = await reparser.parse_pending(limit=1)

    assert result.parsed == 1


async def test_parse_pending_mapping_failure_still_parses(db: Database) -> None:
    point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="1",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    _, delivery_id = await _seed_pending_delivery(db, raw_payload=b"good")
    provider = FakeProvider()
    provider.set_parser(FakeParser(points_by_payload={b"good": [point]}))

    class BrokenMapper:
        mapping_version = "broken-1"

        def map(self, points: Sequence[DataPoint]) -> Iterable[SignalValue]:
            raise RuntimeError("boom")

        def preference(self, signal: str) -> tuple[str, ...]:
            return ()

    provider.set_mapper(BrokenMapper())

    reparser = Reparser(db, _registry(provider), clock=lambda: _NOW)
    result = await reparser.parse_pending()

    assert result.parsed == 1
    assert await _parse_state(db, delivery_id) == "parsed"


async def test_remap_recomputes_signal_values_for_matching_mapping_version(db: Database) -> None:
    payload = _vwgroup_zip(
        _VIN,
        [
            {
                "key": "k1",
                "dataFieldName": "mileage",
                "timestampUtc": "2026-10-01T00:00:00Z",
                "value": "500",
            }
        ],
    )
    vehicle_id, _ = await _seed_pending_delivery(db, raw_payload=payload)
    provider = FakeProvider()
    provider.set_parser(VwGroupParser())
    provider.set_mapper(VwGroupMapper())
    registry = _registry(provider)

    # Parse first so there are stored data points, but with no mapper, so no signal values
    # are written yet; `remap` must derive them from storage alone.
    bare_provider = FakeProvider()
    bare_provider.set_parser(VwGroupParser())
    bare_reparser = Reparser(db, _registry(bare_provider), clock=lambda: _NOW)
    await bare_reparser.parse_pending()

    reparser = Reparser(db, registry, clock=lambda: _NOW)
    result = await reparser.remap("vwgroup-map-1")

    assert result.vehicles == 1
    assert result.values_written == 1

    signal_values = SignalValueRepository()
    async with db.read() as conn:
        grouped = await signal_values.latest_for_vehicle(conn, vehicle_id)
    assert grouped["vehicle.odometer"][0].value_num == 500.0


async def test_remap_is_idempotent(db: Database) -> None:
    payload = _vwgroup_zip(
        _VIN,
        [
            {
                "key": "k1",
                "dataFieldName": "mileage",
                "timestampUtc": "2026-10-01T00:00:00Z",
                "value": "500",
            }
        ],
    )
    await _seed_pending_delivery(db, raw_payload=payload)
    provider = FakeProvider()
    provider.set_parser(VwGroupParser())
    registry = _registry(provider)
    await Reparser(db, registry, clock=lambda: _NOW).parse_pending()

    provider.set_mapper(VwGroupMapper())
    reparser = Reparser(db, registry, clock=lambda: _NOW)
    first = await reparser.remap("vwgroup-map-1")
    second = await reparser.remap("vwgroup-map-1")

    assert first.values_written == 1
    assert second.values_written == 0


async def test_remap_skips_vehicle_whose_provider_mapper_has_a_different_version(
    db: Database,
) -> None:
    payload = _vwgroup_zip(
        _VIN,
        [
            {
                "key": "k1",
                "dataFieldName": "mileage",
                "timestampUtc": "2026-10-01T00:00:00Z",
                "value": "500",
            }
        ],
    )
    await _seed_pending_delivery(db, raw_payload=payload)
    provider = FakeProvider()
    provider.set_parser(VwGroupParser())
    provider.set_mapper(VwGroupMapper())
    registry = _registry(provider)
    await Reparser(db, registry, clock=lambda: _NOW).parse_pending()

    reparser = Reparser(db, registry, clock=lambda: _NOW)
    result = await reparser.remap("some-other-mapping-version")

    assert result.vehicles == 0
    assert result.values_written == 0
