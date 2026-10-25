"""Tests for the data-explorer support in `carchive.storage.repositories`.

`CatalogEntryRepository` and `DataPointRepository.list_fields_for_vehicle`/
`list_field_values`, used by `services.catalog`/`services.explorer`.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from carchive.core.models import DataPoint, TimestampQuality
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.records import CatalogEntryInput
from carchive.storage.repositories import (
    AccountRepository,
    CatalogEntryRepository,
    DataPointRepository,
    DataRequestRepository,
    DeliveryRepository,
    VehicleRepository,
)

_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


async def _seed_delivery(db: Database) -> tuple[UUID, UUID]:
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
            provider_id="vwgroup-euda",
            brand="audi",
            label="acc",
            credential_ref="ref",
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
        await vehicles.add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin="X" * 17,
            label="v",
            brand="audi",
            model=None,
            created_at=_NOW,
        )
        request_id = await requests.upsert(
            conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
        )
        delivery_id = await deliveries.add(
            conn,
            data_request_id=request_id,
            import_batch_id=None,
            remote_name="f.zip",
            delivered_at=_NOW,
            fetched_at=_NOW,
            has_content=True,
            sha256="a" * 64,
            size_bytes=1,
            parse_state="pending",
            parser_version=None,
            raw_payload=None,
        )
    return vehicle_id, delivery_id


class TestListFieldsForVehicle:
    async def test_aggregates_point_count_and_distinct_values(self, db: Database) -> None:
        vehicle_id, delivery_id = await _seed_delivery(db)
        repo = DataPointRepository()
        points = [
            DataPoint(
                key="k1",
                field_name="powerCurve.0.soc",
                value_raw="10",
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            ),
            DataPoint(
                key="k1",
                field_name="powerCurve.1.soc",
                value_raw="20",
                captured_at=_NOW + timedelta(minutes=1),
                captured_at_quality=TimestampQuality.EXACT,
            ),
            DataPoint(
                key="k1",
                field_name="powerCurve.2.soc",
                value_raw="20",
                captured_at=_NOW - timedelta(minutes=1),
                captured_at_quality=TimestampQuality.EXACT,
            ),
        ]
        async with db.write() as conn:
            await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
            )

        async with db.read() as conn:
            fields = await repo.list_fields_for_vehicle(conn, vehicle_id)

        assert len(fields) == 1
        field = fields[0]
        assert field.field_generic == "powerCurve.[*].soc"
        assert field.key == "k1"
        assert field.point_count == 3
        assert field.distinct_value_count == 2
        assert field.first_captured_at == _NOW - timedelta(minutes=1)
        assert field.last_captured_at == _NOW + timedelta(minutes=1)
        assert field.last_value_raw == "20"

    async def test_invalid_timestamps_are_excluded_from_first_last_but_not_from_the_count(
        self, db: Database
    ) -> None:
        vehicle_id, delivery_id = await _seed_delivery(db)
        repo = DataPointRepository()
        points = [
            DataPoint(
                key="k1",
                field_name="mileage",
                value_raw="100",
                captured_at=None,
                captured_at_quality=TimestampQuality.INVALID,
            ),
        ]
        async with db.write() as conn:
            await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
            )

        async with db.read() as conn:
            fields = await repo.list_fields_for_vehicle(conn, vehicle_id)

        assert len(fields) == 1
        assert fields[0].point_count == 1
        assert fields[0].first_captured_at is None
        assert fields[0].last_captured_at is None
        # No valid timestamp anywhere: the "last value" falls back to `last_seen_at`.
        assert fields[0].last_value_raw == "100"

    async def test_no_points_returns_empty_list(self, db: Database) -> None:
        vehicle_id, _ = await _seed_delivery(db)
        repo = DataPointRepository()
        async with db.read() as conn:
            assert await repo.list_fields_for_vehicle(conn, vehicle_id) == []


class TestListFieldValues:
    async def test_returns_newest_first_for_one_generic_field(self, db: Database) -> None:
        vehicle_id, delivery_id = await _seed_delivery(db)
        repo = DataPointRepository()
        points = [
            DataPoint(
                key="k1",
                field_name="powerCurve.0.soc",
                value_raw="10",
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            ),
            DataPoint(
                key="k1",
                field_name="powerCurve.1.soc",
                value_raw="20",
                captured_at=_NOW + timedelta(minutes=1),
                captured_at_quality=TimestampQuality.EXACT,
            ),
            DataPoint(
                key="k2",
                field_name="mileage",
                value_raw="999",
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            ),
        ]
        async with db.write() as conn:
            await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
            )

        async with db.read() as conn:
            values = await repo.list_field_values(conn, vehicle_id, "powerCurve.[*].soc")

        assert [v.value_raw for v in values] == ["20", "10"]

    async def test_limit_caps_the_result(self, db: Database) -> None:
        vehicle_id, delivery_id = await _seed_delivery(db)
        repo = DataPointRepository()
        points = [
            DataPoint(
                key="k1",
                field_name=f"powerCurve.{i}.soc",
                value_raw=str(i),
                captured_at=_NOW + timedelta(minutes=i),
                captured_at_quality=TimestampQuality.EXACT,
            )
            for i in range(5)
        ]
        async with db.write() as conn:
            await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
            )

        async with db.read() as conn:
            values = await repo.list_field_values(conn, vehicle_id, "powerCurve.[*].soc", limit=2)

        assert len(values) == 2
        assert values[0].value_raw == "4"


class TestCatalogEntryRepository:
    async def test_upsert_many_inserts_new_entries(self, db: Database) -> None:
        repo = CatalogEntryRepository()
        entries = [
            CatalogEntryInput(
                key="11111111-1111-1111-1111-111111111111",
                name="mileage",
                description="odometer reading",
                unit="km",
                data_type="int",
                clusters=["General"],
            )
        ]
        async with db.write() as conn:
            counts = await repo.upsert_many(
                conn,
                provider_id="vwgroup-euda",
                catalog_version="6.0",
                kind="continuous",
                entries=entries,
            )

        assert counts.new == 1
        assert counts.updated == 0

        async with db.read() as conn:
            found = await repo.latest_for_keys(
                conn, "vwgroup-euda", ["11111111-1111-1111-1111-111111111111"]
            )
        entry = found["11111111-1111-1111-1111-111111111111"]
        assert entry.name == "mileage"
        assert entry.description == "odometer reading"
        assert entry.clusters == ["General"]
        assert entry.kind == "continuous"

    async def test_upsert_many_updates_an_existing_entry(self, db: Database) -> None:
        repo = CatalogEntryRepository()
        key = "11111111-1111-1111-1111-111111111111"
        async with db.write() as conn:
            await repo.upsert_many(
                conn,
                provider_id="vwgroup-euda",
                catalog_version="6.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key=key,
                        name="old",
                        description=None,
                        unit=None,
                        data_type=None,
                        clusters=None,
                    )
                ],
            )
            counts = await repo.upsert_many(
                conn,
                provider_id="vwgroup-euda",
                catalog_version="6.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key=key,
                        name="new",
                        description="d",
                        unit="%",
                        data_type="float",
                        clusters=["A"],
                    )
                ],
            )

        assert counts.new == 0
        assert counts.updated == 1

        async with db.read() as conn:
            found = await repo.latest_for_keys(conn, "vwgroup-euda", [key])
        assert found[key].name == "new"
        assert found[key].unit == "%"

    async def test_latest_for_keys_prefers_the_newer_catalog_version(self, db: Database) -> None:
        repo = CatalogEntryRepository()
        key = "11111111-1111-1111-1111-111111111111"
        async with db.write() as conn:
            await repo.upsert_many(
                conn,
                provider_id="vwgroup-euda",
                catalog_version="5.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key=key,
                        name="old-name",
                        description=None,
                        unit=None,
                        data_type=None,
                        clusters=None,
                    )
                ],
            )
            await repo.upsert_many(
                conn,
                provider_id="vwgroup-euda",
                catalog_version="6.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key=key,
                        name="new-name",
                        description=None,
                        unit=None,
                        data_type=None,
                        clusters=None,
                    )
                ],
            )

        async with db.read() as conn:
            found = await repo.latest_for_keys(conn, "vwgroup-euda", [key])

        assert found[key].name == "new-name"
        assert found[key].catalog_version == "6.0"

    async def test_latest_for_keys_skips_keys_never_imported(self, db: Database) -> None:
        repo = CatalogEntryRepository()
        async with db.read() as conn:
            found = await repo.latest_for_keys(conn, "vwgroup-euda", ["does-not-exist"])
        assert found == {}

    async def test_upsert_many_with_no_entries_is_a_noop(self, db: Database) -> None:
        repo = CatalogEntryRepository()
        async with db.write() as conn:
            counts = await repo.upsert_many(
                conn,
                provider_id="vwgroup-euda",
                catalog_version="6.0",
                kind="continuous",
                entries=[],
            )
        assert counts.new == 0
        assert counts.updated == 0

    async def test_list_versions_counts_entries_per_version(self, db: Database) -> None:
        repo = CatalogEntryRepository()
        async with db.write() as conn:
            await repo.upsert_many(
                conn,
                provider_id="vwgroup-euda",
                catalog_version="6.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key="11111111-1111-1111-1111-111111111111",
                        name="a",
                        description=None,
                        unit=None,
                        data_type=None,
                        clusters=None,
                    ),
                    CatalogEntryInput(
                        key="22222222-2222-2222-2222-222222222222",
                        name="b",
                        description=None,
                        unit=None,
                        data_type=None,
                        clusters=None,
                    ),
                ],
            )

        async with db.read() as conn:
            versions = await repo.list_versions(conn)

        assert len(versions) == 1
        assert versions[0].provider_id == "vwgroup-euda"
        assert versions[0].catalog_version == "6.0"
        assert versions[0].kind == "continuous"
        assert versions[0].entry_count == 2
