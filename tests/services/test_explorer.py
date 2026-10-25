"""Tests for `carchive.services.explorer`."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from carchive.core.models import DataPoint, TimestampQuality
from carchive.core.provider import ProviderRegistry
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.services.catalog import CatalogService
from carchive.services.explorer import ExplorerService
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
from tests.services.fakes import FakeProvider

_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


def _registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    provider = FakeProvider()
    provider.set_mapper(VwGroupMapper())
    registry.register(provider)
    return registry


async def _seed_vehicle(db: Database, *, provider_id: str = "fake") -> UUID:
    accounts = AccountRepository()
    vehicles = VehicleRepository()
    account_id = uuid4()
    vehicle_id = uuid4()
    async with db.write() as conn:
        await accounts.add(
            conn,
            id=account_id,
            provider_id=provider_id,
            brand="fake",
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
            brand="fake",
            model=None,
            created_at=_NOW,
        )
    return vehicle_id


async def _seed_points(db: Database, vehicle_id: UUID, points: list[DataPoint]) -> None:
    requests = DataRequestRepository()
    deliveries = DeliveryRepository()
    data_points = DataPointRepository()
    async with db.write() as conn:
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
        await data_points.upsert_many(
            conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
        )


class TestFields:
    async def test_returns_none_for_unknown_vehicle(self, db: Database) -> None:
        service = ExplorerService(db, CatalogService(db), _registry())
        assert await service.fields(uuid4()) is None

    async def test_lists_fields_with_no_catalog_imported(self, db: Database) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
                DataPoint(
                    key="k1",
                    field_name="mileage",
                    value_raw="100",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                )
            ],
        )
        service = ExplorerService(db, CatalogService(db), _registry())

        page = await service.fields(vehicle_id)

        assert page is not None
        assert page.catalog_imported is False
        assert page.total == 1
        assert page.items[0].field_generic == "mileage"
        assert page.items[0].catalog_name is None
        assert page.items[0].is_mapped is True

    async def test_catalog_metadata_is_attached_when_imported(self, db: Database) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
                DataPoint(
                    key="k1",
                    field_name="powerCurve.0.soc",
                    value_raw="50",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                )
            ],
        )
        catalog_repo = CatalogEntryRepository()
        async with db.write() as conn:
            await catalog_repo.upsert_many(
                conn,
                provider_id="fake",
                catalog_version="1.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key="k1",
                        name="power curve SoC",
                        description="state of charge at this point",
                        unit="%",
                        data_type="float",
                        clusters=["Charging"],
                    )
                ],
            )
        service = ExplorerService(db, CatalogService(db), _registry())

        page = await service.fields(vehicle_id)

        assert page is not None
        assert page.catalog_imported is True
        field = page.items[0]
        assert field.catalog_name == "power curve SoC"
        assert field.catalog_description == "state of charge at this point"
        assert field.catalog_unit == "%"
        assert field.catalog_clusters == ("Charging",)

    async def test_query_matches_field_name_and_catalog_text(self, db: Database) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
                DataPoint(
                    key="k1",
                    field_name="mileage",
                    value_raw="100",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                ),
                DataPoint(
                    key="k2",
                    field_name="otherField",
                    value_raw="x",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                ),
            ],
        )
        catalog_repo = CatalogEntryRepository()
        async with db.write() as conn:
            await catalog_repo.upsert_many(
                conn,
                provider_id="fake",
                catalog_version="1.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key="k2",
                        name="other",
                        description="mentions odometer somewhere",
                        unit=None,
                        data_type=None,
                        clusters=None,
                    )
                ],
            )
        service = ExplorerService(db, CatalogService(db), _registry())

        by_name = await service.fields(vehicle_id, query="mile")
        by_description = await service.fields(vehicle_id, query="odometer")

        assert by_name is not None and [f.field_generic for f in by_name.items] == ["mileage"]
        assert by_description is not None and [f.field_generic for f in by_description.items] == [
            "otherField"
        ]

    async def test_cluster_filter_matches_only_fields_in_that_cluster(self, db: Database) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
                DataPoint(
                    key="k1",
                    field_name="fieldA",
                    value_raw="1",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                ),
                DataPoint(
                    key="k2",
                    field_name="fieldB",
                    value_raw="2",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                ),
            ],
        )
        catalog_repo = CatalogEntryRepository()
        async with db.write() as conn:
            await catalog_repo.upsert_many(
                conn,
                provider_id="fake",
                catalog_version="1.0",
                kind="continuous",
                entries=[
                    CatalogEntryInput(
                        key="k1",
                        name="a",
                        description=None,
                        unit=None,
                        data_type=None,
                        clusters=["Cluster A"],
                    ),
                    CatalogEntryInput(
                        key="k2",
                        name="b",
                        description=None,
                        unit=None,
                        data_type=None,
                        clusters=["Cluster B"],
                    ),
                ],
            )
        service = ExplorerService(db, CatalogService(db), _registry())

        page = await service.fields(vehicle_id, cluster="Cluster A")

        assert page is not None
        assert [f.field_generic for f in page.items] == ["fieldA"]

    async def test_paging_slices_the_sorted_result(self, db: Database) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
                DataPoint(
                    key=f"k{i}",
                    field_name=f"field{i}",
                    value_raw=str(i),
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                )
                for i in range(5)
            ],
        )
        service = ExplorerService(db, CatalogService(db), _registry())

        page = await service.fields(vehicle_id, limit=2, offset=1)

        assert page is not None
        assert page.total == 5
        assert [f.field_generic for f in page.items] == ["field1", "field2"]

    async def test_unmapped_field_reports_is_mapped_false(self, db: Database) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
                DataPoint(
                    key="k1",
                    field_name="someUninterpretedField",
                    value_raw="1",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                )
            ],
        )
        service = ExplorerService(db, CatalogService(db), _registry())

        page = await service.fields(vehicle_id)

        assert page is not None
        assert page.items[0].is_mapped is False

    async def test_provider_without_a_mapper_treats_every_field_as_unmapped(
        self, db: Database
    ) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
                DataPoint(
                    key="k1",
                    field_name="mileage",
                    value_raw="1",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                )
            ],
        )
        registry = ProviderRegistry()
        registry.register(FakeProvider())  # no mapper configured
        service = ExplorerService(db, CatalogService(db), registry)

        page = await service.fields(vehicle_id)

        assert page is not None
        assert page.items[0].is_mapped is False


class TestFieldValues:
    async def test_returns_none_for_unknown_vehicle(self, db: Database) -> None:
        service = ExplorerService(db, CatalogService(db), _registry())
        assert await service.field_values(uuid4(), "mileage") is None

    async def test_returns_newest_first_with_concrete_field_names(self, db: Database) -> None:
        vehicle_id = await _seed_vehicle(db)
        await _seed_points(
            db,
            vehicle_id,
            [
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
            ],
        )
        service = ExplorerService(db, CatalogService(db), _registry())

        values = await service.field_values(vehicle_id, "powerCurve.[*].soc")

        assert values is not None
        assert [v.field_name for v in values] == ["powerCurve.1.soc", "powerCurve.0.soc"]
