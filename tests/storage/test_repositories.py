"""Tests for `carchive.storage.repositories`."""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from carchive.core.models import DataPoint, SignalValue, TimestampQuality
from carchive.storage.db import Database
from carchive.storage.dedup import dedup_key as compute_dedup_key
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import (
    AccountRepository,
    CollectorRunRepository,
    DataPointRepository,
    DataRequestRepository,
    DeliveryRepository,
    OperatorSessionRepository,
    SignalValueRepository,
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


async def _seed_account(db: Database) -> UUID:
    accounts = AccountRepository()
    account_id = uuid4()
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
    return account_id


async def _seed_vehicle(db: Database, account_id: UUID) -> UUID:
    vehicles = VehicleRepository()
    vehicle_id = uuid4()
    async with db.write() as conn:
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
    return vehicle_id


class TestAccountRepository:
    async def test_add_and_get(self, db: Database) -> None:
        repo = AccountRepository()
        account_id = uuid4()
        async with db.write() as conn:
            await repo.add(
                conn,
                id=account_id,
                provider_id="p",
                brand="audi",
                label="l",
                credential_ref="r",
                state="active",
                state_reason=None,
                created_at=_NOW,
            )
        async with db.read() as conn:
            record = await repo.get(conn, account_id)
        assert record is not None
        assert record.label == "l"
        assert record.state == "active"

    async def test_get_missing_returns_none(self, db: Database) -> None:
        repo = AccountRepository()
        async with db.read() as conn:
            assert await repo.get(conn, uuid4()) is None

    async def test_list_all(self, db: Database) -> None:
        repo = AccountRepository()
        async with db.write() as conn:
            await repo.add(
                conn,
                id=uuid4(),
                provider_id="p",
                brand="audi",
                label="a",
                credential_ref="r",
                state="active",
                state_reason=None,
                created_at=_NOW,
            )
            await repo.add(
                conn,
                id=uuid4(),
                provider_id="p",
                brand="skoda",
                label="b",
                credential_ref="r",
                state="active",
                state_reason=None,
                created_at=_NOW,
            )
        async with db.read() as conn:
            records = await repo.list_all(conn)
        assert len(records) == 2

    async def test_set_state_updates_reason(self, db: Database) -> None:
        repo = AccountRepository()
        account_id = await _seed_account(db)
        async with db.write() as conn:
            await repo.set_state(conn, account_id, "needs_attention", "login layout changed")
        async with db.read() as conn:
            record = await repo.get(conn, account_id)
        assert record is not None
        assert record.state == "needs_attention"
        assert record.state_reason == "login layout changed"

    async def test_set_state_on_missing_account_raises(self, db: Database) -> None:
        repo = AccountRepository()
        with pytest.raises(KeyError):
            async with db.write() as conn:
                await repo.set_state(conn, uuid4(), "disabled", None)

    async def test_list_due_retries_needs_attention_once_overdue(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests_repo = DataRequestRepository()

        async with db.write() as conn:
            overdue = await requests_repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            await requests_repo.set_state(conn, overdue, "needs_attention", "invalid identifier")
            await requests_repo.set_next_due(conn, overdue, _NOW - timedelta(hours=1))

        repo = AccountRepository()
        async with db.read() as conn:
            due_ids = {record.id for record in await repo.list_due(conn, _NOW)}
        assert due_ids == {account_id}

        async with db.write() as conn:
            await requests_repo.set_next_due(conn, overdue, _NOW + timedelta(hours=1))
        async with db.read() as conn:
            due_ids = {record.id for record in await repo.list_due(conn, _NOW)}
        assert due_ids == set()

    async def test_invalid_state_is_rejected_by_check_constraint(self, db: Database) -> None:
        repo = AccountRepository()
        with pytest.raises(IntegrityError):
            async with db.write() as conn:
                await repo.add(
                    conn,
                    id=uuid4(),
                    provider_id="p",
                    brand="audi",
                    label="bad",
                    credential_ref="r",
                    state="bogus",
                    state_reason=None,
                    created_at=_NOW,
                )


class TestVehicleRepository:
    async def test_add_get_list_and_lookup_by_vin(self, db: Database) -> None:
        account_id = await _seed_account(db)
        repo = VehicleRepository()
        vehicle_id = uuid4()
        async with db.write() as conn:
            await repo.add(
                conn,
                id=vehicle_id,
                account_id=account_id,
                vin="WAUZZZ4V0JA123456",
                label="my car",
                brand="audi",
                model="A6 e-tron",
                created_at=_NOW,
            )

        async with db.read() as conn:
            by_id = await repo.get(conn, vehicle_id)
            listed = await repo.list_for_account(conn, account_id)
            by_vin = await repo.get_by_vin(conn, account_id, "WAUZZZ4V0JA123456")
            missing = await repo.get_by_vin(conn, account_id, "DOES-NOT-EXIST")

        assert by_id is not None and by_id.vin == "WAUZZZ4V0JA123456"
        assert len(listed) == 1
        assert by_vin is not None and by_vin.id == vehicle_id
        assert missing is None

    async def test_duplicate_vin_per_account_is_rejected(self, db: Database) -> None:
        account_id = await _seed_account(db)
        repo = VehicleRepository()
        async with db.write() as conn:
            await repo.add(
                conn,
                id=uuid4(),
                account_id=account_id,
                vin="SAME1234567890123",
                label="a",
                brand="audi",
                model=None,
                created_at=_NOW,
            )
        with pytest.raises(IntegrityError):
            async with db.write() as conn:
                await repo.add(
                    conn,
                    id=uuid4(),
                    account_id=account_id,
                    vin="SAME1234567890123",
                    label="b",
                    brand="audi",
                    model=None,
                    created_at=_NOW,
                )


class TestDataRequestRepository:
    async def test_upsert_creates_then_updates_without_resetting_state(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        repo = DataRequestRepository()

        async with db.write() as conn:
            request_id = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r1", interval_s=900
            )
            await repo.set_state(conn, request_id, "needs_attention", "invalid identifier")
            await repo.set_next_due(conn, request_id, _NOW + timedelta(hours=1))

        async with db.write() as conn:
            same_id = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r2", interval_s=600
            )

        assert same_id == request_id
        async with db.read() as conn:
            record = await repo.get(conn, request_id)
            rows = await repo.list_due(conn, _NOW)
        # state and due time survive the re-upsert, so it must not show up as due yet
        assert record is not None
        assert record.state == "needs_attention"
        assert record.state_reason == "invalid identifier"
        assert rows == []

    async def test_list_due_includes_null_and_past_due(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        repo = DataRequestRepository()

        async with db.write() as conn:
            never_run = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            due_later = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="all", remote_id="r", interval_s=900
            )
            await repo.set_next_due(conn, due_later, _NOW + timedelta(hours=1))

        async with db.read() as conn:
            due = {record.id for record in await repo.list_due(conn, _NOW)}

        assert due == {never_run}

    async def test_list_due_retries_needs_attention_once_overdue(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        repo = DataRequestRepository()

        async with db.write() as conn:
            overdue = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            await repo.set_state(conn, overdue, "needs_attention", "invalid identifier")
            await repo.set_next_due(conn, overdue, _NOW - timedelta(hours=1))

            not_yet_due = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="all", remote_id="r", interval_s=900
            )
            await repo.set_state(conn, not_yet_due, "needs_attention", "invalid identifier")
            await repo.set_next_due(conn, not_yet_due, _NOW + timedelta(hours=1))

        async with db.read() as conn:
            due = {record.id for record in await repo.list_due(conn, _NOW)}

        assert due == {overdue}

    async def test_earliest_next_due_considers_overdue_needs_attention(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        repo = DataRequestRepository()

        async with db.write() as conn:
            overdue = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            await repo.set_state(conn, overdue, "needs_attention", "invalid identifier")
            await repo.set_next_due(conn, overdue, _NOW - timedelta(hours=1))

        async with db.read() as conn:
            earliest = await repo.earliest_next_due(conn, _NOW)

        assert earliest == _NOW

    async def test_mark_success_sets_last_success_at(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        repo = DataRequestRepository()
        async with db.write() as conn:
            request_id = await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            await repo.mark_success(conn, request_id, _NOW)

        async with db.read() as conn:
            rows = await repo.list_due(conn, _NOW)
        assert rows[0].last_success_at == _NOW

    async def test_set_next_due_on_missing_request_raises(self, db: Database) -> None:
        repo = DataRequestRepository()
        with pytest.raises(KeyError):
            async with db.write() as conn:
                await repo.set_next_due(conn, uuid4(), _NOW)


class TestDeliveryRepository:
    async def _request(self, db: Database) -> UUID:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        repo = DataRequestRepository()
        async with db.write() as conn:
            return await repo.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )

    async def test_exists_add_and_set_parse_state(self, db: Database) -> None:
        request_id = await self._request(db)
        repo = DeliveryRepository()

        async with db.read() as conn:
            assert await repo.exists(conn, request_id, "f1.zip") is False

        async with db.write() as conn:
            delivery_id = await repo.add(
                conn,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name="f1.zip",
                delivered_at=_NOW,
                fetched_at=_NOW,
                has_content=True,
                sha256="a" * 64,
                size_bytes=100,
                parse_state="pending",
                parser_version=None,
                raw_payload=None,
            )

        async with db.read() as conn:
            assert await repo.exists(conn, request_id, "f1.zip") is True

        async with db.write() as conn:
            await repo.set_parse_state(conn, delivery_id, "parsed", "vwgroup-1")

    async def test_both_parents_set_is_rejected(self, db: Database) -> None:
        request_id = await self._request(db)
        repo = DeliveryRepository()
        with pytest.raises(IntegrityError):
            async with db.write() as conn:
                await repo.add(
                    conn,
                    data_request_id=request_id,
                    import_batch_id=uuid4(),
                    remote_name="f.zip",
                    delivered_at=None,
                    fetched_at=_NOW,
                    has_content=True,
                    sha256="a" * 64,
                    size_bytes=1,
                    parse_state="pending",
                    parser_version=None,
                    raw_payload=None,
                )

    async def test_no_parent_set_is_rejected(self, db: Database) -> None:
        repo = DeliveryRepository()
        with pytest.raises(IntegrityError):
            async with db.write() as conn:
                await repo.add(
                    conn,
                    data_request_id=None,
                    import_batch_id=None,
                    remote_name="f.zip",
                    delivered_at=None,
                    fetched_at=_NOW,
                    has_content=True,
                    sha256="a" * 64,
                    size_bytes=1,
                    parse_state="pending",
                    parser_version=None,
                    raw_payload=None,
                )

    async def test_duplicate_remote_name_per_request_is_rejected(self, db: Database) -> None:
        request_id = await self._request(db)
        repo = DeliveryRepository()
        async with db.write() as conn:
            await repo.add(
                conn,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name="dup.zip",
                delivered_at=None,
                fetched_at=_NOW,
                has_content=True,
                sha256="a" * 64,
                size_bytes=1,
                parse_state="pending",
                parser_version=None,
                raw_payload=None,
            )
        with pytest.raises(IntegrityError):
            async with db.write() as conn:
                await repo.add(
                    conn,
                    data_request_id=request_id,
                    import_batch_id=None,
                    remote_name="dup.zip",
                    delivered_at=None,
                    fetched_at=_NOW,
                    has_content=True,
                    sha256="b" * 64,
                    size_bytes=2,
                    parse_state="pending",
                    parser_version=None,
                    raw_payload=None,
                )

    async def test_set_parse_state_on_missing_delivery_raises(self, db: Database) -> None:
        repo = DeliveryRepository()
        with pytest.raises(KeyError):
            async with db.write() as conn:
                await repo.set_parse_state(conn, uuid4(), "failed")

    async def test_purge_raw_payloads_only_clears_old_parsed_deliveries(self, db: Database) -> None:
        request_id = await self._request(db)
        repo = DeliveryRepository()
        old_parsed = _NOW - timedelta(days=40)
        recent_parsed = _NOW - timedelta(days=1)

        async def _add(name: str, *, fetched_at: datetime, parse_state: str) -> UUID:
            async with db.write() as conn:
                delivery_id = await repo.add(
                    conn,
                    data_request_id=request_id,
                    import_batch_id=None,
                    remote_name=name,
                    delivered_at=fetched_at,
                    fetched_at=fetched_at,
                    has_content=True,
                    sha256="a" * 64,
                    size_bytes=4,
                    parse_state="pending",
                    parser_version=None,
                    raw_payload=b"payload",
                )
                if parse_state != "pending":
                    await repo.set_parse_state(conn, delivery_id, parse_state, "vwgroup-1")
                return delivery_id

        await _add("old-parsed.zip", fetched_at=old_parsed, parse_state="parsed")
        await _add("recent-parsed.zip", fetched_at=recent_parsed, parse_state="parsed")
        await _add("old-pending.zip", fetched_at=old_parsed, parse_state="pending")
        await _add("old-failed.zip", fetched_at=old_parsed, parse_state="failed")

        async with db.write() as conn:
            purged = await repo.purge_raw_payloads(conn, cutoff=_NOW - timedelta(days=30))
        assert purged == 1

        async def _raw_payload(conn: AsyncConnection, remote_name: str) -> bytes | None:
            content = await repo.get_content(conn, request_id, remote_name)
            assert content is not None
            return content.raw_payload

        async with db.read() as conn:
            assert await _raw_payload(conn, "old-parsed.zip") is None
            assert await _raw_payload(conn, "recent-parsed.zip") == b"payload"
            assert await _raw_payload(conn, "old-pending.zip") == b"payload"
            assert await _raw_payload(conn, "old-failed.zip") == b"payload"

        # Re-running is a no-op: already-purged rows have raw_payload = NULL already.
        async with db.write() as conn:
            assert await repo.purge_raw_payloads(conn, cutoff=_NOW - timedelta(days=30)) == 0

    async def test_list_for_vehicle_orders_and_counts_new_points(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        repo = DeliveryRepository()
        points = DataPointRepository()
        async with db.write() as conn:
            request_id = await requests.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            older = await repo.add(
                conn,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name="older.zip",
                delivered_at=_NOW - timedelta(days=2),
                fetched_at=_NOW - timedelta(days=2),
                has_content=True,
                sha256="a" * 64,
                size_bytes=10,
                parse_state="parsed",
                parser_version="v1",
                raw_payload=b"x",
            )
            newer = await repo.add(
                conn,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name="newer.zip",
                delivered_at=_NOW - timedelta(days=1),
                fetched_at=_NOW - timedelta(days=1),
                has_content=True,
                sha256="b" * 64,
                size_bytes=20,
                parse_state="parsed",
                parser_version="v1",
                raw_payload=b"y",
            )
            unconfirmed = await repo.add(
                conn,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name="unconfirmed.zip",
                delivered_at=None,
                fetched_at=_NOW,
                has_content=True,
                sha256="c" * 64,
                size_bytes=30,
                parse_state="parsed",
                parser_version="v1",
                raw_payload=b"z",
            )
            await points.upsert_many(
                conn,
                vehicle_id=vehicle_id,
                delivery_id=newer,
                points=[
                    DataPoint(
                        key="k1",
                        field_name="mileage",
                        value_raw="1",
                        captured_at=_NOW - timedelta(days=1),
                        captured_at_quality=TimestampQuality.EXACT,
                    )
                ],
                seen_at=_NOW,
            )

        async with db.read() as conn:
            records, total = await repo.list_for_vehicle(conn, vehicle_id, limit=50, offset=0)

        assert total == 3
        # Deliveries with a known `delivered_at` sort before the unconfirmed one, newest first.
        assert [record.id for record in records] == [newer, older, unconfirmed]
        newer_record = records[0]
        assert newer_record.new_point_count == 1
        assert newer_record.new_captured_min == _NOW - timedelta(days=1)
        assert newer_record.new_captured_max == _NOW - timedelta(days=1)
        assert records[1].new_point_count == 0
        assert records[1].new_captured_min is None

    async def test_list_for_vehicle_paginates(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        repo = DeliveryRepository()
        async with db.write() as conn:
            request_id = await requests.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            for i in range(3):
                await repo.add(
                    conn,
                    data_request_id=request_id,
                    import_batch_id=None,
                    remote_name=f"f{i}.zip",
                    delivered_at=_NOW - timedelta(days=i),
                    fetched_at=_NOW - timedelta(days=i),
                    has_content=True,
                    sha256=f"{i}" * 64,
                    size_bytes=1,
                    parse_state="parsed",
                    parser_version="v1",
                    raw_payload=None,
                )

        async with db.read() as conn:
            first_page, total = await repo.list_for_vehicle(conn, vehicle_id, limit=2, offset=0)
            second_page, _ = await repo.list_for_vehicle(conn, vehicle_id, limit=2, offset=2)

        assert total == 3
        assert len(first_page) == 2
        assert len(second_page) == 1

    async def test_get_detail_and_get_raw_payload(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        repo = DeliveryRepository()
        async with db.write() as conn:
            request_id = await requests.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )
            delivery_id = await repo.add(
                conn,
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
                raw_payload=b"payload",
            )

        async with db.read() as conn:
            detail = await repo.get_detail(conn, delivery_id)
            assert detail is not None
            assert detail.vehicle_id == vehicle_id
            assert detail.kind == "partial"
            assert detail.source == "portal"
            assert detail.raw_available is True

            payload = await repo.get_raw_payload(conn, delivery_id)
            assert payload == b"payload"

            assert await repo.get_detail(conn, uuid4()) is None
            assert await repo.get_raw_payload(conn, uuid4()) is None


class TestDataPointRepository:
    async def _delivery(self, db: Database) -> tuple[UUID, UUID]:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        deliveries = DeliveryRepository()
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
        return vehicle_id, delivery_id

    async def test_new_points_get_typed_columns_filled(self, db: Database) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        points = [
            DataPoint(
                key="k1",
                field_name="mileage",
                value_raw="12345.5",
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            ),
            DataPoint(
                key="k2",
                field_name="odd",
                value_raw="NaN",
                captured_at=None,
                captured_at_quality=TimestampQuality.INVALID,
            ),
            DataPoint(
                key="k3",
                field_name="when",
                value_raw="2026-10-22T10:00:00Z",
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            ),
            DataPoint(
                key="k4",
                field_name="flag",
                value_raw="true",
                captured_at=None,
                captured_at_quality=TimestampQuality.INVALID,
            ),
            DataPoint(
                key="k5",
                field_name="absent",
                value_raw=None,
                captured_at=None,
                captured_at_quality=TimestampQuality.INVALID,
            ),
        ]

        async with db.write() as conn:
            result = await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
            )

        assert result.new == 5
        assert result.repeated == 0

        from sqlalchemy import select

        from carchive.storage.schema import data_points

        async with db.read() as conn:
            rows = {
                row.key: row
                for row in (
                    await conn.execute(select(data_points).order_by(data_points.c.key))
                ).all()
            }

        assert rows["k1"].value_type == "num"
        assert rows["k1"].value_num == 12345.5
        assert rows["k1"].value_raw == "12345.5"
        assert rows["k2"].value_type == "text"  # "NaN" is text, never a number
        assert rows["k2"].value_raw == "NaN"
        assert rows["k3"].value_type == "time"
        assert rows["k4"].value_type == "bool"
        assert rows["k4"].value_bool is True
        assert rows["k5"].value_type == "null"
        assert rows["k5"].value_raw is None
        for row in rows.values():
            assert row.seen_count == 1
            assert row.first_seen_at == _NOW
            assert row.last_seen_at == _NOW

    async def test_repeated_point_bumps_seen_count_without_changing_value_raw(
        self, db: Database
    ) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        point = DataPoint(
            key="k1",
            field_name="mileage",
            value_raw="100",
            captured_at=_NOW,
            captured_at_quality=TimestampQuality.EXACT,
        )

        async with db.write() as conn:
            first = await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
            )

        later = _NOW + timedelta(minutes=15)
        async with db.write() as conn:
            second = await repo.upsert_many(
                conn,
                vehicle_id=vehicle_id,
                delivery_id=delivery_id,
                points=[point],
                seen_at=later,
            )

        assert first.new == 1
        assert second.new == 0
        assert second.repeated == 1

        from sqlalchemy import select

        from carchive.storage.schema import data_points

        async with db.read() as conn:
            row = (await conn.execute(select(data_points).where(data_points.c.key == "k1"))).first()
        assert row is not None
        assert row.value_raw == "100"
        assert row.seen_count == 2
        assert row.first_seen_at == _NOW
        assert row.last_seen_at == later

    async def test_duplicate_points_within_one_batch_collapse_to_one_row(
        self, db: Database
    ) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        point = DataPoint(
            key="k1",
            field_name="mileage",
            value_raw="100",
            captured_at=_NOW,
            captured_at_quality=TimestampQuality.EXACT,
        )

        async with db.write() as conn:
            result = await repo.upsert_many(
                conn,
                vehicle_id=vehicle_id,
                delivery_id=delivery_id,
                points=[point, point, point],
                seen_at=_NOW,
            )

        assert result.new == 1
        assert result.repeated == 0

    async def test_empty_batch_returns_zero_counts(self, db: Database) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        async with db.write() as conn:
            result = await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[], seen_at=_NOW
            )
        assert result.new == 0
        assert result.repeated == 0

    @pytest.mark.slow
    async def test_one_hundred_thousand_points_complete_quickly(self, db: Database) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        points = [
            DataPoint(
                key=f"k{i}",
                field_name=f"f{i}",
                value_raw=str(i),
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            )
            for i in range(100_000)
        ]

        started = time.monotonic()
        async with db.write() as conn:
            result = await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
            )
        elapsed = time.monotonic() - started

        assert result.new == 100_000
        assert elapsed < 20.0

    async def test_first_seen_by_dedup_keys_resolves_known_and_omits_unknown(
        self, db: Database
    ) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        point = DataPoint(
            key="k1",
            field_name="mileage",
            value_raw="100",
            captured_at=_NOW,
            captured_at_quality=TimestampQuality.EXACT,
        )
        known_key = compute_dedup_key(
            point.key, point.field_name, point.captured_at, point.value_raw
        )
        async with db.write() as conn:
            await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
            )

        unknown_key = compute_dedup_key("nope", "nope", None, None)
        async with db.read() as conn:
            resolved = await repo.first_seen_by_dedup_keys(
                conn, vehicle_id, [known_key, unknown_key]
            )

        assert resolved[known_key] == (delivery_id, _NOW)
        assert unknown_key not in resolved

    async def test_list_first_seen_in_delivery_paginates_by_field_name(self, db: Database) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        points = [
            DataPoint(
                key=f"k{i}",
                field_name=f"f{i}",
                value_raw=str(i),
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            )
            for i in range(3)
        ]
        async with db.write() as conn:
            await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=points, seen_at=_NOW
            )

        async with db.read() as conn:
            page, total = await repo.list_first_seen_in_delivery(
                conn, delivery_id, limit=2, offset=0
            )
            rest, _ = await repo.list_first_seen_in_delivery(conn, delivery_id, limit=2, offset=2)

        assert total == 3
        assert [record.field_name for record in page] == ["f0", "f1"]
        assert [record.field_name for record in rest] == ["f2"]


class TestCollectorRunRepository:
    async def test_add_and_latest_for_request(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        async with db.write() as conn:
            request_id = await requests.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
            )

        repo = CollectorRunRepository()
        async with db.write() as conn:
            await repo.add(
                conn,
                account_id=account_id,
                data_request_id=request_id,
                started_at=_NOW,
                finished_at=_NOW + timedelta(seconds=5),
                outcome="ok",
                listed=10,
                placeholders=2,
                downloaded=8,
                with_content=6,
                pending=2,
                oldest_pending_age_s=120.0,
                message=None,
            )

        async with db.read() as conn:
            latest = await repo.latest_for_request(conn, request_id)
        assert latest is not None
        assert latest.outcome == "ok"
        assert latest.downloaded == 8

    async def test_account_level_run_has_no_data_request(self, db: Database) -> None:
        account_id = await _seed_account(db)
        repo = CollectorRunRepository()
        async with db.write() as conn:
            await repo.add(
                conn,
                account_id=account_id,
                data_request_id=None,
                started_at=_NOW,
                finished_at=_NOW,
                outcome="login_failed",
                listed=None,
                placeholders=None,
                downloaded=None,
                with_content=None,
                pending=None,
                oldest_pending_age_s=None,
                message="login rejected",
            )

        async with db.read() as conn:
            latest = await repo.latest_for_account(conn, account_id)
        assert latest is not None
        assert latest.data_request_id is None
        assert latest.outcome == "login_failed"

    async def test_invalid_outcome_is_rejected_by_check_constraint(self, db: Database) -> None:
        account_id = await _seed_account(db)
        repo = CollectorRunRepository()
        with pytest.raises(IntegrityError):
            async with db.write() as conn:
                await repo.add(
                    conn,
                    account_id=account_id,
                    data_request_id=None,
                    started_at=_NOW,
                    finished_at=_NOW,
                    outcome="bogus",
                    listed=None,
                    placeholders=None,
                    downloaded=None,
                    with_content=None,
                    pending=None,
                    oldest_pending_age_s=None,
                    message=None,
                )


class TestDataPointRepositoryWithSignals:
    """`upsert_many`'s `new_points` and `list_for_vehicle`, used by the mapper/reparse flow."""

    async def _delivery(self, db: Database) -> tuple[UUID, UUID]:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        deliveries = DeliveryRepository()
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
        return vehicle_id, delivery_id

    async def test_upsert_many_returns_ids_for_new_points_only(self, db: Database) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        point = DataPoint(
            key="k1",
            field_name="mileage",
            value_raw="100",
            captured_at=_NOW,
            captured_at_quality=TimestampQuality.EXACT,
        )

        async with db.write() as conn:
            first = await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
            )
        async with db.write() as conn:
            second = await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
            )

        assert len(first.new_points) == 1
        assert first.new_points[0][1] == point
        assert second.new_points == ()

    async def test_list_for_vehicle_reconstructs_stored_points(self, db: Database) -> None:
        vehicle_id, delivery_id = await self._delivery(db)
        repo = DataPointRepository()
        point = DataPoint(
            key="k1",
            field_name="mileage",
            value_raw="100",
            captured_at=_NOW,
            captured_at_quality=TimestampQuality.EXACT,
        )
        async with db.write() as conn:
            await repo.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
            )

        async with db.read() as conn:
            stored = await repo.list_for_vehicle(conn, vehicle_id)

        assert len(stored) == 1
        point_id, stored_point = stored[0]
        assert isinstance(point_id, UUID)
        assert stored_point == point

    async def test_list_for_vehicle_empty_for_unknown_vehicle(self, db: Database) -> None:
        repo = DataPointRepository()
        async with db.read() as conn:
            assert await repo.list_for_vehicle(conn, uuid4()) == []


class TestDeliveryRepositoryPending:
    async def _pending_delivery(
        self,
        db: Database,
        *,
        parse_state: str = "pending",
        raw_payload: bytes | None = b"zip",
        remote_name: str = "f.zip",
        vehicle_id: UUID | None = None,
    ) -> tuple[UUID, UUID]:
        if vehicle_id is None:
            account_id = await _seed_account(db)
            vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        deliveries = DeliveryRepository()
        async with db.write() as conn:
            request_id = await requests.upsert(
                conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
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
                parse_state=parse_state,
                parser_version=None,
                raw_payload=raw_payload,
            )
        return vehicle_id, delivery_id

    async def test_list_pending_includes_vehicle_and_provider_context(self, db: Database) -> None:
        vehicle_id, delivery_id = await self._pending_delivery(db)
        repo = DeliveryRepository()

        async with db.read() as conn:
            pending = await repo.list_pending(conn)

        assert len(pending) == 1
        record = pending[0]
        assert record.delivery_id == delivery_id
        assert record.vehicle_id == vehicle_id
        assert record.provider_id == "vwgroup-euda"
        assert record.request_kind == "partial"
        assert record.raw_payload == b"zip"

    async def test_list_pending_excludes_other_states(self, db: Database) -> None:
        await self._pending_delivery(db, parse_state="parsed")
        repo = DeliveryRepository()
        async with db.read() as conn:
            assert await repo.list_pending(conn) == []

    async def test_list_pending_respects_limit(self, db: Database) -> None:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        await self._pending_delivery(db, remote_name="f1.zip", vehicle_id=vehicle_id)
        await self._pending_delivery(db, remote_name="f2.zip", vehicle_id=vehicle_id)
        repo = DeliveryRepository()
        async with db.read() as conn:
            assert len(await repo.list_pending(conn, limit=1)) == 1


class TestVehicleRepositoryListAll:
    async def test_list_all_includes_archived_vehicles(self, db: Database) -> None:
        account_id = await _seed_account(db)
        await _seed_vehicle(db, account_id)
        vehicles = VehicleRepository()
        async with db.read() as conn:
            all_vehicles = await vehicles.list_all(conn)
        assert len(all_vehicles) == 1


class TestSignalValueRepository:
    async def _data_point_id(self, db: Database) -> tuple[UUID, UUID]:
        account_id = await _seed_account(db)
        vehicle_id = await _seed_vehicle(db, account_id)
        requests = DataRequestRepository()
        deliveries = DeliveryRepository()
        points = DataPointRepository()
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
            point = DataPoint(
                key="k1",
                field_name="mileage",
                value_raw="100",
                captured_at=_NOW,
                captured_at_quality=TimestampQuality.EXACT,
            )
            result = await points.upsert_many(
                conn, vehicle_id=vehicle_id, delivery_id=delivery_id, points=[point], seen_at=_NOW
            )
        return vehicle_id, result.new_points[0][0]

    def _value(self, *, value: float = 123.0, mapping_version: str = "v1") -> SignalValue:
        return SignalValue(
            signal="vehicle.odometer",
            value=value,
            unit="km",
            captured_at=_NOW,
            captured_at_quality=TimestampQuality.EXACT,
            source_key="k1",
            source_field="mileage",
            mapping_version=mapping_version,
        )

    async def test_add_many_inserts_and_latest_for_vehicle_groups_by_signal(
        self, db: Database
    ) -> None:
        vehicle_id, point_id = await self._data_point_id(db)
        repo = SignalValueRepository()
        value = self._value()

        async with db.write() as conn:
            written = await repo.add_many(
                conn, vehicle_id=vehicle_id, values_with_source_ids=[(value, point_id)]
            )
        assert written == 1

        async with db.read() as conn:
            grouped = await repo.latest_for_vehicle(conn, vehicle_id)
        assert list(grouped) == ["vehicle.odometer"]
        assert grouped["vehicle.odometer"][0].value_num == 123.0
        assert grouped["vehicle.odometer"][0].source_data_point_id == point_id

    async def test_add_many_is_idempotent_over_source_signal_and_mapping_version(
        self, db: Database
    ) -> None:
        vehicle_id, point_id = await self._data_point_id(db)
        repo = SignalValueRepository()
        value = self._value()

        async with db.write() as conn:
            await repo.add_many(
                conn, vehicle_id=vehicle_id, values_with_source_ids=[(value, point_id)]
            )
        async with db.write() as conn:
            second_written = await repo.add_many(
                conn, vehicle_id=vehicle_id, values_with_source_ids=[(value, point_id)]
            )

        assert second_written == 0
        async with db.read() as conn:
            grouped = await repo.latest_for_vehicle(conn, vehicle_id)
        assert len(grouped["vehicle.odometer"]) == 1

    async def test_add_many_keeps_both_mapping_versions(self, db: Database) -> None:
        vehicle_id, point_id = await self._data_point_id(db)
        repo = SignalValueRepository()
        v1 = self._value(value=1.0, mapping_version="v1")
        v2 = self._value(value=2.0, mapping_version="v2")

        async with db.write() as conn:
            await repo.add_many(
                conn, vehicle_id=vehicle_id, values_with_source_ids=[(v1, point_id)]
            )
        async with db.write() as conn:
            await repo.add_many(
                conn, vehicle_id=vehicle_id, values_with_source_ids=[(v2, point_id)]
            )

        async with db.read() as conn:
            grouped = await repo.latest_for_vehicle(conn, vehicle_id)
        assert {row.mapping_version for row in grouped["vehicle.odometer"]} == {"v1", "v2"}

    async def test_add_many_empty_input_returns_zero(self, db: Database) -> None:
        vehicle_id, _ = await self._data_point_id(db)
        repo = SignalValueRepository()
        async with db.write() as conn:
            assert await repo.add_many(conn, vehicle_id=vehicle_id, values_with_source_ids=[]) == 0

    async def test_latest_for_vehicle_empty_for_unknown_vehicle(self, db: Database) -> None:
        repo = SignalValueRepository()
        async with db.read() as conn:
            assert await repo.latest_for_vehicle(conn, uuid4()) == {}


class TestOperatorSessionRepository:
    async def _add(
        self, db: Database, token_hash: str, *, last_seen: datetime, expires: datetime
    ) -> None:
        async with db.write() as conn:
            await OperatorSessionRepository().add(
                conn,
                id=uuid4(),
                token_hash=token_hash,
                created_at=_NOW,
                last_seen_at=last_seen,
                expires_at=expires,
            )

    async def test_add_get_touch_delete(self, db: Database) -> None:
        repo = OperatorSessionRepository()
        await self._add(db, "h1", last_seen=_NOW, expires=_NOW + timedelta(days=1))

        async with db.read() as conn:
            record = await repo.get_by_token_hash(conn, "h1")
            assert await repo.get_by_token_hash(conn, "other") is None
        assert record is not None
        assert (record.last_seen_at, record.expires_at) == (_NOW, _NOW + timedelta(days=1))

        later = _NOW + timedelta(minutes=5)
        async with db.write() as conn:
            await repo.touch(conn, record.id, later)
        async with db.write() as conn:
            assert await repo.delete_by_token_hash(conn, "h1") == 1
            assert await repo.delete_by_token_hash(conn, "h1") == 0

    async def test_duplicate_token_hash_is_rejected(self, db: Database) -> None:
        await self._add(db, "h1", last_seen=_NOW, expires=_NOW + timedelta(days=1))
        with pytest.raises(IntegrityError):
            await self._add(db, "h1", last_seen=_NOW, expires=_NOW + timedelta(days=1))

    async def test_delete_expired_and_delete_all(self, db: Database) -> None:
        repo = OperatorSessionRepository()
        day = timedelta(days=1)
        await self._add(db, "fresh", last_seen=_NOW, expires=_NOW + day)
        await self._add(db, "old", last_seen=_NOW, expires=_NOW - day)
        await self._add(db, "idle", last_seen=_NOW - day, expires=_NOW + day)

        async with db.write() as conn:
            deleted = await repo.delete_expired(
                conn, expired_before=_NOW, idle_before=_NOW - timedelta(hours=12)
            )
        assert deleted == 2
        async with db.write() as conn:
            assert await repo.delete_all(conn) == 1
