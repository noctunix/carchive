"""Tests for `carchive.services.collector`."""

from __future__ import annotations

import io
import json
import logging
import zipfile
from collections.abc import AsyncGenerator, Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from carchive.core.errors import (
    AuthenticationError,
    NeedsAttentionError,
    RateLimitedError,
    TransientError,
)
from carchive.core.models import (
    DataPoint,
    RemoteDataRequest,
    RemoteDelivery,
    SignalValue,
    TimestampQuality,
)
from carchive.core.provider import ProviderRegistry
from carchive.core.redact import register_secret
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.providers.vwgroup.parser import VwGroupParser
from carchive.services.collector import Collector
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import (
    AccountRepository,
    CollectorRunRepository,
    DataPointRepository,
    DataRequestRepository,
    DeliveryRepository,
    SignalValueRepository,
    VehicleRepository,
)
from tests.services.fakes import FakeParser, FakeProvider

_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
_VIN = "WAUZZZ4V0JA123456"
_PASSWORD = "s3cret-password"


def _delivery(name: str, *, has_content: bool = True, age_minutes: int = 0) -> RemoteDelivery:
    return RemoteDelivery(
        remote_name=name,
        delivered_at=_NOW - timedelta(minutes=age_minutes),
        has_content=has_content,
    )


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


async def _seed_account(db: Database, *, credential_ref: str = "ref1") -> UUID:
    repo = AccountRepository()
    account_id = uuid4()
    async with db.write() as conn:
        await repo.add(
            conn,
            id=account_id,
            provider_id="fake",
            brand="fake",
            label="acc",
            credential_ref=credential_ref,
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
    return account_id


async def _seed_vehicle(db: Database, account_id: UUID, vin: str = _VIN) -> UUID:
    repo = VehicleRepository()
    vehicle_id = uuid4()
    async with db.write() as conn:
        await repo.add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin=vin,
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
    return vehicle_id


def _registry(provider: FakeProvider) -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(provider)
    return registry


def _credentials_for(table: dict[str, dict[str, str]]) -> Callable[[str], dict[str, str]]:
    def lookup(ref: str) -> dict[str, str]:
        return table[ref]

    return lookup


async def _force_all_requests_due(db: Database, account_id: UUID, now: datetime) -> None:
    async with db.write() as conn:
        requests_repo = DataRequestRepository()
        vehicle_id = (await VehicleRepository().list_for_account(conn, account_id))[0].id
        for request in await requests_repo.list_for_vehicle(conn, vehicle_id):
            await requests_repo.set_next_due(conn, request.id, now)


def _collector(
    db: Database,
    provider: FakeProvider,
    credentials: dict[str, dict[str, str]],
    *,
    max_downloads: int = 50,
    clock: Callable[[], datetime] = lambda: _NOW,
) -> Collector:
    return Collector(
        db,
        _registry(provider),
        _credentials_for(credentials),
        max_downloads=max_downloads,
        interval_s=900,
        clock=clock,
        rng=None,
    )


async def test_first_run_discovers_and_downloads_oldest_first(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [
        _delivery("20261001000200_f2.zip", age_minutes=200),
        _delivery("20261001000100_f1.zip", age_minutes=300),
        _delivery("20261001000300_ph.zip", has_content=False, age_minutes=100),
    ]
    for d in provider.deliveries_by_remote_id["r1"]:
        provider.payloads[d.remote_name] = b"content" if d.has_content else b""

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await collector.run_account(account_id)

    assert result.login_outcome == "ok"
    assert len(result.request_results) == 1
    assert result.request_results[0].outcome == "ok"
    assert result.request_results[0].downloaded == 3

    deliveries = DeliveryRepository()
    requests = DataRequestRepository()
    runs = CollectorRunRepository()
    async with db.read() as conn:
        due_requests = await requests.list_for_vehicle(conn, vehicle_id)
        assert len(due_requests) == 1
        request_id = due_requests[0].id
        for name, _has_content in (
            ("20261001000100_f1.zip", True),
            ("20261001000200_f2.zip", True),
            ("20261001000300_ph.zip", False),
        ):
            assert await deliveries.exists(conn, request_id, name)
        latest_run = await runs.latest_for_request(conn, request_id)

    assert latest_run is not None
    assert latest_run.outcome == "ok"
    assert latest_run.listed == 3
    assert latest_run.placeholders == 1
    assert latest_run.downloaded == 3

    from sqlalchemy import select

    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        rows = {
            row.remote_name: row for row in (await conn.execute(select(deliveries_table))).all()
        }
    assert rows["20261001000300_ph.zip"].has_content is False
    assert rows["20261001000300_ph.zip"].parse_state == "empty"
    assert rows["20261001000100_f1.zip"].parse_state == "pending"


async def test_second_run_does_not_redownload(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
    provider.payloads["20261001000100_f1.zip"] = b"content"

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    await collector.run_account(account_id)

    await _force_all_requests_due(db, account_id, _NOW)

    result = await collector.run_account(account_id)

    assert provider.download_calls == 1
    assert result.request_results[0].downloaded == 0


async def test_fake_parser_writes_data_points(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
    provider.payloads["20261001000100_f1.zip"] = b"good"
    point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="100",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    provider.set_parser(FakeParser(points_by_payload={b"good": [point]}))

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    await collector.run_account(account_id)

    data_points = DataPointRepository()
    from sqlalchemy import select

    from carchive.storage.schema import data_points as data_points_table
    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        rows = (await conn.execute(select(data_points_table))).all()
        delivery_row = (await conn.execute(select(deliveries_table))).first()
    assert len(rows) == 1
    assert rows[0].vehicle_id == vehicle_id
    assert delivery_row is not None
    assert delivery_row.parse_state == "parsed"
    del data_points


async def test_parser_error_marks_delivery_failed_and_continues(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_bad.zip")]
    provider.payloads["20261001000100_bad.zip"] = b"bad"
    provider.set_parser(FakeParser(fail_on={b"bad"}))

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await collector.run_account(account_id)

    assert result.request_results[0].outcome == "ok"

    from sqlalchemy import select

    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        row = (await conn.execute(select(deliveries_table))).first()
    assert row is not None
    assert row.parse_state == "failed"


async def test_max_downloads_caps_a_single_run(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    names = [f"2026100100{i:02d}00_f{i}.zip" for i in range(5)]
    provider.deliveries_by_remote_id["r1"] = [_delivery(n) for n in names]
    for n in names:
        provider.payloads[n] = b"c"

    collector = _collector(
        db, provider, {"ref1": {"user": "user", "password": _PASSWORD}}, max_downloads=2
    )
    first = await collector.run_account(account_id)
    assert first.request_results[0].downloaded == 2

    from sqlalchemy import select

    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        count = len((await conn.execute(select(deliveries_table))).all())
    assert count == 2

    await _force_all_requests_due(db, account_id, _NOW)

    second = await collector.run_account(account_id)
    assert second.request_results[0].downloaded == 2

    async with db.read() as conn:
        count = len((await conn.execute(select(deliveries_table))).all())
    assert count == 4


async def test_wrong_password_sets_needs_attention_without_download(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": "wrong"}})
    result = await collector.run_account(account_id)

    assert result.login_outcome == "login_failed"
    assert provider.download_calls == 0

    accounts = AccountRepository()
    async with db.read() as conn:
        account = await accounts.get(conn, account_id)
    assert account is not None
    assert account.state == "needs_attention"


async def test_successful_login_after_needs_attention_reactivates_account(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)

    bad = _collector(db, provider, {"ref1": {"user": "user", "password": "wrong"}})
    await bad.run_account(account_id)

    good = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await good.run_account(account_id)

    assert result.login_outcome == "ok"
    accounts = AccountRepository()
    async with db.read() as conn:
        account = await accounts.get(conn, account_id)
    assert account is not None
    assert account.state == "active"


async def test_missing_credential_reference_sets_needs_attention(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db, credential_ref="missing-ref")
    await _seed_vehicle(db, account_id)

    collector = _collector(db, provider, {})
    result = await collector.run_account(account_id)

    assert result.login_outcome == "login_failed"
    assert provider.login_calls == 0
    accounts = AccountRepository()
    async with db.read() as conn:
        account = await accounts.get(conn, account_id)
    assert account is not None
    assert account.state == "needs_attention"


async def test_rate_limit_keeps_already_stored_deliveries_and_ends_run(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="all", remote_id="r1"),
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r2"),
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
    provider.payloads["20261001000100_f1.zip"] = b"c"
    provider.deliveries_by_remote_id["r2"] = [_delivery("20261001000100_g1.zip")]
    provider.list_errors["r2"] = [RateLimitedError(retry_after_s=30.0)]

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await collector.run_account(account_id)

    outcomes = {r.outcome for r in result.request_results}
    assert "rate_limited" in outcomes
    assert "ok" in outcomes

    from sqlalchemy import select

    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        rows = (await conn.execute(select(deliveries_table))).all()
    assert len(rows) == 1
    assert rows[0].remote_name == "20261001000100_f1.zip"


async def test_transient_error_on_one_request_does_not_stop_others(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1"),
        RemoteDataRequest(vin=_VIN, kind="all", remote_id="r2"),
    ]
    provider.deliveries_by_remote_id["r1"] = []
    provider.list_errors["r2"] = [TransientError("network blip")]
    provider.deliveries_by_remote_id["r2"] = [_delivery("20261001000100_g1.zip")]

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await collector.run_account(account_id)

    outcomes = {r.outcome for r in result.request_results}
    assert outcomes == {"ok", "error"}


async def test_backoff_sequence_over_consecutive_failures(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]

    requests = DataRequestRepository()
    vehicles = VehicleRepository()
    expected_minutes = [15, 30, 60, 120, 240, 360, 360]
    now = _NOW

    def _frozen_clock(frozen_now: datetime) -> Callable[[], datetime]:
        return lambda: frozen_now

    for expected in expected_minutes:
        provider.list_errors["r1"] = [TransientError("boom")]
        collector = _collector(
            db,
            provider,
            {"ref1": {"user": "user", "password": _PASSWORD}},
            clock=_frozen_clock(now),
        )
        await collector.run_account(account_id)

        async with db.read() as conn:
            vehicle_id = (await vehicles.list_for_account(conn, account_id))[0].id
            request = (await requests.list_for_vehicle(conn, vehicle_id))[0]
        assert request.next_due_at is not None
        assert request.next_due_at - now == timedelta(minutes=expected)

        # advance past the computed due time so the next iteration's run finds it due again
        now = request.next_due_at


async def test_exactly_one_login_per_run_and_session_closed_on_exception(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.list_errors["r1"] = [TransientError("boom")]

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    await collector.run_account(account_id)

    assert provider.login_calls == 1
    assert provider.close_calls == 1


async def test_canary_no_password_or_full_vin_in_run_message_or_logs(
    db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    register_secret(_PASSWORD)
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.login_errors = [AuthenticationError(f"login failed for {_VIN} with {_PASSWORD}")]

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    with caplog.at_level(logging.DEBUG):
        await collector.run_account(account_id)

    runs = CollectorRunRepository()
    async with db.read() as conn:
        run = await runs.latest_for_account(conn, account_id)
    assert run is not None
    assert run.message is not None
    assert _PASSWORD not in run.message
    assert _VIN not in run.message
    for record in caplog.records:
        assert _PASSWORD not in record.getMessage()
        assert _VIN not in record.getMessage()


async def test_needs_attention_at_request_level_sets_request_state(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.list_errors["r1"] = [NeedsAttentionError("invalid identifier")]

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await collector.run_account(account_id)

    assert result.request_results[0].outcome == "error"
    requests = DataRequestRepository()
    async with db.read() as conn:
        request = (await requests.list_for_vehicle(conn, vehicle_id))[0]
    assert request.state == "needs_attention"
    assert request.state_reason == "invalid identifier"


async def test_needs_attention_request_is_retried_and_reactivated_once_due(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
    provider.payloads["20261001000100_f1.zip"] = b"content"
    provider.list_errors["r1"] = [NeedsAttentionError("invalid identifier")]

    now = _NOW
    collector = _collector(
        db, provider, {"ref1": {"user": "user", "password": _PASSWORD}}, clock=lambda: now
    )

    first = await collector.run_account(account_id)
    assert first.request_results[0].outcome == "error"

    requests = DataRequestRepository()
    async with db.read() as conn:
        request = (await requests.list_for_vehicle(conn, vehicle_id))[0]
    assert request.state == "needs_attention"
    assert request.state_reason == "invalid identifier"

    # Still well within the delay: a second run must not retry it yet.
    second = await collector.run_account(account_id)
    assert second.request_results == ()

    # Past the delay: the request is retried, downloads normally and reactivates.
    now = _NOW + timedelta(hours=6, seconds=1)
    third = await collector.run_account(account_id)
    assert third.request_results[0].outcome == "ok"
    assert third.request_results[0].downloaded == 1

    async with db.read() as conn:
        request = (await requests.list_for_vehicle(conn, vehicle_id))[0]
    assert request.state == "active"
    assert request.state_reason is None


async def test_discovery_failure_is_recorded_as_an_account_level_run(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.discover_errors[_VIN] = [TransientError("portal unreachable")]

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await collector.run_account(account_id)

    assert result.login_outcome == "ok"
    assert result.request_results == ()

    runs = CollectorRunRepository()
    async with db.read() as conn:
        run = await runs.latest_for_account(conn, account_id)
    assert run is not None
    assert run.data_request_id is None
    assert run.outcome == "error"
    assert run.message is not None
    assert "discovery failed" in run.message
    assert "portal unreachable" in run.message
    assert _VIN not in run.message


async def test_parsing_runs_off_the_event_loop(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
    provider.payloads["20261001000100_f1.zip"] = b"good"

    seen_threads: list[int] = []

    class ThreadRecordingParser:
        parser_version = "thread-recording-1"

        def parse(self, payload: bytes, context: object) -> list[DataPoint]:
            import threading

            seen_threads.append(threading.get_ident())
            return [
                DataPoint(
                    key="k1",
                    field_name="mileage",
                    value_raw="1",
                    captured_at=_NOW,
                    captured_at_quality=TimestampQuality.EXACT,
                )
            ]

    provider.set_parser(ThreadRecordingParser())
    import threading

    main_thread = threading.get_ident()

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    await collector.run_account(account_id)

    assert len(seen_threads) == 1
    assert seen_threads[0] != main_thread

    deliveries = DeliveryRepository()
    requests = DataRequestRepository()
    async with db.read() as conn:
        request_id = (await requests.list_for_vehicle(conn, vehicle_id))[0].id
        assert await deliveries.exists(conn, request_id, "20261001000100_f1.zip")

    from sqlalchemy import select

    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        row = (await conn.execute(select(deliveries_table))).first()
    assert row is not None
    assert row.parse_state == "parsed"


def _vwgroup_zip(vin: str, records: list[dict[str, object]]) -> bytes:
    document = {"vin": vin, "userId": "11111111-1111-1111-1111-111111111111", "Data": records}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dataset.json", json.dumps(document))
    return buf.getvalue()


async def test_real_parser_and_mapper_write_data_points_and_signal_values(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
    payload = _vwgroup_zip(
        _VIN,
        [
            {
                "key": "k1",
                "dataFieldName": "mileage",
                "timestampUtc": "2026-10-01T00:00:00Z",
                "value": "12345",
            },
            {
                "key": "k2",
                "dataFieldName": "currentSOCInPct",
                "timestampUtc": "2026-10-01T00:00:00Z",
                "value": "80",
            },
            {
                "key": "k3",
                "dataFieldName": "someUnmappedField",
                "timestampUtc": "2026-10-01T00:00:00Z",
                "value": "x",
            },
        ],
    )
    provider.payloads["20261001000100_f1.zip"] = payload
    provider.set_parser(VwGroupParser())
    provider.set_mapper(VwGroupMapper())

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    await collector.run_account(account_id)

    data_points = DataPointRepository()
    signal_values = SignalValueRepository()
    async with db.read() as conn:
        points = await data_points.list_for_vehicle(conn, vehicle_id)
        grouped = await signal_values.latest_for_vehicle(conn, vehicle_id)

    assert len(points) == 3
    assert set(grouped) == {"vehicle.odometer", "battery.soc"}
    assert grouped["vehicle.odometer"][0].value_num == 12345.0
    assert grouped["battery.soc"][0].value_num == 80.0

    from sqlalchemy import select

    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        delivery_row = (await conn.execute(select(deliveries_table))).first()
    assert delivery_row is not None
    assert delivery_row.parser_version == "vwgroup-records-1"


async def test_repeated_delivery_does_not_duplicate_signal_values(db: Database) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
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
    provider.payloads["20261001000100_f1.zip"] = payload
    provider.set_parser(VwGroupParser())
    provider.set_mapper(VwGroupMapper())

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    await collector.run_account(account_id)
    await _force_all_requests_due(db, account_id, _NOW)
    await collector.run_account(account_id)

    signal_values = SignalValueRepository()
    async with db.read() as conn:
        grouped = await signal_values.latest_for_vehicle(conn, vehicle_id)
    assert len(grouped["vehicle.odometer"]) == 1


async def test_mapping_failure_does_not_lose_the_delivery(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(password=_PASSWORD)
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id)
    provider.data_requests_by_vin[_VIN] = [
        RemoteDataRequest(vin=_VIN, kind="partial", remote_id="r1")
    ]
    provider.deliveries_by_remote_id["r1"] = [_delivery("20261001000100_f1.zip")]
    point = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="100",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    provider.payloads["20261001000100_f1.zip"] = b"good"
    provider.set_parser(FakeParser(points_by_payload={b"good": [point]}))

    class BrokenMapper:
        mapping_version = "broken-1"

        def map(self, points: Sequence[DataPoint]) -> Iterable[SignalValue]:
            raise RuntimeError("mapping exploded")

        def preference(self, signal: str) -> tuple[str, ...]:
            return ()

    provider.set_mapper(BrokenMapper())

    collector = _collector(db, provider, {"ref1": {"user": "user", "password": _PASSWORD}})
    result = await collector.run_account(account_id)

    assert result.request_results[0].outcome == "ok"

    from sqlalchemy import select

    from carchive.storage.schema import data_points as data_points_table
    from carchive.storage.schema import deliveries as deliveries_table

    async with db.read() as conn:
        rows = (await conn.execute(select(data_points_table))).all()
        delivery_row = (await conn.execute(select(deliveries_table))).first()
    assert len(rows) == 1
    assert delivery_row is not None
    assert delivery_row.parse_state == "parsed"
