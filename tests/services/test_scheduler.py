"""Tests for `carchive.services.scheduler`."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import AsyncGenerator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from carchive.services.backup import BackupOptions, BackupService
from carchive.services.collector import AccountRunResult
from carchive.services.scheduler import Scheduler
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import (
    AccountRepository,
    DataRequestRepository,
    DeliveryRepository,
    VehicleRepository,
)

_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
_BEFORE_BACKUP_TIME = datetime(2026, 10, 22, 2, 0, 0, tzinfo=UTC)


class FakeCollector:
    """Records `run_account` calls and concurrency, replaying configured outcomes."""

    def __init__(self) -> None:
        self.started: list[UUID] = []
        self.finished: list[UUID] = []
        self.active = 0
        self.max_concurrent = 0
        self.outcomes: dict[UUID, BaseException | AccountRunResult] = {}

    async def run_account(self, account_id: UUID) -> AccountRunResult:
        self.active += 1
        self.max_concurrent = max(self.max_concurrent, self.active)
        self.started.append(account_id)
        await asyncio.sleep(0)
        self.active -= 1
        self.finished.append(account_id)
        outcome = self.outcomes[account_id]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture(autouse=True)
def _utc_local_time() -> Iterator[None]:
    """Pin the process's local timezone to UTC for `BackupService.due`'s comparisons."""
    previous = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    yield
    if previous is None:
        del os.environ["TZ"]
    else:
        os.environ["TZ"] = previous
    time.tzset()


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


async def _seed_due_account(db: Database, label: str) -> UUID:
    accounts = AccountRepository()
    vehicles = VehicleRepository()
    requests = DataRequestRepository()
    account_id = uuid4()
    vehicle_id = uuid4()
    async with db.write() as conn:
        await accounts.add(
            conn,
            id=account_id,
            provider_id="fake",
            brand="fake",
            label=label,
            credential_ref="ref",
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
        await vehicles.add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin=f"{label.upper():*>17}"[:17],
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
        await requests.upsert(
            conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
        )
    return account_id


async def test_run_once_processes_due_accounts_sequentially(db: Database) -> None:
    account_a = await _seed_due_account(db, "a")
    account_b = await _seed_due_account(db, "b")
    collector = FakeCollector()
    collector.outcomes[account_a] = AccountRunResult(account_a, "ok", ())
    collector.outcomes[account_b] = AccountRunResult(account_b, "ok", ())

    scheduler = Scheduler(collector, db, clock=lambda: _NOW)  # type: ignore[arg-type]
    results = await scheduler.run_once()

    assert {r.account_id for r in results} == {account_a, account_b}
    assert collector.max_concurrent == 1


async def test_run_once_continues_after_one_account_raises(
    db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    account_a = await _seed_due_account(db, "a")
    account_b = await _seed_due_account(db, "b")
    collector = FakeCollector()
    collector.outcomes[account_a] = RuntimeError("boom")
    collector.outcomes[account_b] = AccountRunResult(account_b, "ok", ())

    scheduler = Scheduler(collector, db, clock=lambda: _NOW)  # type: ignore[arg-type]
    with caplog.at_level(logging.ERROR):
        results = await scheduler.run_once()

    assert {r.account_id for r in results} == {account_b}
    assert account_a in collector.finished


async def test_run_ends_cleanly_when_stop_is_set(db: Database) -> None:
    collector = FakeCollector()
    sleep_calls: list[float] = []
    stop = asyncio.Event()

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        stop.set()

    scheduler = Scheduler(collector, db, clock=lambda: _NOW, sleep=fake_sleep, poll_cap_s=60.0)  # type: ignore[arg-type]

    await scheduler.run(stop)

    assert sleep_calls == [60.0]
    assert collector.started == []


async def test_stop_ends_the_sleep_immediately_instead_of_waiting_the_full_poll_cap(
    db: Database,
) -> None:
    """`stop` must cut the sleep short, not just be checked after it finishes.

    Uses the real clock and the real `asyncio.sleep` (no `sleep=` override) so this
    exercises the actual race, not a fake that happens to return quickly.
    """
    collector = FakeCollector()
    stop = asyncio.Event()
    scheduler = Scheduler(collector, db, clock=lambda: _NOW, poll_cap_s=60.0)  # type: ignore[arg-type]

    run_task = asyncio.ensure_future(scheduler.run(stop))
    await asyncio.sleep(0.05)  # let run() enter its 60s sleep before stopping it
    started = time.monotonic()
    stop.set()
    await asyncio.wait_for(run_task, timeout=2.0)
    elapsed = time.monotonic() - started

    assert elapsed < 1.0


async def test_run_continues_the_loop_after_run_once_raises(db: Database) -> None:
    collector = FakeCollector()
    stop = asyncio.Event()
    calls: list[int] = []

    async def flaky_run_once() -> list[AccountRunResult]:
        calls.append(len(calls))
        if len(calls) == 1:
            raise RuntimeError("boom")
        stop.set()
        return []

    async def fake_sleep(_seconds: float) -> None:
        return None

    scheduler = Scheduler(collector, db, clock=lambda: _NOW, sleep=fake_sleep, poll_cap_s=60.0)  # type: ignore[arg-type]
    scheduler.run_once = flaky_run_once  # type: ignore[method-assign]

    await scheduler.run(stop)

    assert len(calls) == 2


async def test_sleep_duration_is_capped_at_poll_cap_s(db: Database) -> None:
    accounts = AccountRepository()
    vehicles = VehicleRepository()
    requests = DataRequestRepository()
    account_id = uuid4()
    vehicle_id = uuid4()
    async with db.write() as conn:
        await accounts.add(
            conn,
            id=account_id,
            provider_id="fake",
            brand="fake",
            label="c",
            credential_ref="ref",
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
        await vehicles.add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin="C" * 17,
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
        request_id = await requests.upsert(
            conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
        )
        await requests.set_next_due(conn, request_id, _NOW + timedelta(seconds=500))

    collector = FakeCollector()
    stop = asyncio.Event()
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        stop.set()

    scheduler = Scheduler(collector, db, clock=lambda: _NOW, sleep=fake_sleep, poll_cap_s=60.0)  # type: ignore[arg-type]

    await scheduler.run(stop)

    assert sleep_calls == [60.0]


async def test_sleep_duration_reaches_exactly_the_next_due_time_under_the_cap(
    db: Database,
) -> None:
    accounts = AccountRepository()
    vehicles = VehicleRepository()
    requests = DataRequestRepository()
    account_id = uuid4()
    vehicle_id = uuid4()
    async with db.write() as conn:
        await accounts.add(
            conn,
            id=account_id,
            provider_id="fake",
            brand="fake",
            label="c",
            credential_ref="ref",
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
        await vehicles.add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin="D" * 17,
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
        request_id = await requests.upsert(
            conn, vehicle_id=vehicle_id, kind="partial", remote_id="r", interval_s=900
        )
        await requests.set_next_due(conn, request_id, _NOW + timedelta(seconds=10))

    collector = FakeCollector()
    stop = asyncio.Event()
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        stop.set()

    scheduler = Scheduler(collector, db, clock=lambda: _NOW, sleep=fake_sleep, poll_cap_s=60.0)  # type: ignore[arg-type]

    await scheduler.run(stop)

    assert sleep_calls == [10.0]


# --- backup integration -----------------------------------------------------------


async def test_run_once_creates_a_backup_once_due(db: Database, tmp_path: Path) -> None:
    backup = BackupService(tmp_path / "carchive.sqlite3", tmp_path / "backups", db)
    scheduler = Scheduler(
        FakeCollector(),  # type: ignore[arg-type]
        db,
        clock=lambda: _NOW,
        backup=backup,
        backup_time="03:30",
    )

    await scheduler.run_once()

    assert len(backup.list_backups()) == 1


async def test_run_once_does_not_back_up_before_backup_time(db: Database, tmp_path: Path) -> None:
    backup = BackupService(tmp_path / "carchive.sqlite3", tmp_path / "backups", db)
    scheduler = Scheduler(
        FakeCollector(),  # type: ignore[arg-type]
        db,
        clock=lambda: _BEFORE_BACKUP_TIME,
        backup=backup,
        backup_time="03:30",
    )

    await scheduler.run_once()

    assert backup.list_backups() == []


async def test_run_once_backs_up_at_most_once_per_day(db: Database, tmp_path: Path) -> None:
    backup = BackupService(tmp_path / "carchive.sqlite3", tmp_path / "backups", db)
    scheduler = Scheduler(
        FakeCollector(),  # type: ignore[arg-type]
        db,
        clock=lambda: _NOW,
        backup=backup,
        backup_time="03:30",
    )

    await scheduler.run_once()
    await scheduler.run_once()

    assert len(backup.list_backups()) == 1


async def test_run_once_logs_and_continues_when_backup_creation_fails(
    db: Database, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    backup = BackupService(
        tmp_path / "does-not-exist" / "carchive.sqlite3", tmp_path / "backups", db
    )
    collector = FakeCollector()
    scheduler = Scheduler(
        collector,  # type: ignore[arg-type]
        db,
        clock=lambda: _NOW,
        backup=backup,
        backup_time="03:30",
    )

    results = await scheduler.run_once()

    assert results == []
    assert backup.list_backups() == []
    assert "scheduler.backup_failed" in capsys.readouterr().out


async def test_run_once_fails_loudly_for_credentials_without_encryption(
    db: Database, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_path = tmp_path / "cfg" / "secrets.toml"
    secrets_path.parent.mkdir()
    secrets_path.write_text("")
    secrets_path.chmod(0o600)
    backup = BackupService(
        tmp_path / "carchive.sqlite3",
        tmp_path / "backups",
        db,
        options=BackupOptions(include_credentials=True, secrets_path=secrets_path),
    )
    scheduler = Scheduler(
        FakeCollector(),  # type: ignore[arg-type]
        db,
        clock=lambda: _NOW,
        backup=backup,
        backup_time="03:30",
    )

    await scheduler.run_once()

    out = capsys.readouterr().out
    assert "scheduler.backup_failed" in out
    assert "unencrypted" in out
    assert "error" in out
    assert backup.list_backups() == []


# --- raw payload retention ---------------------------------------------------------


async def _seed_parsed_delivery(
    db: Database, *, remote_name: str, fetched_at: datetime, parse_state: str = "parsed"
) -> None:
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
            label=remote_name,
            credential_ref="ref",
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
        await vehicles.add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin=f"{remote_name.upper():*>17}"[:17],
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
        request_id = await requests.upsert(
            conn, vehicle_id=vehicle_id, kind="partial", remote_id=remote_name, interval_s=900
        )
        delivery_id = await deliveries.add(
            conn,
            data_request_id=request_id,
            import_batch_id=None,
            remote_name=remote_name,
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
            await deliveries.set_parse_state(conn, delivery_id, parse_state, "vwgroup-1")


async def _raw_payload_is_cleared(db: Database, remote_name: str) -> bool:
    async with db.read() as conn:
        rows = (
            await conn.execute(
                text("SELECT raw_payload FROM deliveries WHERE remote_name = :name"),
                {"name": remote_name},
            )
        ).all()
    assert len(rows) == 1
    return rows[0].raw_payload is None


async def test_run_once_purges_old_parsed_raw_payloads(db: Database) -> None:
    await _seed_parsed_delivery(db, remote_name="old.zip", fetched_at=_NOW - timedelta(days=40))
    await _seed_parsed_delivery(db, remote_name="recent.zip", fetched_at=_NOW - timedelta(days=1))
    scheduler = Scheduler(
        FakeCollector(),  # type: ignore[arg-type]
        db,
        clock=lambda: _NOW,
        raw_payload_retention_days=30,
    )

    await scheduler.run_once()

    assert await _raw_payload_is_cleared(db, "old.zip") is True
    assert await _raw_payload_is_cleared(db, "recent.zip") is False


async def test_run_once_keeps_raw_payloads_forever_when_retention_is_none(db: Database) -> None:
    await _seed_parsed_delivery(db, remote_name="old.zip", fetched_at=_NOW - timedelta(days=4000))
    scheduler = Scheduler(
        FakeCollector(),  # type: ignore[arg-type]
        db,
        clock=lambda: _NOW,
        raw_payload_retention_days=None,
    )

    await scheduler.run_once()

    assert await _raw_payload_is_cleared(db, "old.zip") is False


async def test_run_once_logs_and_continues_when_purge_fails(
    db: Database, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def _boom(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr(DeliveryRepository, "purge_raw_payloads", _boom)
    scheduler = Scheduler(
        FakeCollector(),  # type: ignore[arg-type]
        db,
        clock=lambda: _NOW,
        raw_payload_retention_days=30,
    )

    results = await scheduler.run_once()

    assert results == []
    assert "scheduler.raw_payload_purge_failed" in capsys.readouterr().out
