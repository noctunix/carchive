"""Tests for `carchive.services.backup`."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import os
import sqlite3
import stat
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from carchive.services.backup import BackupError, BackupFile, BackupService
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import AccountRepository, VehicleRepository
from carchive.storage.schema import accounts, backups, vehicles

_NOW = datetime(2026, 10, 22, 3, 0, 0, tzinfo=UTC)


async def _connected_db(db_path: Path) -> Database:
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    return database


async def _seed(database: Database, label: str) -> None:
    account_repo = AccountRepository()
    vehicle_repo = VehicleRepository()
    account_id = uuid4()
    async with database.write() as conn:
        await account_repo.add(
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
        await vehicle_repo.add(
            conn,
            id=uuid4(),
            account_id=account_id,
            vin=f"{label.upper():*>17}"[:17],
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )


def _minimal_sqlite_bytes(tmp_path: Path) -> bytes:
    """Return the bytes of a tiny, valid, standalone SQLite database file."""
    scratch = tmp_path / ".scratch.sqlite3"
    conn = sqlite3.connect(str(scratch))
    try:
        conn.execute("CREATE TABLE t (x)")
        conn.commit()
    finally:
        conn.close()
    data = scratch.read_bytes()
    scratch.unlink()
    return data


def _write_archive(path: Path, content: bytes) -> None:
    """Write a gzip archive and a matching, correctly formatted checksum sidecar."""
    with gzip.open(path, "wb") as gz:
        gz.write(content)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")


# --- create -------------------------------------------------------------------


async def test_create_produces_a_verified_owner_only_backup(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    await _seed(database, "a")
    backup_dir = tmp_path / "backups"
    service = BackupService(db_path, backup_dir, database, clock=lambda: _NOW)

    path = await service.create()

    assert stat.S_IMODE(backup_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    checksum_path = path.with_name(path.name + ".sha256")
    assert stat.S_IMODE(checksum_path.stat().st_mode) == 0o600
    service.verify(path)  # does not raise
    await database.close()


async def test_create_records_a_successful_row_in_backups_table(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)

    path = await service.create()

    async with database.read() as conn:
        row = (await conn.execute(select(backups))).one()
    assert row.verified is True
    assert row.error is None
    assert row.path == str(path)
    assert row.size_bytes > 0
    await database.close()


async def test_create_while_db_has_concurrent_writes_still_produces_a_valid_backup(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)

    async def _write_loop() -> None:
        for i in range(20):
            await _seed(database, f"writer-{i}")
            await asyncio.sleep(0)

    _, path = await asyncio.gather(_write_loop(), service.create())

    service.verify(path)  # the snapshot itself must still be internally consistent
    await database.close()


async def test_create_failure_leaves_no_temp_file_and_records_an_error_row(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "not-a-file.sqlite3"
    db_path.mkdir()  # sqlite3 cannot open a directory as a database file
    database = await _connected_db(tmp_path / "carchive.sqlite3")
    backup_dir = tmp_path / "backups"
    service = BackupService(db_path, backup_dir, database, clock=lambda: _NOW)

    with pytest.raises(BackupError):
        await service.create()

    leftovers = list(backup_dir.iterdir()) if backup_dir.is_dir() else []
    assert leftovers == []
    async with database.read() as conn:
        row = (await conn.execute(select(backups))).one()
    assert row.verified is False
    assert row.error is not None
    await database.close()


async def test_create_with_a_frozen_clock_refuses_to_overwrite_the_first_backup(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)

    first = await service.create()
    first_bytes = first.read_bytes()

    with pytest.raises(BackupError, match="already exists"):
        await service.create()

    assert first.read_bytes() == first_bytes
    assert len(service.list_backups()) == 1
    async with database.read() as conn:
        rows = (await conn.execute(select(backups))).all()
    assert [row.verified for row in rows] == [True, False]
    await database.close()


async def test_create_without_db_does_not_touch_backups_table(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    service = BackupService(db_path, tmp_path / "backups", None, clock=lambda: _NOW)

    path = await service.create()

    assert path.is_file()


# --- verify ---------------------------------------------------------------------


async def test_verify_detects_a_missing_checksum_file(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)
    path = await service.create()
    path.with_name(path.name + ".sha256").unlink()

    with pytest.raises(BackupError, match="checksum"):
        service.verify(path)
    await database.close()


async def test_verify_detects_a_tampered_checksum(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)
    path = await service.create()
    checksum_path = path.with_name(path.name + ".sha256")
    checksum_path.write_text(f"{'0' * 64}  {path.name}\n")

    with pytest.raises(BackupError, match="mismatch"):
        service.verify(path)
    await database.close()


async def test_verify_detects_truncated_gzip(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    path = backup_dir / "carchive-20261022T030000Z.sqlite3.gz"
    _write_archive(path, b"not actually used, overwritten below")
    # Truncate after the checksum was computed over the full file, so the checksum still
    # matches the file as it existed on disk a moment ago but gzip can no longer decode it.
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")

    service = BackupService(tmp_path / "carchive.sqlite3", backup_dir, None, clock=lambda: _NOW)

    with pytest.raises(BackupError):
        service.verify(path)


async def test_verify_detects_a_corrupt_database_inside_a_valid_archive(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    path = backup_dir / "carchive-20261022T030000Z.sqlite3.gz"
    _write_archive(path, b"this is not a sqlite database")
    service = BackupService(tmp_path / "carchive.sqlite3", backup_dir, None, clock=lambda: _NOW)

    with pytest.raises(BackupError):
        service.verify(path)


async def test_verify_rejects_a_missing_archive(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    path = backup_dir / "carchive-20261022T030000Z.sqlite3.gz"
    path.with_name(path.name + ".sha256").write_text(f"{'0' * 64}  {path.name}\n")
    service = BackupService(tmp_path / "carchive.sqlite3", backup_dir, None, clock=lambda: _NOW)

    with pytest.raises(BackupError):
        service.verify(path)


# --- list_backups / prune --------------------------------------------------------


def _touch_backup(backup_dir: Path, created_at: datetime, content: bytes = b"x") -> Path:
    name = f"carchive-{created_at.strftime('%Y%m%dT%H%M%SZ')}.sqlite3.gz"
    path = backup_dir / name
    _write_archive(path, content)
    return path


async def test_list_backups_ignores_foreign_files(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    kept = _touch_backup(backup_dir, _NOW)
    (backup_dir / "notes.txt").write_text("not a backup")
    (backup_dir / "carchive-bad-name.sqlite3.gz").write_text("not a backup either")
    service = BackupService(tmp_path / "carchive.sqlite3", backup_dir, None, clock=lambda: _NOW)

    result = service.list_backups()

    assert [f.path for f in result] == [kept]


async def test_prune_keeps_gfs_window_and_leaves_foreign_files(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    base = datetime(2026, 10, 22, 3, 30, 0, tzinfo=UTC)
    foreign = backup_dir / "not-a-backup.txt"
    foreign.write_text("leave me alone")
    sqlite_bytes = _minimal_sqlite_bytes(tmp_path)

    # One backup per day for the last 8 months.
    created: list[Path] = []
    for days_ago in range(0, 8 * 30, 1):
        created_at = base - timedelta(days=days_ago)
        created.append(_touch_backup(backup_dir, created_at, sqlite_bytes))

    service = BackupService(
        tmp_path / "carchive.sqlite3",
        backup_dir,
        None,
        clock=lambda: base,
        keep_daily=7,
        keep_weekly=4,
        keep_monthly=6,
    )

    deleted = service.prune(base)

    assert foreign.is_file()
    remaining = {f.path for f in service.list_backups()}
    assert len(remaining) <= 7 + 4 + 6
    assert created[0] in remaining  # the newest backup is always kept
    assert set(deleted) | remaining == set(created)
    for path in deleted:
        assert not path.exists()
        assert not path.with_name(path.name + ".sha256").exists()


async def test_prune_deletes_nothing_when_the_newest_backup_fails_verification(
    tmp_path: Path,
) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    _touch_backup(backup_dir, _NOW - timedelta(days=10))
    newest = _touch_backup(backup_dir, _NOW)
    newest.with_name(newest.name + ".sha256").write_text(f"{'0' * 64}  {newest.name}\n")
    service = BackupService(
        tmp_path / "carchive.sqlite3", backup_dir, None, clock=lambda: _NOW, keep_daily=1
    )

    deleted = service.prune(_NOW)

    assert deleted == []
    assert len(service.list_backups()) == 2


async def test_prune_on_empty_directory_deletes_nothing(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    service = BackupService(tmp_path / "carchive.sqlite3", backup_dir, None, clock=lambda: _NOW)

    assert service.prune(_NOW) == []


# --- restore ----------------------------------------------------------------------


async def test_restore_round_trips_row_counts_and_moves_old_db_aside(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    await _seed(database, "original")
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)
    backup_path = await service.create()
    await database.close()

    # Simulate the WAL/SHM sidecar files a live server might leave behind.
    wal_path = db_path.with_name(db_path.name + "-wal")
    shm_path = db_path.with_name(db_path.name + "-shm")
    wal_path.write_bytes(b"fake-wal")
    shm_path.write_bytes(b"fake-shm")

    # Mutate the live database after the backup, so a restore is actually observable.
    live = Database()
    await live.connect(db_path)
    await _seed(live, "added-after-backup")
    await live.close()

    moved_aside = (await service.restore(backup_path, db_path)).previous_db

    assert moved_aside is not None
    assert moved_aside.is_file()
    assert not wal_path.is_file()
    assert not shm_path.is_file()

    restored = Database()
    await restored.connect(db_path)
    async with restored.read() as conn:
        account_rows = (await conn.execute(select(accounts))).all()
        vehicle_rows = (await conn.execute(select(vehicles))).all()
    await restored.close()
    assert len(account_rows) == 1
    assert len(vehicle_rows) == 1
    assert account_rows[0].label == "original"


async def test_restore_without_an_existing_database_returns_none(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    await _seed(database, "a")
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)
    backup_path = await service.create()
    await database.close()
    db_path.unlink()

    moved_aside = (await service.restore(backup_path, db_path)).previous_db

    assert moved_aside is None
    assert db_path.is_file()


async def test_restore_refuses_a_backup_that_fails_verification(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    path = backup_dir / "carchive-20261022T030000Z.sqlite3.gz"
    _write_archive(path, b"this is not a sqlite database")
    service = BackupService(db_path, backup_dir, None, clock=lambda: _NOW)
    original_bytes = db_path.read_bytes()

    with pytest.raises(BackupError):
        await service.restore(path, db_path)

    assert db_path.read_bytes() == original_bytes
    assert list(backup_dir.glob(".tmp-*")) == []


# --- latest_verified_age / due ----------------------------------------------------


async def test_latest_verified_age_without_db_returns_none(tmp_path: Path) -> None:
    service = BackupService(
        tmp_path / "carchive.sqlite3", tmp_path / "backups", None, clock=lambda: _NOW
    )

    assert await service.latest_verified_age(_NOW) is None


async def test_latest_verified_age_with_no_backups_returns_none(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)

    age = await service.latest_verified_age(_NOW)

    assert age is None
    await database.close()


async def test_latest_verified_age_reports_time_since_the_newest_successful_backup(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    database = await _connected_db(db_path)
    service = BackupService(db_path, tmp_path / "backups", database, clock=lambda: _NOW)
    await service.create()

    later = _NOW + timedelta(hours=5)
    age = await service.latest_verified_age(later)

    assert age == timedelta(hours=5)
    await database.close()


@pytest.fixture(autouse=True)
def _utc_local_time() -> Iterator[None]:
    """Pin the process's local timezone to UTC for `due()`'s local-time comparisons."""
    previous = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    yield
    if previous is None:
        del os.environ["TZ"]
    else:
        os.environ["TZ"] = previous
    time.tzset()


class TestDue:
    def test_not_due_before_backup_time_today(self) -> None:
        now = datetime(2026, 10, 22, 2, 0, 0, tzinfo=UTC)
        assert BackupService.due(now, None, "03:30") is False

    def test_due_after_backup_time_with_no_prior_backup(self) -> None:
        now = datetime(2026, 10, 22, 4, 0, 0, tzinfo=UTC)
        assert BackupService.due(now, None, "03:30") is True

    def test_not_due_when_already_backed_up_after_todays_threshold(self) -> None:
        now = datetime(2026, 10, 22, 10, 0, 0, tzinfo=UTC)
        last_backup_at = datetime(2026, 10, 22, 3, 45, 0, tzinfo=UTC)
        assert BackupService.due(now, last_backup_at, "03:30") is False

    def test_due_when_last_backup_was_before_todays_threshold(self) -> None:
        now = datetime(2026, 10, 22, 10, 0, 0, tzinfo=UTC)
        last_backup_at = datetime(2026, 10, 22, 1, 0, 0, tzinfo=UTC)
        assert BackupService.due(now, last_backup_at, "03:30") is True

    def test_due_when_last_backup_was_yesterday(self) -> None:
        now = datetime(2026, 10, 22, 10, 0, 0, tzinfo=UTC)
        last_backup_at = datetime(2026, 10, 21, 23, 0, 0, tzinfo=UTC)
        assert BackupService.due(now, last_backup_at, "03:30") is True

    def test_not_due_just_after_midnight_even_without_a_prior_backup(self) -> None:
        now = datetime(2026, 10, 22, 0, 5, 0, tzinfo=UTC)
        assert BackupService.due(now, None, "03:30") is False


def test_backup_file_is_a_plain_data_holder(tmp_path: Path) -> None:
    backup_file = BackupFile(tmp_path / "x", _NOW, 123)
    assert backup_file.size_bytes == 123
