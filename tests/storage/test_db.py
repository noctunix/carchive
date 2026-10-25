"""Tests for `carchive.storage.db`."""

from __future__ import annotations

import asyncio
import stat
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from carchive.storage.db import Database, ensure_owner_only_file
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.schema import accounts, vehicles


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


def _account_values(label: str = "acc") -> dict[str, object]:
    return {
        "id": uuid4(),
        "provider_id": "vwgroup-euda",
        "brand": "audi",
        "label": label,
        "credential_ref": "ref",
        "state": "active",
        "state_reason": None,
        "created_at": datetime.now(UTC),
    }


async def test_connect_creates_file_with_owner_only_permissions(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    db_path.chmod(0o644)

    database = Database()
    await database.connect(db_path)
    try:
        assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    finally:
        await database.close()


def test_ensure_owner_only_file_creates_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "new.sqlite3"

    ensure_owner_only_file(path)

    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_ensure_owner_only_file_fixes_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "existing.sqlite3"
    path.write_text("not actually a database")
    path.chmod(0o644)

    ensure_owner_only_file(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == "not actually a database"


async def test_connecting_twice_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    try:
        with pytest.raises(RuntimeError, match="already connected"):
            await database.connect(db_path)
    finally:
        await database.close()


async def test_read_or_write_before_connect_raises() -> None:
    database = Database()
    with pytest.raises(RuntimeError, match="not connected"):
        async with database.read():
            pass
    with pytest.raises(RuntimeError, match="not connected"):
        async with database.write():
            pass


async def test_foreign_keys_are_enforced(db: Database) -> None:
    with pytest.raises(IntegrityError):
        async with db.write() as conn:
            await conn.execute(
                insert(vehicles).values(
                    id=uuid4(),
                    account_id=uuid4(),
                    vin="X" * 17,
                    label="v",
                    brand="audi",
                    model=None,
                    created_at=datetime.now(UTC),
                    archived_at=None,
                )
            )


async def test_write_rolls_back_on_exception(db: Database) -> None:
    class _BoomError(Exception):
        pass

    with pytest.raises(_BoomError):
        async with db.write() as conn:
            await conn.execute(insert(accounts).values(**_account_values()))
            raise _BoomError

    async with db.read() as conn:
        rows = (await conn.execute(select(accounts))).all()
    assert rows == []


async def test_write_commits_on_success(db: Database) -> None:
    async with db.write() as conn:
        await conn.execute(insert(accounts).values(**_account_values()))

    async with db.read() as conn:
        rows = (await conn.execute(select(accounts))).all()
    assert len(rows) == 1


async def test_two_concurrent_writes_run_one_after_the_other(db: Database) -> None:
    order: list[str] = []

    async def writer(label: str, delay: float) -> None:
        async with db.write() as conn:
            order.append(f"start-{label}")
            await asyncio.sleep(delay)
            await conn.execute(insert(accounts).values(**_account_values(label)))
            order.append(f"end-{label}")

    await asyncio.gather(writer("a", 0.05), writer("b", 0.0))

    # Whichever writer started first must also finish before the other one starts;
    # if the lock were not serializing them, the two "start" entries would be adjacent.
    assert order.index("end-a") < order.index("start-b") or order.index("end-b") < order.index(
        "start-a"
    )
