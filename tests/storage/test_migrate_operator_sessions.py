"""Tests for migration `0003` (`operator_sessions`)."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest
from alembic import command

from carchive.storage import migrate


async def _run(db_path: Path, action: str, revision: str) -> None:
    config = migrate._config(db_path)
    await asyncio.to_thread(getattr(command, action), config, revision)


def _table_exists(db_path: Path) -> bool:
    connection = sqlite3.connect(str(db_path))
    try:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'operator_sessions'"
        ).fetchone()
    finally:
        connection.close()
    return row is not None


async def test_head_includes_operator_sessions(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"

    await migrate.upgrade_to_head(db_path)

    assert migrate.head_revision() == "0003"
    assert _table_exists(db_path)


async def test_upgrade_from_0002_keeps_existing_data(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await _run(db_path, "upgrade", "0002")
    assert not _table_exists(db_path)
    connection = sqlite3.connect(str(db_path))
    try:
        connection.execute(
            "INSERT INTO backups (id, created_at, path, size_bytes, sha256, verified) "
            "VALUES ('b1', '2026-10-22 00:00:00', 'x', 1, 'ab', 1)"
        )
        connection.commit()
    finally:
        connection.close()

    previous, new = await migrate.upgrade_to_head(db_path)

    assert (previous, new) == ("0002", "0003")
    assert _table_exists(db_path)
    connection = sqlite3.connect(str(db_path))
    try:
        assert connection.execute("SELECT count(*) FROM backups").fetchone() == (1,)
    finally:
        connection.close()


async def test_token_hash_is_unique(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await migrate.upgrade_to_head(db_path)
    insert = (
        "INSERT INTO operator_sessions (id, token_hash, created_at, last_seen_at, expires_at) "
        "VALUES (?, 'h', '2026-10-23 00:00:00', '2026-10-23 00:00:00', '2026-10-24 00:00:00')"
    )
    connection = sqlite3.connect(str(db_path))
    try:
        connection.execute(insert, ("a",))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert, ("b",))
    finally:
        connection.close()


async def test_downgrade_to_0002_drops_the_table(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await migrate.upgrade_to_head(db_path)

    await _run(db_path, "downgrade", "0002")

    assert not _table_exists(db_path)
