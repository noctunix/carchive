"""Tests for migration `0002`'s `data_points.field_generic` backfill."""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from pathlib import Path

from alembic import command

from carchive.storage import migrate


async def _upgrade_to(db_path: Path, revision: str) -> None:
    """Run `command.upgrade` off the running event loop, like `migrate.upgrade_to_head` does."""
    config = migrate._config(db_path)
    await asyncio.to_thread(command.upgrade, config, revision)


def _insert_data_point(db_path: Path, field_name: str) -> str:
    """Insert one minimal `data_points` row directly, bypassing foreign keys (off by default
    on a raw `sqlite3` connection), and return its id.
    """
    point_id = str(uuid.uuid4())
    connection = sqlite3.connect(str(db_path))
    try:
        connection.execute(
            """
            INSERT INTO data_points (
                id, vehicle_id, key, field_name, value_raw, value_type, value_num,
                value_text, value_bool, value_time, captured_at, captured_at_quality,
                first_delivery_id, first_seen_at, last_seen_at, seen_count, dedup_key
            ) VALUES (?, ?, ?, ?, ?, 'text', NULL, ?, NULL, NULL, NULL, 'invalid', ?, ?, ?, 1, ?)
            """,
            (
                point_id,
                str(uuid.uuid4()),
                "some-key",
                field_name,
                "value",
                "value",
                str(uuid.uuid4()),
                "2026-10-22T00:00:00+00:00",
                "2026-10-22T00:00:00+00:00",
                str(uuid.uuid4()),
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return point_id


def _field_generic(db_path: Path, point_id: str) -> str | None:
    connection = sqlite3.connect(str(db_path))
    try:
        row = connection.execute(
            "SELECT field_generic FROM data_points WHERE id = ?", (point_id,)
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    value: str | None = row[0]
    return value


async def test_upgrade_backfills_field_generic_for_existing_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await _upgrade_to(db_path, "0001")

    point_id = _insert_data_point(db_path, "powerCurve.3.timeCurve.17.soc")

    await _upgrade_to(db_path, "head")

    assert _field_generic(db_path, point_id) == "powerCurve.[*].timeCurve.[*].soc"


async def test_upgrade_backfills_many_rows_across_batches(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await _upgrade_to(db_path, "0001")

    point_ids = [_insert_data_point(db_path, f"series.{i}.value") for i in range(5)]

    await _upgrade_to(db_path, "head")

    for point_id in point_ids:
        assert _field_generic(db_path, point_id) == "series.[*].value"
