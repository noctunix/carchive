"""Tests for `carchive.storage.migrate`."""

from __future__ import annotations

import stat
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

from carchive.storage import schema
from carchive.storage.migrate import (
    current_revision,
    downgrade_to_base,
    head_revision,
    upgrade_to_head,
)


async def test_upgrade_from_empty_reaches_head(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"

    previous, new = await upgrade_to_head(db_path)

    assert previous is None
    assert new == head_revision()
    assert await current_revision(db_path) == new


async def test_downgrade_to_base_then_upgrade_again_reaches_head(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)

    await downgrade_to_base(db_path)
    assert await current_revision(db_path) is None

    previous, new = await upgrade_to_head(db_path)
    assert previous is None
    assert new == head_revision()


async def test_migrated_schema_matches_metadata_exactly(tmp_path: Path) -> None:
    """A migrated database must have no drift from `schema.metadata` (Alembic's own check)."""
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)

    sync_engine = create_engine(f"sqlite:///{db_path}")
    try:
        with sync_engine.connect() as conn:
            context = MigrationContext.configure(conn)
            diffs = compare_metadata(context, schema.metadata)
    finally:
        sync_engine.dispose()

    assert diffs == [], f"schema drift between migration and schema.py: {diffs}"


async def test_current_revision_is_none_for_nonexistent_file(tmp_path: Path) -> None:
    assert await current_revision(tmp_path / "does-not-exist.sqlite3") is None


async def test_upgrade_creates_the_file_owner_only(tmp_path: Path) -> None:
    db_path = tmp_path / "carchive.sqlite3"

    await upgrade_to_head(db_path)

    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
