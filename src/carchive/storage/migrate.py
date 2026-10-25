"""Programmatic Alembic configuration: no `alembic.ini` anywhere in the repository.

A bare `alembic` CLI invocation would otherwise have nowhere to read its target database
from except an accidental default; every migration always runs through `upgrade_to_head`
with an explicit database path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from carchive.storage.db import ensure_owner_only_file

_MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _base_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    return config


def _config(db_path: Path) -> Config:
    config = _base_config()
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return config


def head_revision() -> str | None:
    """Return the latest revision id known to the migration scripts, or `None` if there are none.

    Reads only the version scripts on disk, no database access.
    """
    script_dir = ScriptDirectory.from_config(_base_config())
    return script_dir.get_current_head()


def _read_revision(connection: Connection) -> str | None:
    return MigrationContext.configure(connection).get_current_revision()


async def current_revision(db_path: Path) -> str | None:
    """Return the revision `db_path` is currently stamped at.

    Args:
        db_path: path to the SQLite database file.

    Returns:
        The current revision id, or `None` if the file does not exist yet or has never been
        migrated (no `alembic_version` table).
    """
    if not db_path.exists():
        return None

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        async with engine.connect() as connection:
            return await connection.run_sync(_read_revision)
    finally:
        await engine.dispose()


async def upgrade_to_head(db_path: Path) -> tuple[str | None, str | None]:
    """Upgrade `db_path` to the latest migration, creating the file if it does not exist.

    Args:
        db_path: path to the SQLite database file.

    Returns:
        A `(previous_revision, new_revision)` pair; `previous_revision` is `None` for a
        database that had never been migrated.
    """
    config = _config(db_path)
    previous = await current_revision(db_path)
    # Alembic's own engine would otherwise create the file with whatever default permissions
    # the process umask leaves, bypassing Database.connect's 0600 guarantee.
    ensure_owner_only_file(db_path)
    # Alembic's `command` module drives its async env.py with its own `asyncio.run`; running
    # it in a worker thread avoids nesting that inside the event loop already running here.
    await asyncio.to_thread(command.upgrade, config, "head")
    new = await current_revision(db_path)
    return previous, new


async def downgrade_to_base(db_path: Path) -> None:
    """Downgrade `db_path` to before the first migration (drops every managed table).

    Args:
        db_path: path to the SQLite database file.
    """
    config = _config(db_path)
    await asyncio.to_thread(command.downgrade, config, "base")
