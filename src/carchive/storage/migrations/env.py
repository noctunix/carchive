"""Alembic runtime environment: migrates over an async SQLite engine, SQLite batch mode on.

Loaded by Alembic's `command` functions, never imported directly; `storage.migrate` builds
the `Config` this module reads from `context.config`.
"""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from carchive.storage.schema import metadata

config = context.config
target_metadata = metadata


def _do_run_migrations(connection: Connection) -> None:
    """Configure Alembic against `connection` and run the pending migrations."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite's ALTER TABLE cannot drop/modify columns or constraints; batch mode
        # works around that by rebuilding the table instead.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_migrations_online() -> None:
    """Open an async engine for the configured URL and run migrations through it."""
    url = config.get_main_option("sqlalchemy.url")
    if url is None:
        raise RuntimeError("no sqlalchemy.url configured for this migration run")

    connectable = create_async_engine(url)
    try:
        async with connectable.connect() as connection:
            await connection.run_sync(_do_run_migrations)
    finally:
        await connectable.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline migrations are not supported")

asyncio.run(_run_migrations_online())
