"""Async SQLite connection management: file permissions, pragmas and write serialization."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import ConnectionPoolEntry

# SQLite can run bursts of queries without waiting on disk fsyncs in "normal" sync mode
# because WAL durability already covers crash safety; busy_timeout avoids spurious
# "database is locked" errors from readers overlapping the single writer.
_PRAGMAS = (
    "PRAGMA foreign_keys=ON",
    "PRAGMA journal_mode=WAL",
    "PRAGMA busy_timeout=5000",
    "PRAGMA synchronous=NORMAL",
)


def _set_pragmas(dbapi_connection: object, _connection_record: ConnectionPoolEntry) -> None:
    """Apply the SQLite pragmas to every new DBAPI connection as it is created."""
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    try:
        for pragma in _PRAGMAS:
            cursor.execute(pragma)
    finally:
        cursor.close()


def ensure_owner_only_file(path: Path) -> None:
    """Create `path` with mode 0600 if it does not exist yet, and enforce that mode either way.

    The process umask alone is not a complete defense: a database opened through a different
    entry point (a test, a future embedding) must not depend on the CLI having set it.

    Args:
        path: the file to create/secure. Its parent directory must already exist.
    """
    if not path.exists():
        path.touch(mode=0o600)
    path.chmod(0o600)


class Database:
    """An async SQLite database with owner-only file permissions and serialized writes.

    `read()` yields a connection for read-only use with no further coordination; `write()`
    serializes writers through an in-process lock, since SQLite allows only one writer at a
    time even under WAL. Callers manage their own transaction boundaries via the connection's
    `begin()`/commit/rollback, except `write()`, which wraps the whole block in a transaction
    and rolls back on any exception.
    """

    def __init__(self) -> None:
        self._engine: AsyncEngine | None = None
        self._write_lock = asyncio.Lock()

    async def connect(self, path: Path) -> None:
        """Open the database at `path`, creating it with owner-only permissions if needed.

        Args:
            path: the SQLite database file. Its parent directory must already exist (the
                caller is expected to hold a `DataDirLock` on it).

        Raises:
            RuntimeError: if this `Database` is already connected.
        """
        if self._engine is not None:
            raise RuntimeError("Database is already connected")

        ensure_owner_only_file(path)

        engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
        # `sync_engine` is the underlying sync Engine aiosqlite wraps internally; pool
        # "connect" events are always synchronous, even for the async dialect.
        event.listen(engine.sync_engine, "connect", _set_pragmas)
        self._engine = engine

    @asynccontextmanager
    async def read(self) -> AsyncIterator[AsyncConnection]:
        """Open a connection for reading, without taking the write lock.

        Returns:
            An async context manager yielding an `AsyncConnection`.

        Raises:
            RuntimeError: if this `Database` is not connected.
        """
        engine = self._require_engine()
        async with engine.connect() as conn:
            yield conn

    @asynccontextmanager
    async def write(self) -> AsyncIterator[AsyncConnection]:
        """Open a connection for writing, serialized against every other writer.

        The whole block runs in one transaction, committed on success and rolled back if the
        block raises.

        Returns:
            An async context manager yielding an `AsyncConnection`.

        Raises:
            RuntimeError: if this `Database` is not connected.
        """
        engine = self._require_engine()
        async with self._write_lock, engine.begin() as conn:
            yield conn

    async def close(self) -> None:
        """Dispose of the underlying connection pool."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None

    def _require_engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("Database is not connected")
        return self._engine
