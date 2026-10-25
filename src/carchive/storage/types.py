"""Portable SQLAlchemy column types shared by every table in `schema.py`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    """A timezone-aware UTC `datetime`, stored and read back identically on every dialect.

    SQLite has no native timezone-aware storage, so values are normalized to UTC and written
    as naive UTC; every dialect reads them back as timezone-aware UTC. Naive input is rejected
    rather than assumed to be UTC, so a missing timezone upstream surfaces immediately instead
    of silently picking a zone.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        """Normalize `value` to UTC before it is sent to the database.

        Args:
            value: the value bound to the column, or `None`.
            dialect: the dialect in use (unused; behavior is dialect-independent).

        Returns:
            `value` converted to UTC, or `None`.

        Raises:
            ValueError: if `value` is a naive `datetime` (no timezone).
        """
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("UTCDateTime requires a timezone-aware datetime, got a naive value")
        return value.astimezone(UTC)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        """Return `value` as a timezone-aware UTC `datetime`.

        Args:
            value: the value read from the database, or `None`.
            dialect: the dialect in use (unused; behavior is dialect-independent).

        Returns:
            `value` with UTC attached (SQLite returns naive UTC) or converted to UTC
            (PostgreSQL returns timezone-aware values already), or `None`.
        """
        if value is None:
            return None
        parsed: datetime = value
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
