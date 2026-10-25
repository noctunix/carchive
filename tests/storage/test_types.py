"""Tests for `carchive.storage.types`."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import Column, MetaData, Table, Uuid, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from carchive.storage.types import UTCDateTime

_metadata = MetaData()
_probe = Table(
    "probe",
    _metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("at", UTCDateTime),
)


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
    yield engine
    await engine.dispose()


def test_naive_datetime_is_rejected() -> None:
    naive = datetime(2026, 1, 1, 12, 0, 0)
    with pytest.raises(ValueError, match="naive"):
        UTCDateTime().process_bind_param(naive, dialect=None)  # type: ignore[arg-type]


def test_none_passes_through() -> None:
    column_type = UTCDateTime()
    assert column_type.process_bind_param(None, dialect=None) is None  # type: ignore[arg-type]
    assert column_type.process_result_value(None, dialect=None) is None  # type: ignore[arg-type]


async def test_offset_aware_datetime_is_normalized_to_utc(engine: AsyncEngine) -> None:
    from uuid import uuid4

    plus_two = timezone(timedelta(hours=2))
    at = datetime(2026, 1, 1, 14, 0, 0, tzinfo=plus_two)

    async with engine.begin() as conn:
        await conn.execute(_probe.insert().values(id=uuid4(), at=at))
        row = (await conn.execute(select(_probe.c.at))).first()

    assert row is not None
    assert row.at == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert row.at.tzinfo is not None


async def test_roundtrip_keeps_timezone_aware_utc(engine: AsyncEngine) -> None:
    from uuid import uuid4

    at = datetime(2026, 6, 15, 8, 30, 0, tzinfo=UTC)

    async with engine.begin() as conn:
        await conn.execute(_probe.insert().values(id=uuid4(), at=at))
        row = (await conn.execute(select(_probe.c.at))).first()

    assert row is not None
    assert row.at == at
    assert row.at.tzinfo is not None
