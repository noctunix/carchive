"""Tests for `carchive.core.models`."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from carchive.core.models import (
    DataPoint,
    RemoteDelivery,
    SignalValue,
    TimestampQuality,
    Vehicle,
)

_AWARE = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
_NAIVE = datetime(2026, 10, 22, 12, 0)


def test_data_point_accepts_aware_datetime() -> None:
    point = DataPoint(
        key="k",
        field_name="f",
        value_raw="1",
        captured_at=_AWARE,
        captured_at_quality=TimestampQuality.EXACT,
    )
    assert point.captured_at == _AWARE


def test_data_point_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="captured_at"):
        DataPoint(
            key="k",
            field_name="f",
            value_raw="1",
            captured_at=_NAIVE,
            captured_at_quality=TimestampQuality.EXACT,
        )


def test_data_point_accepts_none_captured_at() -> None:
    point = DataPoint(
        key="k",
        field_name="f",
        value_raw=None,
        captured_at=None,
        captured_at_quality=TimestampQuality.INVALID,
    )
    assert point.captured_at is None


def test_signal_value_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="captured_at"):
        SignalValue(
            signal="battery.soc",
            value=80.0,
            unit="%",
            captured_at=_NAIVE,
            captured_at_quality=TimestampQuality.EXACT,
            source_key="k",
            source_field="f",
            mapping_version="v1",
        )


def test_remote_delivery_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="delivered_at"):
        RemoteDelivery(remote_name="x.zip", delivered_at=_NAIVE, has_content=True)


def test_remote_delivery_accepts_none_delivered_at() -> None:
    delivery = RemoteDelivery(remote_name="x.zip", delivered_at=None, has_content=False)
    assert delivery.delivered_at is None


def test_vehicle_is_frozen() -> None:
    vehicle = Vehicle(
        id=uuid4(),
        account_id=uuid4(),
        vin="WVWZZZ1KZAW000001",
        label="Mine",
        brand="audi",
        model=None,
    )
    with pytest.raises(AttributeError):
        vehicle.label = "Other"  # type: ignore[misc]
