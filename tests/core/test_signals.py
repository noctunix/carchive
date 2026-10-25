"""Tests for `carchive.core.signals`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from carchive.core.models import DataPoint, SignalValue, TimestampQuality
from carchive.core.signals import SIGNALS, SignalKind, associate_source_ids, preferred, spec

_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("name", "unit", "kind"),
    [
        ("vehicle.odometer", "km", SignalKind.NUMERIC),
        ("battery.soc", "%", SignalKind.NUMERIC),
        ("fuel.level", "%", SignalKind.NUMERIC),
        ("range.primary", "km", SignalKind.NUMERIC),
        ("range.secondary", "km", SignalKind.NUMERIC),
        ("range.total", "km", SignalKind.NUMERIC),
        ("climate.outdoor_temperature", "°C", SignalKind.NUMERIC),
        ("battery.temperature", "°C", SignalKind.NUMERIC),
        ("charging.state", None, SignalKind.ENUM),
        ("charging.power", "kW", SignalKind.NUMERIC),
        ("plug.connection_state", None, SignalKind.ENUM),
    ],
)
def test_catalog_contains_expected_signal(name: str, unit: str | None, kind: SignalKind) -> None:
    entry = spec(name)
    assert entry.unit == unit
    assert entry.kind == kind
    assert entry.amber_after is not None
    assert entry.red_after is not None
    assert entry.amber_after < entry.red_after


def test_catalog_has_exactly_the_mvp_signals() -> None:
    assert set(SIGNALS) == {
        "vehicle.odometer",
        "battery.soc",
        "fuel.level",
        "range.primary",
        "range.secondary",
        "range.total",
        "climate.outdoor_temperature",
        "battery.temperature",
        "charging.state",
        "charging.power",
        "plug.connection_state",
    }


def test_spec_unknown_name_raises_key_error() -> None:
    with pytest.raises(KeyError, match="unknown.signal"):
        spec("unknown.signal")


def _signal_value(
    source_field: str, *, captured_at: datetime | None, value: float = 1.0
) -> SignalValue:
    quality = TimestampQuality.EXACT if captured_at is not None else TimestampQuality.INVALID
    return SignalValue(
        signal="battery.soc",
        value=value,
        unit="%",
        captured_at=captured_at,
        captured_at_quality=quality,
        source_key="k1",
        source_field=source_field,
        mapping_version="v1",
    )


def test_preferred_returns_none_for_an_empty_sequence() -> None:
    assert preferred([], ("a", "b")) is None


def test_preferred_picks_the_newest_captured_at() -> None:
    older = _signal_value("a", captured_at=_NOW - timedelta(hours=1), value=1.0)
    newer = _signal_value("b", captured_at=_NOW, value=2.0)
    assert preferred([older, newer], ("a", "b")).value == 2.0  # type: ignore[union-attr]


def test_preferred_breaks_ties_by_preference_order() -> None:
    preferred_field = _signal_value("a", captured_at=_NOW, value=1.0)
    other_field = _signal_value("b", captured_at=_NOW, value=2.0)
    result = preferred([other_field, preferred_field], ("a", "b"))
    assert result is not None
    assert result.source_field == "a"


def test_preferred_never_picks_an_invalid_timestamp_over_a_valid_one() -> None:
    invalid = _signal_value("a", captured_at=None, value=99.0)
    valid_but_old = _signal_value("b", captured_at=_NOW - timedelta(days=30), value=1.0)
    result = preferred([invalid, valid_but_old], ("a", "b"))
    assert result is not None
    assert result.value == 1.0


def test_preferred_unranked_field_loses_a_tie() -> None:
    ranked = _signal_value("a", captured_at=_NOW, value=1.0)
    unranked = _signal_value("unknown", captured_at=_NOW, value=2.0)
    result = preferred([unranked, ranked], ("a",))
    assert result is not None
    assert result.source_field == "a"


def test_associate_source_ids_matches_by_key_field_and_captured_at() -> None:
    id1, id2 = uuid4(), uuid4()
    point1 = DataPoint(
        key="k1",
        field_name="mileage",
        value_raw="1",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    point2 = DataPoint(
        key="k2",
        field_name="currentSOCInPct",
        value_raw="80",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
    )
    value1 = SignalValue(
        signal="vehicle.odometer",
        value=1.0,
        unit="km",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
        source_key="k1",
        source_field="mileage",
        mapping_version="v1",
    )
    value2 = SignalValue(
        signal="battery.soc",
        value=80.0,
        unit="%",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
        source_key="k2",
        source_field="currentSOCInPct",
        mapping_version="v1",
    )

    paired = associate_source_ids([(id1, point1), (id2, point2)], [value1, value2])

    assert set(paired) == {(value1, id1), (value2, id2)}


def test_associate_source_ids_drops_a_value_with_no_matching_point() -> None:
    value = SignalValue(
        signal="vehicle.odometer",
        value=1.0,
        unit="km",
        captured_at=_NOW,
        captured_at_quality=TimestampQuality.EXACT,
        source_key="unknown",
        source_field="mileage",
        mapping_version="v1",
    )
    assert associate_source_ids([], [value]) == []
