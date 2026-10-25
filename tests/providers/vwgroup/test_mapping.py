"""Tests for `providers.vwgroup.mapping.VwGroupMapper`."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest

from carchive.core.models import DataPoint, TimestampQuality
from carchive.core.signals import preferred
from carchive.providers.vwgroup.mapping import VwGroupMapper

_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


def _point(
    field_name: str, value_raw: str | None, *, key: str = "k1", captured_at: datetime | None = _NOW
) -> DataPoint:
    quality = TimestampQuality.EXACT if captured_at is not None else TimestampQuality.INVALID
    return DataPoint(
        key=key,
        field_name=field_name,
        value_raw=value_raw,
        captured_at=captured_at,
        captured_at_quality=quality,
    )


@pytest.mark.parametrize(
    ("field_name", "value_raw", "signal", "expected_value"),
    [
        ("mileage", "12345", "vehicle.odometer", 12345.0),
        ("currentSOCInPct", "80", "battery.soc", 80.0),
        ("batteryStatus.currentSOC_pct", "79", "battery.soc", 79.0),
        ("ChargingEvent.3.BatteryStatus.0.currentSocPct", "81", "battery.soc", 81.0),
        ("cruisingRangeElectricInKm", "250", "range.primary", 250.0),
        ("batteryStatus.cruisingRange.range", "240", "range.primary", 240.0),
        ("chargePowerInKW", "11", "charging.power", 11.0),
        ("chargingStatus.chargePower_kW", "22", "charging.power", 22.0),
        ("chargingState", "charging", "charging.state", "charging"),
        (
            "chargingStatus.currentChargeState",
            "readyForCharging",
            "charging.state",
            "readyForCharging",
        ),
        ("plugConnectionState", "connected", "plug.connection_state", "connected"),
        (
            "plugStatusItem.plugConnectionState",
            "disconnected",
            "plug.connection_state",
            "disconnected",
        ),
        ("fuel_level", "55", "fuel.level", 55.0),
        ("fuel_level.value", "56", "fuel.level", 56.0),
        ("fuel_level_current_level", "57", "fuel.level", 57.0),
    ],
)
def test_maps_every_table_row(
    field_name: str, value_raw: str, signal: str, expected_value: float | str
) -> None:
    mapper = VwGroupMapper()
    [mapped] = list(mapper.map([_point(field_name, value_raw)]))

    assert mapped.signal == signal
    assert mapped.value == expected_value
    assert mapped.mapping_version == "vwgroup-map-1"
    assert mapped.source_field == field_name
    assert mapped.source_key == "k1"


def test_index_generalization_matches_concrete_array_indices() -> None:
    mapper = VwGroupMapper()
    point = _point("ChargingEvent.17.BatteryStatus.4.currentSocPct", "42")
    [mapped] = list(mapper.map([point]))
    assert mapped.signal == "battery.soc"


@pytest.mark.parametrize(
    ("field_name", "value_raw"),
    [
        ("someUnrelatedField", "50"),  # not a known field at all
        ("currentSOCInPct", "-1"),  # below plausible range
        ("currentSOCInPct", "101"),  # above plausible range
        ("mileage", "-5"),
        ("mileage", "2000001"),
        ("cruisingRangeElectricInKm", "3001"),
        ("chargePowerInKW", "1001"),
        ("fuel_level", "101"),
    ],
)
def test_out_of_range_or_unknown_fields_are_not_mapped(field_name: str, value_raw: str) -> None:
    mapper = VwGroupMapper()
    assert list(mapper.map([_point(field_name, value_raw)])) == []


def test_non_numeric_value_for_a_numeric_signal_is_not_mapped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    mapper = VwGroupMapper()
    with caplog.at_level(logging.DEBUG):
        result = list(mapper.map([_point("mileage", "not-a-number")]))
    assert result == []


def test_empty_text_value_for_an_enum_signal_is_not_mapped() -> None:
    mapper = VwGroupMapper()
    assert list(mapper.map([_point("chargingState", "")])) == []
    assert list(mapper.map([_point("chargingState", None)])) == []


def test_unmapped_field_is_silently_skipped() -> None:
    mapper = VwGroupMapper()
    assert list(mapper.map([_point("someUnrelatedField", "1")])) == []


def test_preference_returns_table_order() -> None:
    mapper = VwGroupMapper()
    assert mapper.preference("battery.soc") == (
        "currentSOCInPct",
        "batteryStatus.currentSOC_pct",
        "ChargingEvent.[*].BatteryStatus.[*].currentSocPct",
    )
    assert mapper.preference("unknown.signal") == ()


def test_preferred_picks_the_newest_valid_value() -> None:
    mapper = VwGroupMapper()
    older = _point("currentSOCInPct", "70", captured_at=_NOW - timedelta(hours=1))
    newer = _point("batteryStatus.currentSOC_pct", "80", captured_at=_NOW)
    values = list(mapper.map([older, newer]))

    chosen = preferred(values, mapper.preference("battery.soc"))
    assert chosen is not None
    assert chosen.value == 80.0


def test_preferred_breaks_ties_by_mapper_preference() -> None:
    mapper = VwGroupMapper()
    less_preferred = _point("batteryStatus.currentSOC_pct", "70", captured_at=_NOW)
    more_preferred = _point("currentSOCInPct", "80", captured_at=_NOW)
    values = list(mapper.map([less_preferred, more_preferred]))

    chosen = preferred(values, mapper.preference("battery.soc"))
    assert chosen is not None
    assert chosen.value == 80.0


def test_preferred_never_prefers_an_invalid_timestamp_over_a_valid_one() -> None:
    mapper = VwGroupMapper()
    invalid_but_recent = DataPoint(
        key="k1",
        field_name="currentSOCInPct",
        value_raw="99",
        captured_at=None,
        captured_at_quality=TimestampQuality.INVALID,
    )
    valid_but_old = _point(
        "batteryStatus.currentSOC_pct", "60", captured_at=_NOW - timedelta(days=30)
    )
    values = list(mapper.map([invalid_but_recent, valid_but_old]))

    chosen = preferred(values, mapper.preference("battery.soc"))
    assert chosen is not None
    assert chosen.value == 60.0


def test_preferred_returns_none_for_empty_sequence() -> None:
    assert preferred([], ("a",)) is None
