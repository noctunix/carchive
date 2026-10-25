"""Tests for `carchive.core.fields.generic_field_name`."""

from __future__ import annotations

from carchive.core.fields import generic_field_name


def test_dotted_index_is_generalized() -> None:
    assert generic_field_name("powerCurve.3.soc") == "powerCurve.[*].soc"


def test_bracketed_index_is_generalized() -> None:
    assert generic_field_name("powerCurve[3].soc") == "powerCurve.[*].soc"


def test_bracketed_dotted_index_is_generalized() -> None:
    assert generic_field_name("powerCurve.[3].soc") == "powerCurve.[*].soc"


def test_already_generic_name_is_unchanged() -> None:
    assert generic_field_name("powerCurve.[*].soc") == "powerCurve.[*].soc"


def test_name_with_no_index_is_unchanged() -> None:
    assert generic_field_name("mileage") == "mileage"


def test_several_indices_are_all_generalized() -> None:
    assert (
        generic_field_name("ChargingEvent.3.BatteryStatus.1.currentSocPct")
        == "ChargingEvent.[*].BatteryStatus.[*].currentSocPct"
    )
