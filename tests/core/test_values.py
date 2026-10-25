"""Tests for `carchive.core.values`."""

from __future__ import annotations

from datetime import UTC, datetime

from carchive.core.values import parse_value


def test_parse_value_integer() -> None:
    result = parse_value("42")
    assert result.num == 42.0
    assert result.text is None
    assert result.boolean is None
    assert result.time is None


def test_parse_value_negative_decimal() -> None:
    result = parse_value("-3.5")
    assert result.num == -3.5


def test_parse_value_comma_decimal_is_text() -> None:
    result = parse_value("1,5")
    assert result.text == "1,5"
    assert result.num is None


def test_parse_value_nan_is_text() -> None:
    result = parse_value("NaN")
    assert result.text == "NaN"
    assert result.num is None


def test_parse_value_boolean_is_case_insensitive() -> None:
    result = parse_value("TRUE")
    assert result.boolean is True
    assert result.num is None
    assert result.text is None


def test_parse_value_timestamp() -> None:
    result = parse_value("2026-10-22T12:00:00Z")
    assert result.time == datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
    assert result.text is None
    assert result.num is None


def test_parse_value_empty_string_is_text() -> None:
    result = parse_value("")
    assert result.text == ""
    assert result.num is None
    assert result.time is None


def test_parse_value_none_sets_nothing() -> None:
    result = parse_value(None)
    assert result.num is None
    assert result.text is None
    assert result.boolean is None
    assert result.time is None
