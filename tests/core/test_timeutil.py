"""Tests for `carchive.core.timeutil`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from carchive.core.models import TimestampQuality
from carchive.core.timeutil import Freshness, freshness, from_epoch, parse_timestamp

_NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("text", "expected", "quality"),
    [
        ("2026-10-22T12:00:00Z", datetime(2026, 10, 22, 12, 0, tzinfo=UTC), TimestampQuality.EXACT),
        (
            "2026-10-22T14:00:00+02:00",
            datetime(2026, 10, 22, 12, 0, tzinfo=UTC),
            TimestampQuality.EXACT,
        ),
        (
            "2026-10-22T12:00:00.123456789Z",
            datetime(2026, 10, 22, 12, 0, 0, 123456, tzinfo=UTC),
            TimestampQuality.EXACT,
        ),
        (
            "2026-10-22T12:00:00",
            datetime(2026, 10, 22, 12, 0, tzinfo=UTC),
            TimestampQuality.TZ_UNKNOWN,
        ),
    ],
)
def test_parse_timestamp_valid_cases(
    text: str, expected: datetime, quality: TimestampQuality
) -> None:
    parsed, actual_quality = parse_timestamp(text)
    assert parsed == expected
    assert actual_quality == quality


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "not a timestamp",
        "1970-01-21T17:57:04.053Z",
        "1999-12-31T23:59:59Z",
    ],
)
def test_parse_timestamp_invalid_cases(text: str | None) -> None:
    parsed, quality = parse_timestamp(text)
    assert parsed is None
    assert quality == TimestampQuality.INVALID


def test_parse_timestamp_never_rescales_epoch_seconds_as_milliseconds() -> None:
    # The portal writes epoch seconds where milliseconds were expected for some records;
    # ×1000 would land in 2026, but the rule is to surface this as invalid, not to correct it.
    parsed, quality = parse_timestamp("1970-01-21T17:57:04.053Z")
    assert parsed is None
    assert quality == TimestampQuality.INVALID


def test_from_epoch_with_numeric_inputs() -> None:
    result = from_epoch(1761134400, 500_000_000)
    assert result == datetime(2025, 10, 22, 12, 0, 0, 500000, tzinfo=UTC)


def test_from_epoch_with_string_inputs() -> None:
    result = from_epoch("1761134400", "500000000")
    assert result == datetime(2025, 10, 22, 12, 0, 0, 500000, tzinfo=UTC)


def test_from_epoch_defaults_nanos_to_zero() -> None:
    result = from_epoch(1761134400)
    assert result == datetime(2025, 10, 22, 12, 0, 0, tzinfo=UTC)


def test_from_epoch_before_min_plausible_is_none() -> None:
    assert from_epoch(0) is None


def test_from_epoch_unparsable_is_none() -> None:
    assert from_epoch("not a number") is None


def test_freshness_unknown_without_captured_at() -> None:
    assert freshness(None, _NOW, timedelta(hours=2), timedelta(hours=24)) == Freshness.UNKNOWN


def test_freshness_fresh_without_thresholds() -> None:
    old = _NOW - timedelta(days=365)
    assert freshness(old, _NOW, None, None) == Freshness.FRESH


def test_freshness_fresh_just_under_amber() -> None:
    captured_at = _NOW - timedelta(hours=2) + timedelta(seconds=1)
    assert freshness(captured_at, _NOW, timedelta(hours=2), timedelta(hours=24)) == Freshness.FRESH


def test_freshness_aging_exactly_at_amber_threshold() -> None:
    captured_at = _NOW - timedelta(hours=2)
    assert freshness(captured_at, _NOW, timedelta(hours=2), timedelta(hours=24)) == Freshness.AGING


def test_freshness_stale_exactly_at_red_threshold() -> None:
    captured_at = _NOW - timedelta(hours=24)
    assert freshness(captured_at, _NOW, timedelta(hours=2), timedelta(hours=24)) == Freshness.STALE
