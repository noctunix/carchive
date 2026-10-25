"""Tests for `carchive.storage.dedup`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from carchive.storage.dedup import dedup_key


def test_stable_across_calls() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert dedup_key("k", "f", at, "1") == dedup_key("k", "f", at, "1")


def test_distinguishes_none_from_empty_string() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert dedup_key("k", "f", at, None) != dedup_key("k", "f", at, "")


def test_distinguishes_missing_captured_at_from_any_value() -> None:
    assert dedup_key("k", "f", None, "1") != dedup_key(
        "k", "f", datetime(2026, 1, 1, tzinfo=UTC), "1"
    )


def test_distinguishes_different_keys() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert dedup_key("k1", "f", at, "1") != dedup_key("k2", "f", at, "1")


def test_distinguishes_different_field_names() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert dedup_key("k", "f1", at, "1") != dedup_key("k", "f2", at, "1")


def test_special_characters_do_not_break_encoding() -> None:
    key = dedup_key('k"with\\quotes', "f[0].name", None, "a\nb\tc")
    assert len(key) == 64
    int(key, 16)  # is valid hex


def test_naive_captured_at_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        dedup_key("k", "f", datetime(2026, 1, 1), "1")


def test_result_is_a_sha256_hex_digest() -> None:
    key = dedup_key("k", "f", None, None)
    assert len(key) == 64
    int(key, 16)
