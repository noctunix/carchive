"""Stable, NULL-safe deduplication key for `data_points`.

A unique constraint over nullable columns is not NULL-safe in SQL (NULL is never equal to
NULL, PostgreSQL and SQLite both included), and indexing several wide text columns directly
would bloat the index on both databases. `dedup_key` collapses the row's identity into one
fixed-size, indexable hash instead.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime


def dedup_key(
    key: str, field_name: str, captured_at: datetime | None, value_raw: str | None
) -> str:
    """Compute the deduplication key for one delivered value.

    Args:
        key: the provider's own key for the value.
        field_name: the delivered field name, with concrete array indices resolved.
        captured_at: when the value was captured, or `None` if unknown. Must be
            timezone-aware if given.
        value_raw: the raw value as delivered, or `None`.

    Returns:
        A 64-character lowercase SHA-256 hex digest, stable across calls and distinct for
        any difference in the inputs, including `None` versus an empty string.

    Raises:
        ValueError: if `captured_at` is a naive `datetime`.
    """
    if captured_at is not None and captured_at.tzinfo is None:
        raise ValueError("captured_at must be timezone-aware or None")

    captured_iso = captured_at.isoformat() if captured_at is not None else None
    # A JSON array keeps None and "" apart (null vs. "") and needs no separator convention
    # of our own.
    encoded = json.dumps([key, field_name, captured_iso, value_raw], ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
