"""Timestamp parsing and freshness computation.

Every function here returns UTC `datetime` instances or `None`; nothing guesses a timezone
beyond assuming UTC for zone-less input, and nothing silently rescales a value (e.g. the
portal's epoch-seconds-written-as-milliseconds bug is surfaced as `invalid`, never corrected).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from carchive.core.models import TimestampQuality

MIN_PLAUSIBLE = datetime(2000, 1, 1, tzinfo=UTC)


def parse_timestamp(text: str | None) -> tuple[datetime | None, TimestampQuality]:
    """Parse an ISO-8601 timestamp as delivered by a provider.

    Accepts a trailing `Z` or an explicit offset, and fractional seconds of up to nine digits
    (truncated to microseconds, never rounded). A timestamp without a timezone is interpreted
    as UTC with quality `tz_unknown`. A result before `MIN_PLAUSIBLE` is treated as `invalid`
    rather than silently rescaled, since some providers write epoch seconds where milliseconds
    were expected.

    Args:
        text: the timestamp text, or `None`.

    Returns:
        A `(datetime, quality)` pair; the datetime is `None` exactly when quality is `invalid`.
    """
    if not text:
        return None, TimestampQuality.INVALID

    normalized = text.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    normalized = _truncate_fraction(normalized)

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None, TimestampQuality.INVALID

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
        quality = TimestampQuality.TZ_UNKNOWN
    else:
        parsed = parsed.astimezone(UTC)
        quality = TimestampQuality.EXACT

    if parsed < MIN_PLAUSIBLE:
        return None, TimestampQuality.INVALID
    return parsed, quality


def _truncate_fraction(text: str) -> str:
    """Truncate a fractional-seconds component to at most six digits (microseconds)."""
    dot = text.find(".")
    if dot == -1:
        return text
    end = dot + 1
    while end < len(text) and text[end].isdigit():
        end += 1
    fraction = text[dot + 1 : end]
    if len(fraction) <= 6:
        return text
    return text[: dot + 1] + fraction[:6] + text[end:]


def from_epoch(seconds: int | float | str, nanos: int | str = 0) -> datetime | None:
    """Build a UTC datetime from a `(seconds, nanos)` pair, as used by `carCapturedTimeStamp`.

    Args:
        seconds: epoch seconds, possibly as a string.
        nanos: nanoseconds to add on top of `seconds`, possibly as a string.

    Returns:
        The resulting UTC datetime, or `None` if the inputs are unparsable or implausible
        (before `MIN_PLAUSIBLE`).
    """
    try:
        seconds_value = float(seconds)
        nanos_value = float(nanos)
    except (TypeError, ValueError):
        return None

    try:
        result = datetime.fromtimestamp(seconds_value, tz=UTC) + timedelta(
            microseconds=nanos_value / 1000
        )
    except (OverflowError, OSError, ValueError):
        return None

    if result < MIN_PLAUSIBLE:
        return None
    return result


class Freshness(StrEnum):
    """How recent a signal's captured-at timestamp is, relative to configured thresholds."""

    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    UNKNOWN = "unknown"


def freshness(
    captured_at: datetime | None,
    now: datetime,
    amber_after: timedelta | None,
    red_after: timedelta | None,
) -> Freshness:
    """Classify how fresh a value is.

    Args:
        captured_at: when the value was captured, or `None` if unknown.
        now: the current time, used to compute the age.
        amber_after: age at and beyond which the value counts as `aging`, or `None` to never
            downgrade past `fresh`.
        red_after: age at and beyond which the value counts as `stale`, or `None` to never
            downgrade to `stale`.

    Returns:
        `unknown` if `captured_at` is `None`; otherwise `fresh`, `aging` or `stale` depending
        on the age of `captured_at` relative to the thresholds (a threshold is reached at
        exactly that age, not only past it).
    """
    if captured_at is None:
        return Freshness.UNKNOWN

    age = now - captured_at
    if red_after is not None and age >= red_after:
        return Freshness.STALE
    if amber_after is not None and age >= amber_after:
        return Freshness.AGING
    return Freshness.FRESH
