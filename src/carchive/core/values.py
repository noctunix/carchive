"""Best-effort typing of raw string values delivered by a provider.

The raw string is never discarded by this module; it only computes an additional, typed
interpretation on top of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from carchive.core.models import TimestampQuality
from carchive.core.timeutil import parse_timestamp

_BOOLEAN_LITERALS = {"true": True, "false": False}


@dataclass(frozen=True, slots=True)
class TypedValue:
    """A raw value's typed interpretation; exactly one field is set, or none for plain text.

    Attributes:
        num: the value as a number, if it parses as one.
        text: the value verbatim, if no other interpretation applies.
        boolean: the value as a boolean, if it is a recognised literal.
        time: the value as a timestamp, if `parse_timestamp` recognises it with a valid quality.
    """

    num: float | None
    text: str | None
    boolean: bool | None
    time: datetime | None


def parse_value(raw: str | None) -> TypedValue:
    """Classify a raw delivered value as boolean, numeric, a timestamp, or plain text.

    Args:
        raw: the raw value as delivered, or `None`.

    Returns:
        A `TypedValue` with exactly one of `boolean`, `num`, `time` or `text` set. `None`
        input and strings such as `NaN`/`inf` are returned as text, never as a number.
    """
    if raw is None:
        return TypedValue(num=None, text=None, boolean=None, time=None)

    lowered = raw.lower()
    if lowered in _BOOLEAN_LITERALS:
        return TypedValue(num=None, text=None, boolean=_BOOLEAN_LITERALS[lowered], time=None)

    num = _parse_strict_number(raw)
    if num is not None:
        return TypedValue(num=num, text=None, boolean=None, time=None)

    time, quality = parse_timestamp(raw)
    if quality != TimestampQuality.INVALID:
        return TypedValue(num=None, text=None, boolean=None, time=time)

    return TypedValue(num=None, text=raw, boolean=None, time=None)


def _parse_strict_number(raw: str) -> float | None:
    """Parse `raw` as a plain decimal number, rejecting anything `float()` is too lenient for.

    Args:
        raw: the candidate number string.

    Returns:
        The parsed number, or `None` if `raw` is not a sign-optional, dot-decimal integer or
        float (no thousands separators, no comma decimals, no `nan`/`inf` spellings).
    """
    body = raw[1:] if raw and raw[0] in "+-" else raw
    if not body:
        return None
    if not all(ch.isdigit() or ch == "." for ch in body):
        return None
    if body.count(".") > 1:
        return None
    try:
        return float(raw)
    except ValueError:
        return None
