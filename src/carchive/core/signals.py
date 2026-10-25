"""The canonical signal catalogue: names, units and freshness thresholds."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from carchive.core.models import DataPoint, SignalValue, TimestampQuality


class SignalKind(StrEnum):
    """How a canonical signal's value should be interpreted and displayed."""

    NUMERIC = "numeric"
    ENUM = "enum"
    TEXT = "text"
    BOOLEAN = "boolean"


@dataclass(frozen=True, slots=True)
class SignalSpec:
    """Metadata for one canonical signal."""

    name: str
    unit: str | None
    kind: SignalKind
    amber_after: timedelta | None
    red_after: timedelta | None


def _hours(n: float) -> timedelta:
    return timedelta(hours=n)


SIGNALS: dict[str, SignalSpec] = {
    "vehicle.odometer": SignalSpec(
        "vehicle.odometer", "km", SignalKind.NUMERIC, _hours(24), _hours(24 * 7)
    ),
    "battery.soc": SignalSpec("battery.soc", "%", SignalKind.NUMERIC, _hours(2), _hours(24)),
    "fuel.level": SignalSpec("fuel.level", "%", SignalKind.NUMERIC, _hours(2), _hours(24)),
    "range.primary": SignalSpec("range.primary", "km", SignalKind.NUMERIC, _hours(2), _hours(24)),
    "range.secondary": SignalSpec(
        "range.secondary", "km", SignalKind.NUMERIC, _hours(2), _hours(24)
    ),
    "range.total": SignalSpec("range.total", "km", SignalKind.NUMERIC, _hours(2), _hours(24)),
    "climate.outdoor_temperature": SignalSpec(
        "climate.outdoor_temperature", "°C", SignalKind.NUMERIC, _hours(3), _hours(24)
    ),
    "battery.temperature": SignalSpec(
        "battery.temperature", "°C", SignalKind.NUMERIC, _hours(3), _hours(24)
    ),
    "charging.state": SignalSpec("charging.state", None, SignalKind.ENUM, _hours(2), _hours(24)),
    "charging.power": SignalSpec("charging.power", "kW", SignalKind.NUMERIC, _hours(2), _hours(24)),
    "plug.connection_state": SignalSpec(
        "plug.connection_state", None, SignalKind.ENUM, _hours(2), _hours(24)
    ),
}


def spec(name: str) -> SignalSpec:
    """Return the `SignalSpec` registered under `name`.

    Raises:
        KeyError: if no signal with that name is registered.
    """
    try:
        return SIGNALS[name]
    except KeyError:
        raise KeyError(f"no signal registered with name {name!r}") from None


_NEVER = datetime.min.replace(tzinfo=UTC)


def preferred(values: Sequence[SignalValue], preference: Sequence[str]) -> SignalValue | None:
    """Pick the one value to show for a signal out of several source fields.

    The newest value with a valid (non-`invalid`) captured-at timestamp wins; an invalid
    timestamp never outranks a valid one, however old. Ties on captured-at are broken by
    `preference`, a mapper-provided order of source field names (earlier wins); a value
    whose source field is not listed in `preference` loses every such tie.

    Args:
        values: candidate values for one signal, typically from several source fields.
        preference: `source_field` values in preferred order, as returned by a
            `SignalMapper`'s `preference` method for this signal.

    Returns:
        The preferred value, or `None` if `values` is empty.
    """
    if not values:
        return None

    rank = {field: index for index, field in enumerate(preference)}
    unranked = len(preference)

    def sort_key(value: SignalValue) -> tuple[int, datetime, int]:
        is_valid = value.captured_at is not None and value.captured_at_quality != (
            TimestampQuality.INVALID
        )
        return (
            1 if is_valid else 0,
            value.captured_at if is_valid and value.captured_at is not None else _NEVER,
            -rank.get(value.source_field, unranked),
        )

    return max(values, key=sort_key)


def associate_source_ids(
    points: Sequence[tuple[UUID, DataPoint]], values: Sequence[SignalValue]
) -> list[tuple[SignalValue, UUID]]:
    """Pair mapped signal values back to the id of the data point they were derived from.

    A `SignalMapper` only ever sees `DataPoint`s, not their storage ids, so its output
    carries `source_key`/`source_field`/`captured_at` but no id. This matches each value
    back to the (first still unmatched) point sharing that signature.

    Args:
        points: `(id, point)` pairs the values in `values` were computed from.
        values: signal values produced by a `SignalMapper.map` call over exactly those
            points.

    Returns:
        One `(value, point_id)` pair per value whose source point could be found; a value
        with no matching point (should not happen for a well-behaved mapper) is dropped.
    """
    by_signature: dict[tuple[str, str, datetime | None], list[UUID]] = {}
    for point_id, point in points:
        signature = (point.key, point.field_name, point.captured_at)
        by_signature.setdefault(signature, []).append(point_id)

    paired: list[tuple[SignalValue, UUID]] = []
    for value in values:
        signature = (value.source_key, value.source_field, value.captured_at)
        candidates = by_signature.get(signature)
        if not candidates:
            continue
        paired.append((value, candidates.pop(0)))
    return paired
