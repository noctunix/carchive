"""Maps VW-group `DataPoint`s to canonical signals.

Only fields known to carry one quantity unambiguously are mapped; everything else stays in
`data_points`, visible but uninterpreted.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import structlog

from carchive.core.fields import generic_field_name
from carchive.core.models import DataPoint, SignalValue
from carchive.core.signals import SignalKind, spec
from carchive.core.values import parse_value

logger = structlog.get_logger(__name__)


# Candidate source fields per canonical signal, most preferred first. Field names use the
# same `[*]`-generalized shape `core.fields.generic_field_name` produces.
_SOURCE_FIELDS: dict[str, tuple[str, ...]] = {
    "vehicle.odometer": ("mileage",),
    "battery.soc": (
        "currentSOCInPct",
        "batteryStatus.currentSOC_pct",
        "ChargingEvent.[*].BatteryStatus.[*].currentSocPct",
    ),
    "range.primary": ("cruisingRangeElectricInKm", "batteryStatus.cruisingRange.range"),
    "charging.power": ("chargePowerInKW", "chargingStatus.chargePower_kW"),
    "charging.state": ("chargingState", "chargingStatus.currentChargeState"),
    "plug.connection_state": ("plugConnectionState", "plugStatusItem.plugConnectionState"),
    "fuel.level": ("fuel_level", "fuel_level.value", "fuel_level_current_level"),
}

# Plausible value ranges for the numeric signals above; a value outside its range is not
# mapped, since the manufacturer's own dictionary units/ranges are not reliable.
_NUMERIC_BOUNDS: dict[str, tuple[float, float]] = {
    "vehicle.odometer": (0.0, 2_000_000.0),
    "battery.soc": (0.0, 100.0),
    "range.primary": (0.0, 3000.0),
    "charging.power": (0.0, 1000.0),
    "fuel.level": (0.0, 100.0),
}

_FIELD_TO_SIGNAL: dict[str, str] = {
    field: signal for signal, fields in _SOURCE_FIELDS.items() for field in fields
}


class VwGroupMapper:
    """Maps VW-group `DataPoint`s to canonical signals; satisfies `SignalMapper`."""

    mapping_version = "vwgroup-map-1"

    def map(self, points: Sequence[DataPoint]) -> Iterable[SignalValue]:
        """Map `points` to canonical signal values, skipping everything not in the table.

        Args:
            points: data points, typically all belonging to one vehicle.

        Returns:
            One `SignalValue` per point whose generalized field name is a known source
            field and whose value passes the signal's type and range check.
        """
        results: list[SignalValue] = []
        for point in points:
            mapped = self._map_one(point)
            if mapped is not None:
                results.append(mapped)
        return results

    def _map_one(self, point: DataPoint) -> SignalValue | None:
        signal = _FIELD_TO_SIGNAL.get(generic_field_name(point.field_name))
        if signal is None:
            return None

        signal_spec = spec(signal)
        value: float | str | bool
        if signal_spec.kind == SignalKind.NUMERIC:
            typed = parse_value(point.value_raw)
            if typed.num is None:
                logger.debug("vwgroup.mapping.not_numeric", signal=signal, field=point.field_name)
                return None
            low, high = _NUMERIC_BOUNDS[signal]
            if not (low <= typed.num <= high):
                logger.debug("vwgroup.mapping.out_of_range", signal=signal, field=point.field_name)
                return None
            value = typed.num
        else:
            if not point.value_raw:
                return None
            value = point.value_raw

        return SignalValue(
            signal=signal,
            value=value,
            unit=signal_spec.unit,
            captured_at=point.captured_at,
            captured_at_quality=point.captured_at_quality,
            source_key=point.key,
            source_field=point.field_name,
            mapping_version=self.mapping_version,
        )

    def preference(self, signal: str) -> tuple[str, ...]:
        """Return `signal`'s source fields in preferred order, most preferred first.

        Args:
            signal: a canonical signal name.

        Returns:
            The source fields this mapper knows for `signal`, most preferred first; empty
            if this mapper does not map `signal` at all.
        """
        return _SOURCE_FIELDS.get(signal, ())
