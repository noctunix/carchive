"""Core domain models: vehicles, provider-delivered data points and canonical signals.

All timestamps are UTC `datetime` instances or `None`. Constructors reject naive
`datetime` values so a missing timezone can never pass silently through the system.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class TimestampQuality(StrEnum):
    """How much a captured-at timestamp can be trusted."""

    EXACT = "exact"
    """Taken from a dedicated, zoned report timestamp."""

    REPORT = "report"
    """Taken from a report-level timestamp shared by several values."""

    DELIVERY = "delivery"
    """No per-value timestamp available; the delivery time was used instead."""

    TZ_UNKNOWN = "tz_unknown"
    """The source timestamp had no timezone; UTC was assumed."""

    INVALID = "invalid"
    """No usable timestamp could be derived."""


def _require_utc(value: datetime | None, field: str) -> None:
    """Raise `ValueError` if `value` is a `datetime` without a timezone.

    Args:
        value: the value to check, or `None`.
        field: the field name to mention in the error message.

    Raises:
        ValueError: if `value` is a naive `datetime`.
    """
    if value is not None and value.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware datetime or None, got a naive value")


@dataclass(frozen=True, slots=True)
class RemoteVehicle:
    """A vehicle as reported by a provider, before it is matched to a local `Vehicle`."""

    vin: str
    name: str


@dataclass(frozen=True, slots=True)
class RemoteDataRequest:
    """A data request as identified by a provider.

    `kind` is the provider's own, uninterpreted label for the dataset (e.g. the VW-group
    portal's `all` or `partial`); it is not given meaning outside the provider package.
    """

    vin: str
    kind: str
    remote_id: str


@dataclass(frozen=True, slots=True)
class RemoteDelivery:
    """A single delivery as listed by a provider, before it is downloaded."""

    remote_name: str
    delivered_at: datetime | None
    has_content: bool

    def __post_init__(self) -> None:
        _require_utc(self.delivered_at, "delivered_at")


@dataclass(frozen=True, slots=True)
class DataPoint:
    """A single leaf value parsed from a delivered payload, kept as close to the source as possible.

    `key` is the provider's own key for the value (e.g. a dictionary UUID); `field_name` is the
    delivered name with concrete array indices resolved (e.g. `powerCurve.3.timeCurve.17.soc`).
    """

    key: str
    field_name: str
    value_raw: str | None
    captured_at: datetime | None
    captured_at_quality: TimestampQuality

    def __post_init__(self) -> None:
        _require_utc(self.captured_at, "captured_at")


@dataclass(frozen=True, slots=True)
class SignalValue:
    """A canonical signal value derived from one or more `DataPoint`s by a `SignalMapper`."""

    signal: str
    value: float | str | bool
    unit: str | None
    captured_at: datetime | None
    captured_at_quality: TimestampQuality
    source_key: str
    source_field: str
    mapping_version: str

    def __post_init__(self) -> None:
        _require_utc(self.captured_at, "captured_at")


@dataclass(frozen=True, slots=True)
class Vehicle:
    """A locally known vehicle, linked to the account it was discovered through."""

    id: UUID
    account_id: UUID
    vin: str
    label: str
    brand: str
    model: str | None
