"""Frozen records returned by `repositories.py`.

Kept separate from `core.models` because these mirror full table rows (including columns
such as `state_reason` or `seen_count` that the core domain models do not need), not the
provider-facing shapes `core.models` defines.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from carchive.core.models import DataPoint


@dataclass(frozen=True, slots=True)
class AccountRecord:
    """One row of `accounts`."""

    id: UUID
    provider_id: str
    brand: str
    label: str
    credential_ref: str
    state: str
    state_reason: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class VehicleRecord:
    """One row of `vehicles`."""

    id: UUID
    account_id: UUID
    vin: str
    label: str
    brand: str
    model: str | None
    created_at: datetime
    archived_at: datetime | None


@dataclass(frozen=True, slots=True)
class DataRequestRecord:
    """One row of `data_requests`."""

    id: UUID
    vehicle_id: UUID
    kind: str
    remote_id: str | None
    interval_s: int
    next_due_at: datetime | None
    state: str
    state_reason: str | None
    last_success_at: datetime | None


@dataclass(frozen=True, slots=True)
class CollectorRunRecord:
    """One row of `collector_runs`.

    Attributes:
        data_request_id: the data request this run served, or `None` for an account-level
            run (e.g. a login failure before any request could be resolved).
    """

    id: UUID
    account_id: UUID
    data_request_id: UUID | None
    started_at: datetime
    finished_at: datetime
    outcome: str
    listed: int | None
    placeholders: int | None
    downloaded: int | None
    with_content: int | None
    pending: int | None
    oldest_pending_age_s: float | None
    message: str | None


@dataclass(frozen=True, slots=True)
class BackupRecord:
    """One row of `backups`.

    Attributes:
        path: the backup file's path at the time it was recorded; a pruned file may no
            longer exist on disk.
        verified: whether the integrity check during creation succeeded.
        error: the failure reason if creation failed, else `None`.
    """

    id: UUID
    created_at: datetime
    path: str
    size_bytes: int
    sha256: str
    verified: bool
    error: str | None


@dataclass(frozen=True, slots=True)
class UpsertResult:
    """Outcome of `DataPointRepository.upsert_many`.

    Attributes:
        new: number of points that did not exist yet and were inserted.
        repeated: number of points that already existed and only had their
            `last_seen_at`/`seen_count` updated.
        new_points: `(id, point)` for every newly inserted row, in no particular order;
            empty for points that only bumped an existing row. Lets a caller feed exactly
            the rows it just created to a `SignalMapper` and match the results back to a
            `source_data_point_id` via `core.signals.associate_source_ids`.
    """

    new: int
    repeated: int
    new_points: tuple[tuple[UUID, DataPoint], ...] = ()


@dataclass(frozen=True, slots=True)
class SignalValueRecord:
    """One row of `signal_values`, joined with its source point's field name and first-seen time.

    Attributes:
        source_field: the delivered field name of the `data_points` row this value was
            derived from; needed by `core.signals.preferred` to break ties between several
            source fields reporting the same signal.
        first_seen_at: when the source data point was first stored locally.
    """

    id: UUID
    vehicle_id: UUID
    signal: str
    value_num: float | None
    value_text: str | None
    value_bool: bool | None
    unit: str | None
    captured_at: datetime | None
    captured_at_quality: str
    source_data_point_id: UUID
    mapping_version: str
    source_field: str
    first_seen_at: datetime


@dataclass(frozen=True, slots=True)
class PendingDeliveryRecord:
    """One `deliveries` row with `parse_state = 'pending'`, plus the context needed to parse it.

    Attributes:
        provider_id: the provider that owns the account the delivery's vehicle belongs to;
            resolves the `PayloadParser`/`SignalMapper` to parse it with.
        request_kind: the owning data request's provider-defined kind, as passed to
            `ParseContext` on the original download.
    """

    delivery_id: UUID
    vehicle_id: UUID
    vin: str
    provider_id: str
    request_kind: str
    remote_name: str
    delivered_at: datetime | None
    fetched_at: datetime
    raw_payload: bytes | None


@dataclass(frozen=True, slots=True)
class DeliveryContentRecord:
    """The stored identity and bytes of one `deliveries` row, for integrity comparisons.

    Attributes:
        has_content: whether the delivery carries a payload (false for placeholders).
        sha256: the stored checksum: of `raw_payload` for deliveries with content, of the
            original file for placeholders.
        raw_payload: the stored file, `None` for placeholders.
    """

    has_content: bool
    sha256: str
    raw_payload: bytes | None


@dataclass(frozen=True, slots=True)
class CatalogEntryInput:
    """One parsed dictionary row, ready to upsert into `catalog_entries`.

    Attributes:
        clusters: `None` for a historical-dictionary entry (no cluster column at all); an
            empty list only if a continuous entry's cluster cell was present but blank.
    """

    key: str
    name: str
    description: str | None
    unit: str | None
    data_type: str | None
    clusters: list[str] | None


@dataclass(frozen=True, slots=True)
class CatalogImportCounts:
    """Outcome of `CatalogEntryRepository.upsert_many`."""

    new: int
    updated: int


@dataclass(frozen=True, slots=True)
class CatalogEntryRecord:
    """One row of `catalog_entries`, one dictionary key for one provider/catalog version."""

    id: UUID
    provider_id: str
    catalog_version: str
    key: str
    name: str
    description: str | None
    unit: str | None
    data_type: str | None
    clusters: list[str] | None
    kind: str


@dataclass(frozen=True, slots=True)
class CatalogVersionSummary:
    """One provider's catalog version, with how many entries it holds."""

    provider_id: str
    catalog_version: str
    kind: str
    entry_count: int


@dataclass(frozen=True, slots=True)
class FieldSummaryRecord:
    """One generalized field's aggregated activity for one vehicle, for the data explorer.

    Attributes:
        field_generic: the field name with array indices collapsed to `[*]`.
        key: a representative provider key for this field (stable in practice: every data
            point sharing `field_generic` carries the same dictionary key).
        point_count: how many data points share this generalized field name.
        distinct_value_count: how many distinct `value_raw` values were ever seen.
        first_captured_at: the earliest valid `captured_at` among this field's points, or
            `None` if none has one.
        last_captured_at: the latest valid `captured_at` among this field's points, or
            `None` if none has one.
        last_value_raw: the `value_raw` of the point picked as "current" (the one with the
            latest valid `captured_at`, falling back to the most recently seen point if none
            has a valid timestamp).
    """

    field_generic: str
    key: str
    point_count: int
    distinct_value_count: int
    first_captured_at: datetime | None
    last_captured_at: datetime | None
    last_value_raw: str | None


@dataclass(frozen=True, slots=True)
class FieldValueRecord:
    """One data point belonging to a generalized field, for the field's value-history page."""

    field_name: str
    value_raw: str | None
    captured_at: datetime | None
    captured_at_quality: str
    first_seen_at: datetime
    seen_count: int


@dataclass(frozen=True, slots=True)
class DeliveryActivitySummary:
    """Delivery activity over a set of data requests, for dashboard monitoring.

    Attributes:
        latest_delivery_at: `fetched_at` of the most recent delivery, content or placeholder,
            or `None` if there is none.
        latest_content_at: `fetched_at` of the most recent delivery that had content, or
            `None` if there never was one.
        earliest_delivery_at: `fetched_at` of the very first delivery, or `None` if there is
            none; used as the "only placeholders" window's start when there never was content.
        placeholders_since_content: number of content-less deliveries fetched at or after
            `latest_content_at` (or at or after `earliest_delivery_at` if there never was
            content, so that very first placeholder counts too).
    """

    latest_delivery_at: datetime | None
    latest_content_at: datetime | None
    earliest_delivery_at: datetime | None
    placeholders_since_content: int
