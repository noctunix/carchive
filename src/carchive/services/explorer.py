"""The data explorer: every key a vehicle has ever reported, labelled with the catalog."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from carchive.core.provider import ProviderRegistry
from carchive.core.signals import SIGNALS
from carchive.services.catalog import CatalogService
from carchive.storage.db import Database
from carchive.storage.records import CatalogEntryRecord, FieldSummaryRecord
from carchive.storage.repositories import (
    AccountRepository,
    DataPointRepository,
    VehicleRepository,
)


@dataclass(frozen=True, slots=True)
class FieldInfo:
    """One generalized field's row on the data explorer page.

    Attributes:
        key: a representative provider key for this field (see `FieldSummaryRecord.key`).
        catalog_clusters: the catalog's cluster list for this field's key, empty if no
            catalog entry was found or the dictionary kind has no cluster column.
        is_mapped: whether this field is one of a canonical signal's known source fields.
    """

    field_generic: str
    key: str
    point_count: int
    distinct_value_count: int
    first_captured_at: datetime | None
    last_captured_at: datetime | None
    last_value_raw: str | None
    catalog_name: str | None
    catalog_description: str | None
    catalog_unit: str | None
    catalog_clusters: tuple[str, ...]
    is_mapped: bool


@dataclass(frozen=True, slots=True)
class FieldPage:
    """One page of the data explorer's field list."""

    items: tuple[FieldInfo, ...]
    total: int
    limit: int
    offset: int
    catalog_imported: bool


@dataclass(frozen=True, slots=True)
class FieldValue:
    """One data point belonging to a generalized field, for the field's history page."""

    field_name: str
    value_raw: str | None
    captured_at: datetime | None
    captured_at_quality: str
    first_seen_at: datetime
    seen_count: int


def _matches_query(field: FieldInfo, query: str) -> bool:
    needle = query.lower()
    haystacks = (field.field_generic, field.catalog_name, field.catalog_description)
    return any(needle in haystack.lower() for haystack in haystacks if haystack is not None)


def _matches_cluster(field: FieldInfo, cluster: str) -> bool:
    needle = cluster.lower()
    return any(needle == known.lower() for known in field.catalog_clusters)


class ExplorerService:
    """Builds the data explorer's field list and per-field value history.

    Args:
        db: the database to read data points from.
        catalog: resolves catalog names/descriptions/units/clusters for known keys.
        registry: looks up a vehicle's provider to find which fields are mapped to a
            canonical signal.
    """

    def __init__(self, db: Database, catalog: CatalogService, registry: ProviderRegistry) -> None:
        self._db = db
        self._catalog = catalog
        self._registry = registry
        self._vehicles = VehicleRepository()
        self._accounts = AccountRepository()
        self._data_points = DataPointRepository()

    async def fields(
        self,
        vehicle_id: UUID,
        *,
        query: str | None = None,
        cluster: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> FieldPage | None:
        """Build the filtered, paginated field list for `vehicle_id`.

        Args:
            vehicle_id: the vehicle to list fields for.
            query: case-insensitive substring filter over the field name and, if a catalog
                entry is known for it, its name and description.
            cluster: an exact (case-insensitive) match against one of the field's catalog
                clusters; fields with no catalog cluster never match.
            limit: the maximum number of fields to return.
            offset: how many matching fields to skip, for paging.

        Returns:
            The matching page, or `None` if `vehicle_id` does not exist.
        """
        async with self._db.read() as conn:
            vehicle = await self._vehicles.get(conn, vehicle_id)
            if vehicle is None:
                return None
            account = await self._accounts.get(conn, vehicle.account_id)
            if account is None:
                return None
            summaries = await self._data_points.list_fields_for_vehicle(conn, vehicle_id)

        provider_id = account.provider_id
        catalog_by_key = await self._catalog.lookup(
            provider_id, [summary.key for summary in summaries]
        )
        mapped_fields = self._mapped_fields(provider_id)

        fields = [
            self._build_field_info(summary, catalog_by_key.get(summary.key), mapped_fields)
            for summary in summaries
        ]
        if query:
            fields = [field for field in fields if _matches_query(field, query)]
        if cluster:
            fields = [field for field in fields if _matches_cluster(field, cluster)]
        fields.sort(key=lambda field: field.field_generic)

        catalog_imported = any(
            version.provider_id == provider_id for version in await self._catalog.list_versions()
        )
        return FieldPage(
            items=tuple(fields[offset : offset + limit]),
            total=len(fields),
            limit=limit,
            offset=offset,
            catalog_imported=catalog_imported,
        )

    async def field_values(
        self, vehicle_id: UUID, field_generic: str, *, limit: int = 200
    ) -> list[FieldValue] | None:
        """Return the most recent values for one generalized field, newest first.

        Args:
            vehicle_id: the vehicle to read values for.
            field_generic: the generalized field name to show the history of.
            limit: the maximum number of values to return.

        Returns:
            The matching values, or `None` if `vehicle_id` does not exist.
        """
        async with self._db.read() as conn:
            vehicle = await self._vehicles.get(conn, vehicle_id)
            if vehicle is None:
                return None
            records = await self._data_points.list_field_values(
                conn, vehicle_id, field_generic, limit=limit
            )
        return [
            FieldValue(
                field_name=record.field_name,
                value_raw=record.value_raw,
                captured_at=record.captured_at,
                captured_at_quality=record.captured_at_quality,
                first_seen_at=record.first_seen_at,
                seen_count=record.seen_count,
            )
            for record in records
        ]

    def _mapped_fields(self, provider_id: str) -> frozenset[str]:
        """Return every generalized source field the provider's mapper knows about."""
        try:
            mapper = self._registry.get(provider_id).mapper()
        except (KeyError, NotImplementedError):
            return frozenset()
        fields: set[str] = set()
        for signal in SIGNALS:
            fields.update(mapper.preference(signal))
        return frozenset(fields)

    def _build_field_info(
        self,
        summary: FieldSummaryRecord,
        catalog_entry: CatalogEntryRecord | None,
        mapped_fields: frozenset[str],
    ) -> FieldInfo:
        clusters = tuple(catalog_entry.clusters) if catalog_entry and catalog_entry.clusters else ()
        return FieldInfo(
            field_generic=summary.field_generic,
            key=summary.key,
            point_count=summary.point_count,
            distinct_value_count=summary.distinct_value_count,
            first_captured_at=summary.first_captured_at,
            last_captured_at=summary.last_captured_at,
            last_value_raw=summary.last_value_raw,
            catalog_name=catalog_entry.name if catalog_entry else None,
            catalog_description=catalog_entry.description if catalog_entry else None,
            catalog_unit=catalog_entry.unit if catalog_entry else None,
            catalog_clusters=clusters,
            is_mapped=summary.field_generic in mapped_fields,
        )
