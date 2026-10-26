"""Repositories: the only place that turns domain data into SQL for the collector (P1-07).

Every method takes an `AsyncConnection` the caller already holds a transaction on (via
`Database.write()`/`read()`); repositories never open or commit a transaction themselves.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    ColumnElement,
    CompoundSelect,
    Row,
    bindparam,
    case,
    delete,
    exists,
    func,
    insert,
    literal,
    or_,
    select,
    union_all,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection

from carchive.core.fields import generic_field_name
from carchive.core.models import DataPoint, SignalValue, TimestampQuality
from carchive.core.values import parse_value
from carchive.storage.dedup import dedup_key as compute_dedup_key
from carchive.storage.records import (
    AccountRecord,
    BackupRecord,
    CatalogEntryInput,
    CatalogEntryRecord,
    CatalogImportCounts,
    CatalogVersionSummary,
    CollectorRunRecord,
    DataRequestRecord,
    DeliveryActivitySummary,
    DeliveryContentRecord,
    DeliveryDetailRecord,
    DeliverySummaryRecord,
    FieldSummaryRecord,
    FieldValueRecord,
    FirstSeenPointRecord,
    PendingDeliveryRecord,
    SignalValueRecord,
    UpsertResult,
    VehicleRecord,
)
from carchive.storage.schema import (
    accounts,
    backups,
    catalog_entries,
    collector_runs,
    data_points,
    data_requests,
    deliveries,
    import_batches,
    operator_sessions,
    signal_values,
    vehicles,
)

# Keeps parameter counts well under SQLite's bound-variable limit and PostgreSQL's practical
# statement size, while still moving data in large batches rather than one row at a time.
_CHUNK_SIZE = 500

# States whose data requests are still retried on schedule. `needs_attention` is included so a
# single bad run (e.g. an unexpected portal response) only delays the next attempt rather than
# silencing it forever; only `disabled` (set by a human) drops a request out of scheduling.
_COLLECTABLE_STATES = ("active", "needs_attention")


def _chunks(items: Sequence[Any], size: int = _CHUNK_SIZE) -> Iterable[Sequence[Any]]:
    """Yield `items` in consecutive slices of at most `size` elements."""
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _account_record(row: Row[Any]) -> AccountRecord:
    return AccountRecord(
        id=row.id,
        provider_id=row.provider_id,
        brand=row.brand,
        label=row.label,
        credential_ref=row.credential_ref,
        state=row.state,
        state_reason=row.state_reason,
        created_at=row.created_at,
    )


def _vehicle_record(row: Row[Any]) -> VehicleRecord:
    return VehicleRecord(
        id=row.id,
        account_id=row.account_id,
        vin=row.vin,
        label=row.label,
        brand=row.brand,
        model=row.model,
        created_at=row.created_at,
        archived_at=row.archived_at,
    )


def _data_request_record(row: Row[Any]) -> DataRequestRecord:
    return DataRequestRecord(
        id=row.id,
        vehicle_id=row.vehicle_id,
        kind=row.kind,
        remote_id=row.remote_id,
        interval_s=row.interval_s,
        next_due_at=row.next_due_at,
        state=row.state,
        state_reason=row.state_reason,
        last_success_at=row.last_success_at,
    )


def _catalog_entry_record(row: Row[Any]) -> CatalogEntryRecord:
    return CatalogEntryRecord(
        id=row.id,
        provider_id=row.provider_id,
        catalog_version=row.catalog_version,
        key=row.key,
        name=row.name,
        description=row.description,
        unit=row.unit,
        data_type=row.data_type,
        clusters=row.clusters,
        kind=row.kind,
    )


def _backup_record(row: Row[Any]) -> BackupRecord:
    return BackupRecord(
        id=row.id,
        created_at=row.created_at,
        path=row.path,
        size_bytes=row.size_bytes,
        sha256=row.sha256,
        verified=row.verified,
        error=row.error,
    )


def _signal_value_record(row: Row[Any]) -> SignalValueRecord:
    return SignalValueRecord(
        id=row.id,
        vehicle_id=row.vehicle_id,
        signal=row.signal,
        value_num=row.value_num,
        value_text=row.value_text,
        value_bool=row.value_bool,
        unit=row.unit,
        captured_at=row.captured_at,
        captured_at_quality=row.captured_at_quality,
        source_data_point_id=row.source_data_point_id,
        mapping_version=row.mapping_version,
        source_field=row.source_field,
        first_seen_at=row.first_seen_at,
        source_request_kind=row.source_request_kind,
    )


def _collector_run_record(row: Row[Any]) -> CollectorRunRecord:
    return CollectorRunRecord(
        id=row.id,
        account_id=row.account_id,
        data_request_id=row.data_request_id,
        started_at=row.started_at,
        finished_at=row.finished_at,
        outcome=row.outcome,
        listed=row.listed,
        placeholders=row.placeholders,
        downloaded=row.downloaded,
        with_content=row.with_content,
        pending=row.pending,
        oldest_pending_age_s=row.oldest_pending_age_s,
        message=row.message,
    )


class AccountRepository:
    """Reads and writes `accounts`."""

    async def add(
        self,
        conn: AsyncConnection,
        *,
        id: UUID,
        provider_id: str,
        brand: str,
        label: str,
        credential_ref: str,
        state: str,
        state_reason: str | None,
        created_at: datetime,
    ) -> UUID:
        """Insert a new account.

        Returns:
            `id`, unchanged, for convenience when chaining calls.
        """
        await conn.execute(
            insert(accounts).values(
                id=id,
                provider_id=provider_id,
                brand=brand,
                label=label,
                credential_ref=credential_ref,
                state=state,
                state_reason=state_reason,
                created_at=created_at,
            )
        )
        return id

    async def get(self, conn: AsyncConnection, account_id: UUID) -> AccountRecord | None:
        """Return the account with `account_id`, or `None` if it does not exist."""
        row = (await conn.execute(select(accounts).where(accounts.c.id == account_id))).first()
        return _account_record(row) if row is not None else None

    async def list_all(self, conn: AsyncConnection) -> list[AccountRecord]:
        """Return every account."""
        rows = (await conn.execute(select(accounts))).all()
        return [_account_record(row) for row in rows]

    async def get_by_label(self, conn: AsyncConnection, label: str) -> AccountRecord | None:
        """Return the account with `label`, or `None` if there is none."""
        row = (await conn.execute(select(accounts).where(accounts.c.label == label))).first()
        return _account_record(row) if row is not None else None

    async def set_state(
        self, conn: AsyncConnection, account_id: UUID, state: str, state_reason: str | None
    ) -> None:
        """Update an account's state and reason.

        Raises:
            KeyError: if no account with `account_id` exists.
        """
        result = await conn.execute(
            update(accounts)
            .where(accounts.c.id == account_id)
            .values(state=state, state_reason=state_reason)
        )
        if result.rowcount == 0:
            raise KeyError(f"no account with id {account_id}")

    async def delete(self, conn: AsyncConnection, account_id: UUID) -> None:
        """Delete the account with `account_id`.

        Caller's responsibility: every vehicle and account-scoped `collector_runs` row
        belonging to this account must already be deleted (foreign keys are enforced).

        Raises:
            KeyError: if no account with `account_id` exists.
        """
        result = await conn.execute(delete(accounts).where(accounts.c.id == account_id))
        if result.rowcount == 0:
            raise KeyError(f"no account with id {account_id}")

    async def list_due(self, conn: AsyncConnection, now: datetime) -> list[AccountRecord]:
        """Return every account that has collection work due at `now`.

        An account has work due when at least one of its non-archived vehicles either has a
        due collectable data request (`active` or `needs_attention`; never run, or past
        `next_due_at`) or has no data request at all yet (first discovery, which also
        requires a login).
        """
        due_request = exists(
            select(data_requests.c.id).where(
                data_requests.c.vehicle_id == vehicles.c.id,
                data_requests.c.state.in_(_COLLECTABLE_STATES),
                or_(
                    data_requests.c.next_due_at.is_(None),
                    data_requests.c.next_due_at <= now,
                ),
            )
        )
        no_request_yet = ~exists(
            select(data_requests.c.id).where(data_requests.c.vehicle_id == vehicles.c.id)
        )
        due_account_ids = (
            select(vehicles.c.account_id)
            .where(vehicles.c.archived_at.is_(None), due_request | no_request_yet)
            .distinct()
        )
        rows = (
            await conn.execute(select(accounts).where(accounts.c.id.in_(due_account_ids)))
        ).all()
        return [_account_record(row) for row in rows]


class VehicleRepository:
    """Reads and writes `vehicles`."""

    async def add(
        self,
        conn: AsyncConnection,
        *,
        id: UUID,
        account_id: UUID,
        vin: str,
        label: str,
        brand: str,
        model: str | None,
        created_at: datetime,
    ) -> UUID:
        """Insert a new vehicle.

        Returns:
            `id`, unchanged, for convenience when chaining calls.
        """
        await conn.execute(
            insert(vehicles).values(
                id=id,
                account_id=account_id,
                vin=vin,
                label=label,
                brand=brand,
                model=model,
                created_at=created_at,
                archived_at=None,
            )
        )
        return id

    async def get(self, conn: AsyncConnection, vehicle_id: UUID) -> VehicleRecord | None:
        """Return the vehicle with `vehicle_id`, or `None` if it does not exist."""
        row = (await conn.execute(select(vehicles).where(vehicles.c.id == vehicle_id))).first()
        return _vehicle_record(row) if row is not None else None

    async def list_for_account(
        self, conn: AsyncConnection, account_id: UUID
    ) -> list[VehicleRecord]:
        """Return every vehicle belonging to `account_id`."""
        rows = (
            await conn.execute(select(vehicles).where(vehicles.c.account_id == account_id))
        ).all()
        return [_vehicle_record(row) for row in rows]

    async def list_active_for_account(
        self, conn: AsyncConnection, account_id: UUID
    ) -> list[VehicleRecord]:
        """Return every non-archived vehicle belonging to `account_id`."""
        rows = (
            await conn.execute(
                select(vehicles).where(
                    vehicles.c.account_id == account_id, vehicles.c.archived_at.is_(None)
                )
            )
        ).all()
        return [_vehicle_record(row) for row in rows]

    async def get_by_vin(
        self, conn: AsyncConnection, account_id: UUID, vin: str
    ) -> VehicleRecord | None:
        """Return the vehicle with `vin` under `account_id`, or `None` if there is none."""
        row = (
            await conn.execute(
                select(vehicles).where(vehicles.c.account_id == account_id, vehicles.c.vin == vin)
            )
        ).first()
        return _vehicle_record(row) if row is not None else None

    async def count_active(self, conn: AsyncConnection) -> int:
        """Return the number of non-archived vehicles across all accounts."""
        result = await conn.execute(
            select(func.count()).select_from(vehicles).where(vehicles.c.archived_at.is_(None))
        )
        return result.scalar_one()

    async def list_all(self, conn: AsyncConnection) -> list[VehicleRecord]:
        """Return every vehicle, archived or not."""
        rows = (await conn.execute(select(vehicles))).all()
        return [_vehicle_record(row) for row in rows]

    async def delete(self, conn: AsyncConnection, vehicle_id: UUID) -> None:
        """Delete the vehicle with `vehicle_id`.

        Caller's responsibility: every row elsewhere referencing this vehicle (directly or
        through its data requests/import batches) must already be deleted (foreign keys
        are enforced).

        Raises:
            KeyError: if no vehicle with `vehicle_id` exists.
        """
        result = await conn.execute(delete(vehicles).where(vehicles.c.id == vehicle_id))
        if result.rowcount == 0:
            raise KeyError(f"no vehicle with id {vehicle_id}")


class DataRequestRepository:
    """Reads and writes `data_requests`."""

    async def get(self, conn: AsyncConnection, request_id: UUID) -> DataRequestRecord | None:
        """Return the data request with `request_id`, or `None` if it does not exist."""
        row = (
            await conn.execute(select(data_requests).where(data_requests.c.id == request_id))
        ).first()
        return _data_request_record(row) if row is not None else None

    async def upsert(
        self,
        conn: AsyncConnection,
        *,
        vehicle_id: UUID,
        kind: str,
        remote_id: str | None,
        interval_s: int,
    ) -> UUID:
        """Create the data request `(vehicle_id, kind)` or update its remote id and interval.

        A fresh data request starts in state `active` with no due time, so the scheduler
        picks it up on the next pass; an existing one keeps its state, due time and success
        history, since re-resolving the same request on a later login must not reset them.

        Returns:
            The data request's id, new or existing.
        """
        existing = (
            await conn.execute(
                select(data_requests.c.id).where(
                    data_requests.c.vehicle_id == vehicle_id, data_requests.c.kind == kind
                )
            )
        ).first()
        if existing is not None:
            request_id: UUID = existing.id
            await conn.execute(
                update(data_requests)
                .where(data_requests.c.id == request_id)
                .values(remote_id=remote_id, interval_s=interval_s)
            )
            return request_id

        request_id = uuid4()
        await conn.execute(
            insert(data_requests).values(
                id=request_id,
                vehicle_id=vehicle_id,
                kind=kind,
                remote_id=remote_id,
                interval_s=interval_s,
                next_due_at=None,
                state="active",
                state_reason=None,
                last_success_at=None,
            )
        )
        return request_id

    async def ensure(
        self,
        conn: AsyncConnection,
        *,
        vehicle_id: UUID,
        kind: str,
        interval_s: int,
    ) -> UUID:
        """Create the data request `(vehicle_id, kind)` if it does not exist yet.

        Unlike `upsert`, an already-existing request is returned unchanged: its
        `remote_id`, interval, state and history are never touched. Used by the sampler
        import, which must never clobber a request the live collector has already
        resolved and is tracking.

        Returns:
            The data request's id, new or existing.
        """
        existing = (
            await conn.execute(
                select(data_requests.c.id).where(
                    data_requests.c.vehicle_id == vehicle_id, data_requests.c.kind == kind
                )
            )
        ).first()
        if existing is not None:
            existing_id: UUID = existing.id
            return existing_id

        request_id = uuid4()
        await conn.execute(
            insert(data_requests).values(
                id=request_id,
                vehicle_id=vehicle_id,
                kind=kind,
                remote_id=None,
                interval_s=interval_s,
                next_due_at=None,
                state="active",
                state_reason=None,
                last_success_at=None,
            )
        )
        return request_id

    async def list_for_vehicle(
        self, conn: AsyncConnection, vehicle_id: UUID
    ) -> list[DataRequestRecord]:
        """Return every data request for `vehicle_id`, of any state."""
        rows = (
            await conn.execute(
                select(data_requests).where(data_requests.c.vehicle_id == vehicle_id)
            )
        ).all()
        return [_data_request_record(row) for row in rows]

    async def list_due(self, conn: AsyncConnection, now: datetime) -> list[DataRequestRecord]:
        """Return every collectable data request due at or before `now` (including never-run ones).

        Collectable means `active` or `needs_attention`: a request flagged `needs_attention`
        is still retried once its delay has passed, so one bad run only postpones it rather
        than dropping it from scheduling for good.
        """
        rows = (
            await conn.execute(
                select(data_requests).where(
                    data_requests.c.state.in_(_COLLECTABLE_STATES),
                    or_(
                        data_requests.c.next_due_at.is_(None),
                        data_requests.c.next_due_at <= now,
                    ),
                )
            )
        ).all()
        return [_data_request_record(row) for row in rows]

    async def earliest_next_due(self, conn: AsyncConnection, now: datetime) -> datetime | None:
        """Return the earliest time any collectable data request will next be due.

        Collectable means `active` or `needs_attention`, per `list_due`.

        Args:
            conn: the connection to read through.
            now: the current time; a request that never ran or is already past due counts
                as due at `now` itself, not at some time in the past.

        Returns:
            `now` if at least one collectable request is due now or has never run, the
            smallest future `next_due_at` among collectable requests otherwise, or `None` if
            there are no collectable data requests at all.
        """
        rows = (
            await conn.execute(
                select(data_requests.c.next_due_at).where(
                    data_requests.c.state.in_(_COLLECTABLE_STATES)
                )
            )
        ).all()
        if not rows:
            return None
        due_times: list[datetime | None] = [row.next_due_at for row in rows]
        if any(due_at is None or due_at <= now for due_at in due_times):
            return now
        return min(due_at for due_at in due_times if due_at is not None)

    async def set_next_due(
        self, conn: AsyncConnection, request_id: UUID, next_due_at: datetime
    ) -> None:
        """Set a data request's next due time.

        Raises:
            KeyError: if no data request with `request_id` exists.
        """
        result = await conn.execute(
            update(data_requests)
            .where(data_requests.c.id == request_id)
            .values(next_due_at=next_due_at)
        )
        if result.rowcount == 0:
            raise KeyError(f"no data request with id {request_id}")

    async def set_state(
        self, conn: AsyncConnection, request_id: UUID, state: str, state_reason: str | None
    ) -> None:
        """Set a data request's state and reason.

        Raises:
            KeyError: if no data request with `request_id` exists.
        """
        result = await conn.execute(
            update(data_requests)
            .where(data_requests.c.id == request_id)
            .values(state=state, state_reason=state_reason)
        )
        if result.rowcount == 0:
            raise KeyError(f"no data request with id {request_id}")

    async def delete_for_vehicle(self, conn: AsyncConnection, vehicle_id: UUID) -> int:
        """Delete every data request belonging to `vehicle_id`.

        Caller's responsibility: every `deliveries`/`collector_runs` row referencing one
        of these requests must already be deleted.

        Returns:
            The number of rows deleted.
        """
        result = await conn.execute(
            delete(data_requests).where(data_requests.c.vehicle_id == vehicle_id)
        )
        return result.rowcount

    async def mark_success(self, conn: AsyncConnection, request_id: UUID, at: datetime) -> None:
        """Record `at` as a data request's most recent successful run.

        Raises:
            KeyError: if no data request with `request_id` exists.
        """
        result = await conn.execute(
            update(data_requests).where(data_requests.c.id == request_id).values(last_success_at=at)
        )
        if result.rowcount == 0:
            raise KeyError(f"no data request with id {request_id}")


class DeliveryRepository:
    """Reads and writes `deliveries`."""

    async def exists(self, conn: AsyncConnection, data_request_id: UUID, remote_name: str) -> bool:
        """Return whether a delivery `remote_name` is already stored for `data_request_id`."""
        row = (
            await conn.execute(
                select(deliveries.c.id).where(
                    deliveries.c.data_request_id == data_request_id,
                    deliveries.c.remote_name == remote_name,
                )
            )
        ).first()
        return row is not None

    async def get_content(
        self, conn: AsyncConnection, data_request_id: UUID, remote_name: str
    ) -> DeliveryContentRecord | None:
        """Return the stored checksum and payload of delivery `remote_name`, if present.

        Args:
            conn: the connection to read through.
            data_request_id: the data request the delivery belongs to.
            remote_name: the delivery's file name.

        Returns:
            The delivery's content record, or `None` if no such delivery is stored.
        """
        row = (
            await conn.execute(
                select(
                    deliveries.c.has_content, deliveries.c.sha256, deliveries.c.raw_payload
                ).where(
                    deliveries.c.data_request_id == data_request_id,
                    deliveries.c.remote_name == remote_name,
                )
            )
        ).first()
        if row is None:
            return None
        return DeliveryContentRecord(
            has_content=row.has_content, sha256=row.sha256, raw_payload=row.raw_payload
        )

    async def add(
        self,
        conn: AsyncConnection,
        *,
        data_request_id: UUID | None,
        import_batch_id: UUID | None,
        remote_name: str,
        delivered_at: datetime | None,
        fetched_at: datetime,
        has_content: bool,
        sha256: str,
        size_bytes: int,
        parse_state: str,
        parser_version: str | None,
        raw_payload: bytes | None,
    ) -> UUID:
        """Insert a new delivery.

        Exactly one of `data_request_id`/`import_batch_id` must be given; the database's
        `CHECK` constraint rejects both-set or neither-set.

        Returns:
            The new delivery's id.
        """
        delivery_id = uuid4()
        await conn.execute(
            insert(deliveries).values(
                id=delivery_id,
                data_request_id=data_request_id,
                import_batch_id=import_batch_id,
                remote_name=remote_name,
                delivered_at=delivered_at,
                fetched_at=fetched_at,
                has_content=has_content,
                sha256=sha256,
                size_bytes=size_bytes,
                parse_state=parse_state,
                parser_version=parser_version,
                raw_payload=raw_payload,
            )
        )
        return delivery_id

    async def set_parse_state(
        self,
        conn: AsyncConnection,
        delivery_id: UUID,
        parse_state: str,
        parser_version: str | None = None,
    ) -> None:
        """Update a delivery's parse state and the parser version that produced it.

        Raises:
            KeyError: if no delivery with `delivery_id` exists.
        """
        result = await conn.execute(
            update(deliveries)
            .where(deliveries.c.id == delivery_id)
            .values(parse_state=parse_state, parser_version=parser_version)
        )
        if result.rowcount == 0:
            raise KeyError(f"no delivery with id {delivery_id}")

    async def purge_raw_payloads(self, conn: AsyncConnection, cutoff: datetime) -> int:
        """Clear `raw_payload` for successfully parsed deliveries fetched before `cutoff`.

        Leaves every other column (checksum, size, parse state) untouched; never touches a
        delivery still `pending` or `failed` parsing, since those need their raw payload for
        a future reparse.

        Args:
            conn: the connection to write through.
            cutoff: deliveries fetched before this time have their raw payload cleared.

        Returns:
            How many deliveries were purged.
        """
        result = await conn.execute(
            update(deliveries)
            .where(
                deliveries.c.parse_state == "parsed",
                deliveries.c.raw_payload.is_not(None),
                deliveries.c.fetched_at < cutoff,
            )
            .values(raw_payload=None)
        )
        return result.rowcount

    async def list_pending(
        self, conn: AsyncConnection, *, limit: int | None = None
    ) -> list[PendingDeliveryRecord]:
        """Return deliveries still waiting to be parsed, oldest first.

        Joins through `data_requests` and `vehicles` to attach the context a
        `PayloadParser`/`ParseContext` needs; deliveries belonging to an `import_batch`
        rather than a `data_request` are not returned, since no provider is implied for
        them yet (no historical import exists).

        Args:
            conn: the connection to read through.
            limit: the maximum number of rows to return, or `None` for no limit.

        Returns:
            One record per pending delivery, oldest `fetched_at` first.
        """
        query = (
            select(
                deliveries.c.id.label("delivery_id"),
                deliveries.c.remote_name,
                deliveries.c.delivered_at,
                deliveries.c.fetched_at,
                deliveries.c.raw_payload,
                vehicles.c.id.label("vehicle_id"),
                vehicles.c.vin,
                accounts.c.provider_id,
                data_requests.c.kind.label("request_kind"),
            )
            .select_from(deliveries)
            .join(data_requests, deliveries.c.data_request_id == data_requests.c.id)
            .join(vehicles, data_requests.c.vehicle_id == vehicles.c.id)
            .join(accounts, vehicles.c.account_id == accounts.c.id)
            .where(deliveries.c.parse_state == "pending")
            .order_by(deliveries.c.fetched_at)
        )
        if limit is not None:
            query = query.limit(limit)
        rows = (await conn.execute(query)).all()
        return [
            PendingDeliveryRecord(
                delivery_id=row.delivery_id,
                vehicle_id=row.vehicle_id,
                vin=row.vin,
                provider_id=row.provider_id,
                request_kind=row.request_kind,
                remote_name=row.remote_name,
                delivered_at=row.delivered_at,
                fetched_at=row.fetched_at,
                raw_payload=row.raw_payload,
            )
            for row in rows
        ]

    async def delete_for_vehicle(self, conn: AsyncConnection, vehicle_id: UUID) -> int:
        """Delete every delivery belonging to `vehicle_id`'s data requests or import batches.

        Caller's responsibility: every `data_points` row referencing one of these
        deliveries must already be deleted.

        Returns:
            The number of rows deleted.
        """
        request_ids = select(data_requests.c.id).where(data_requests.c.vehicle_id == vehicle_id)
        batch_ids = select(import_batches.c.id).where(import_batches.c.vehicle_id == vehicle_id)
        result = await conn.execute(
            delete(deliveries).where(
                or_(
                    deliveries.c.data_request_id.in_(request_ids),
                    deliveries.c.import_batch_id.in_(batch_ids),
                )
            )
        )
        return result.rowcount

    async def activity_summary(
        self, conn: AsyncConnection, data_request_ids: Sequence[UUID]
    ) -> DeliveryActivitySummary:
        """Summarize delivery activity across `data_request_ids`, for dashboard monitoring.

        Args:
            conn: the connection to read through.
            data_request_ids: the data requests to summarize deliveries over.

        Returns:
            A summary with every field `None`/0 if `data_request_ids` is empty.
        """
        if not data_request_ids:
            return DeliveryActivitySummary(None, None, None, 0)

        scope = deliveries.c.data_request_id.in_(data_request_ids)
        latest_delivery_at = (
            await conn.execute(select(func.max(deliveries.c.fetched_at)).where(scope))
        ).scalar_one()
        earliest_delivery_at = (
            await conn.execute(select(func.min(deliveries.c.fetched_at)).where(scope))
        ).scalar_one()
        latest_content_at = (
            await conn.execute(
                select(func.max(deliveries.c.fetched_at)).where(
                    scope, deliveries.c.has_content.is_(True)
                )
            )
        ).scalar_one()

        since = latest_content_at if latest_content_at is not None else earliest_delivery_at
        placeholders_since_content = 0
        if since is not None:
            placeholders_since_content = (
                await conn.execute(
                    select(func.count())
                    .select_from(deliveries)
                    .where(
                        scope,
                        deliveries.c.has_content.is_(False),
                        deliveries.c.fetched_at >= since,
                    )
                )
            ).scalar_one()

        return DeliveryActivitySummary(
            latest_delivery_at=latest_delivery_at,
            latest_content_at=latest_content_at,
            earliest_delivery_at=earliest_delivery_at,
            placeholders_since_content=placeholders_since_content,
        )

    def _delivery_rows(
        self, *, vehicle_id: UUID | None = None, delivery_id: UUID | None = None
    ) -> CompoundSelect[Any]:
        """Build the `UNION ALL` of a vehicle's/delivery's rows, reachable via either parent.

        Exactly one `deliveries` row's `data_request_id`/`import_batch_id` is ever set (the
        schema's `exactly_one_parent` check), so the two branches never produce the same row
        twice.

        Args:
            vehicle_id: restrict to deliveries belonging to this vehicle, via either parent.
            delivery_id: restrict to the one delivery with this id, via either parent.

        Returns:
            A `UNION ALL` selecting `id`, `vehicle_id`, `kind`, `source`, `remote_name`,
            `delivered_at`, `fetched_at`, `has_content`, `size_bytes`, `parse_state` and
            `raw_available`.
        """
        portal = select(
            deliveries.c.id,
            data_requests.c.vehicle_id,
            data_requests.c.kind,
            literal("portal").label("source"),
            deliveries.c.remote_name,
            deliveries.c.delivered_at,
            deliveries.c.fetched_at,
            deliveries.c.has_content,
            deliveries.c.size_bytes,
            deliveries.c.parse_state,
            deliveries.c.raw_payload.is_not(None).label("raw_available"),
        ).select_from(
            deliveries.join(data_requests, deliveries.c.data_request_id == data_requests.c.id)
        )
        imported = select(
            deliveries.c.id,
            import_batches.c.vehicle_id,
            import_batches.c.kind,
            literal("import").label("source"),
            deliveries.c.remote_name,
            deliveries.c.delivered_at,
            deliveries.c.fetched_at,
            deliveries.c.has_content,
            deliveries.c.size_bytes,
            deliveries.c.parse_state,
            deliveries.c.raw_payload.is_not(None).label("raw_available"),
        ).select_from(
            deliveries.join(import_batches, deliveries.c.import_batch_id == import_batches.c.id)
        )
        if vehicle_id is not None:
            portal = portal.where(data_requests.c.vehicle_id == vehicle_id)
            imported = imported.where(import_batches.c.vehicle_id == vehicle_id)
        if delivery_id is not None:
            portal = portal.where(deliveries.c.id == delivery_id)
            imported = imported.where(deliveries.c.id == delivery_id)
        return union_all(portal, imported)

    async def list_for_vehicle(
        self, conn: AsyncConnection, vehicle_id: UUID, *, limit: int, offset: int
    ) -> tuple[list[DeliverySummaryRecord], int]:
        """List `vehicle_id`'s deliveries, newest-delivered first, with new-value activity.

        Deliveries with an unknown `delivered_at` (never confirmed by the portal) sort after
        every delivery with a known one, newest `fetched_at` breaking ties. New-value activity
        is computed with one grouped aggregate over `data_points`, outer-joined onto the
        delivery rows, never with one query per delivery.

        Args:
            conn: the connection to read through.
            vehicle_id: the vehicle to list deliveries for.
            limit: the maximum number of deliveries to return.
            offset: how many matching deliveries to skip, for paging.

        Returns:
            The page of deliveries and the total number of deliveries for `vehicle_id`.
        """
        base = self._delivery_rows(vehicle_id=vehicle_id).subquery()
        total = (await conn.execute(select(func.count()).select_from(base))).scalar_one()

        valid_captured_at = case(
            (data_points.c.captured_at_quality != "invalid", data_points.c.captured_at),
            else_=None,
        )
        new_counts = (
            select(
                data_points.c.first_delivery_id,
                func.count().label("new_point_count"),
                func.min(valid_captured_at).label("new_captured_min"),
                func.max(valid_captured_at).label("new_captured_max"),
            )
            .where(data_points.c.vehicle_id == vehicle_id)
            .group_by(data_points.c.first_delivery_id)
            .subquery()
        )
        rows = (
            await conn.execute(
                select(
                    base.c.id,
                    base.c.kind,
                    base.c.source,
                    base.c.remote_name,
                    base.c.delivered_at,
                    base.c.fetched_at,
                    base.c.has_content,
                    base.c.size_bytes,
                    base.c.parse_state,
                    base.c.raw_available,
                    func.coalesce(new_counts.c.new_point_count, 0).label("new_point_count"),
                    new_counts.c.new_captured_min,
                    new_counts.c.new_captured_max,
                )
                .select_from(
                    base.outerjoin(new_counts, base.c.id == new_counts.c.first_delivery_id)
                )
                .order_by(
                    base.c.delivered_at.is_(None),
                    base.c.delivered_at.desc(),
                    base.c.fetched_at.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
        ).all()
        return [self._summary_record(row) for row in rows], total

    def _summary_record(self, row: Any) -> DeliverySummaryRecord:
        return DeliverySummaryRecord(
            id=row.id,
            kind=row.kind,
            source=row.source,
            remote_name=row.remote_name,
            delivered_at=row.delivered_at,
            fetched_at=row.fetched_at,
            has_content=row.has_content,
            size_bytes=row.size_bytes,
            parse_state=row.parse_state,
            raw_available=row.raw_available,
            new_point_count=row.new_point_count,
            new_captured_min=row.new_captured_min,
            new_captured_max=row.new_captured_max,
        )

    async def get_detail(
        self, conn: AsyncConnection, delivery_id: UUID
    ) -> DeliveryDetailRecord | None:
        """Return one delivery's metadata, for the delivery detail page.

        Args:
            conn: the connection to read through.
            delivery_id: the delivery to look up.

        Returns:
            The delivery's detail record, or `None` if no such delivery exists.
        """
        row = (await conn.execute(self._delivery_rows(delivery_id=delivery_id))).first()
        if row is None:
            return None
        valid_captured_at = case(
            (data_points.c.captured_at_quality != "invalid", data_points.c.captured_at),
            else_=None,
        )
        counts = (
            await conn.execute(
                select(
                    func.count(),
                    func.min(valid_captured_at),
                    func.max(valid_captured_at),
                ).where(data_points.c.first_delivery_id == delivery_id)
            )
        ).one()
        return DeliveryDetailRecord(
            id=row.id,
            kind=row.kind,
            source=row.source,
            remote_name=row.remote_name,
            delivered_at=row.delivered_at,
            fetched_at=row.fetched_at,
            has_content=row.has_content,
            size_bytes=row.size_bytes,
            parse_state=row.parse_state,
            raw_available=row.raw_available,
            new_point_count=counts[0],
            new_captured_min=counts[1],
            new_captured_max=counts[2],
            vehicle_id=row.vehicle_id,
        )

    async def get_raw_payload(self, conn: AsyncConnection, delivery_id: UUID) -> bytes | None:
        """Return `delivery_id`'s raw payload, or `None` if purged, a placeholder, or unknown.

        Never returns anything but the payload itself: the caller that needs to tell "purged"
        apart from "unknown delivery id" already has the delivery's `raw_available` flag from
        `get_detail`.
        """
        row = (
            await conn.execute(
                select(deliveries.c.raw_payload).where(deliveries.c.id == delivery_id)
            )
        ).first()
        return row.raw_payload if row is not None else None


class ImportBatchRepository:
    """Reads and writes `import_batches`."""

    async def delete_for_vehicle(self, conn: AsyncConnection, vehicle_id: UUID) -> int:
        """Delete every import batch belonging to `vehicle_id`.

        Caller's responsibility: every `deliveries` row referencing one of these batches
        must already be deleted.

        Returns:
            The number of rows deleted.
        """
        result = await conn.execute(
            delete(import_batches).where(import_batches.c.vehicle_id == vehicle_id)
        )
        return result.rowcount


class DataPointRepository:
    """Reads and writes `data_points`, the highest-volume table in the schema."""

    async def upsert_many(
        self,
        conn: AsyncConnection,
        *,
        vehicle_id: UUID,
        delivery_id: UUID,
        points: Sequence[DataPoint],
        seen_at: datetime,
    ) -> UpsertResult:
        """Insert new data points and bump `last_seen_at`/`seen_count` on repeated ones.

        Processes `points` in batches: existing dedup keys are looked up with one `IN` query
        per batch (never one `SELECT` per point), new rows are inserted with `executemany`,
        and repeated rows are updated with a single `UPDATE ... WHERE id IN (...)` per batch.
        Several input points sharing a dedup key collapse into one row, keeping only the
        first; this is the delivery-level counterpart of the single-row "no redundancy
        blow-up" rule the table as a whole follows.

        Args:
            conn: the connection to write through.
            vehicle_id: the vehicle every point belongs to.
            delivery_id: the delivery `points` were parsed from, recorded as `first_delivery_id`
                for newly inserted rows.
            points: the parsed points to store.
            seen_at: the time to record as `first_seen_at`/`last_seen_at` for this batch.

        Returns:
            The count of newly inserted versus repeated points, after within-batch
            deduplication, plus the `(id, point)` pairs for every newly inserted row.
        """
        unique_points: dict[str, DataPoint] = {}
        for point in points:
            key = compute_dedup_key(point.key, point.field_name, point.captured_at, point.value_raw)
            unique_points.setdefault(key, point)

        if not unique_points:
            return UpsertResult(new=0, repeated=0)

        existing_ids: dict[str, UUID] = {}
        all_keys = list(unique_points.keys())
        for chunk in _chunks(all_keys):
            rows = (
                await conn.execute(
                    select(data_points.c.dedup_key, data_points.c.id).where(
                        data_points.c.vehicle_id == vehicle_id,
                        data_points.c.dedup_key.in_(chunk),
                    )
                )
            ).all()
            for row in rows:
                existing_ids[row.dedup_key] = row.id

        new_rows: list[dict[str, Any]] = []
        new_points: list[tuple[UUID, DataPoint]] = []
        repeated_ids: list[UUID] = []
        for key, point in unique_points.items():
            if key in existing_ids:
                repeated_ids.append(existing_ids[key])
                continue
            typed = parse_value(point.value_raw)
            if point.value_raw is None:
                value_type = "null"
            elif typed.boolean is not None:
                value_type = "bool"
            elif typed.num is not None:
                value_type = "num"
            elif typed.time is not None:
                value_type = "time"
            else:
                value_type = "text"
            new_id = uuid4()
            new_points.append((new_id, point))
            new_rows.append(
                {
                    "id": new_id,
                    "vehicle_id": vehicle_id,
                    "key": point.key,
                    "field_name": point.field_name,
                    "field_generic": generic_field_name(point.field_name),
                    "value_raw": point.value_raw,
                    "value_type": value_type,
                    "value_num": typed.num,
                    "value_text": typed.text,
                    "value_bool": typed.boolean,
                    "value_time": typed.time,
                    "captured_at": point.captured_at,
                    "captured_at_quality": str(point.captured_at_quality),
                    "first_delivery_id": delivery_id,
                    "first_seen_at": seen_at,
                    "last_seen_at": seen_at,
                    "seen_count": 1,
                    "dedup_key": key,
                }
            )

        for chunk in _chunks(new_rows):
            await conn.execute(insert(data_points), list(chunk))

        for chunk in _chunks(repeated_ids):
            await conn.execute(
                update(data_points)
                .where(data_points.c.id.in_(chunk))
                .values(last_seen_at=seen_at, seen_count=data_points.c.seen_count + 1)
            )

        return UpsertResult(
            new=len(new_rows), repeated=len(repeated_ids), new_points=tuple(new_points)
        )

    async def list_for_vehicle(
        self, conn: AsyncConnection, vehicle_id: UUID
    ) -> list[tuple[UUID, DataPoint]]:
        """Return every stored data point for `vehicle_id`, reconstructed as `DataPoint`s.

        Used by `services.reparse.Reparser.remap` to recompute signal values for a new
        mapping version without re-parsing the original deliveries.

        Args:
            conn: the connection to read through.
            vehicle_id: the vehicle to fetch points for.

        Returns:
            `(id, point)` pairs, in no particular order.
        """
        rows = (
            await conn.execute(select(data_points).where(data_points.c.vehicle_id == vehicle_id))
        ).all()
        return [
            (
                row.id,
                DataPoint(
                    key=row.key,
                    field_name=row.field_name,
                    value_raw=row.value_raw,
                    captured_at=row.captured_at,
                    captured_at_quality=TimestampQuality(row.captured_at_quality),
                ),
            )
            for row in rows
        ]

    async def delete_for_vehicle(self, conn: AsyncConnection, vehicle_id: UUID) -> int:
        """Delete every data point belonging to `vehicle_id`.

        Caller's responsibility: every `signal_values` row referencing one of these
        points must already be deleted.

        Returns:
            The number of rows deleted.
        """
        result = await conn.execute(
            delete(data_points).where(data_points.c.vehicle_id == vehicle_id)
        )
        return result.rowcount

    async def list_fields_for_vehicle(
        self, conn: AsyncConnection, vehicle_id: UUID
    ) -> list[FieldSummaryRecord]:
        """Summarize every generalized field `vehicle_id` has ever reported, for the data explorer.

        Does the aggregation in SQL (`GROUP BY`/window function), never by loading every
        data point into Python: a vehicle can have millions of rows but only a few thousand
        distinct generalized fields.

        Args:
            conn: the connection to read through.
            vehicle_id: the vehicle to summarize fields for.

        Returns:
            One `FieldSummaryRecord` per generalized field name, in no particular order
            (`services.explorer.ExplorerService` sorts and filters the result).
        """
        valid_captured_at = case(
            (data_points.c.captured_at_quality != "invalid", data_points.c.captured_at),
            else_=None,
        )
        aggregate_rows = (
            await conn.execute(
                select(
                    data_points.c.field_generic,
                    func.count().label("point_count"),
                    func.count(func.distinct(data_points.c.value_raw)).label(
                        "distinct_value_count"
                    ),
                    func.min(valid_captured_at).label("first_captured_at"),
                    func.max(valid_captured_at).label("last_captured_at"),
                    func.min(data_points.c.key).label("key"),
                )
                .where(
                    data_points.c.vehicle_id == vehicle_id,
                    data_points.c.field_generic.is_not(None),
                )
                .group_by(data_points.c.field_generic)
            )
        ).all()
        if not aggregate_rows:
            return []

        last_value_by_field = await self._last_values_by_field(conn, vehicle_id)
        return [
            FieldSummaryRecord(
                field_generic=row.field_generic,
                key=row.key,
                point_count=row.point_count,
                distinct_value_count=row.distinct_value_count,
                first_captured_at=row.first_captured_at,
                last_captured_at=row.last_captured_at,
                last_value_raw=last_value_by_field.get(row.field_generic),
            )
            for row in aggregate_rows
        ]

    async def _last_values_by_field(
        self, conn: AsyncConnection, vehicle_id: UUID
    ) -> dict[str, str | None]:
        """Return the "current" `value_raw` per generalized field, chosen by `_rank_order`."""
        ranked = (
            select(
                data_points.c.field_generic,
                data_points.c.value_raw,
                func.row_number()
                .over(partition_by=data_points.c.field_generic, order_by=_rank_order())
                .label("rn"),
            )
            .where(
                data_points.c.vehicle_id == vehicle_id,
                data_points.c.field_generic.is_not(None),
            )
            .subquery()
        )
        rows = (
            await conn.execute(
                select(ranked.c.field_generic, ranked.c.value_raw).where(ranked.c.rn == 1)
            )
        ).all()
        return {row.field_generic: row.value_raw for row in rows}

    async def list_field_values(
        self, conn: AsyncConnection, vehicle_id: UUID, field_generic: str, *, limit: int = 200
    ) -> list[FieldValueRecord]:
        """Return the most recent data points sharing `field_generic`, newest first.

        Args:
            conn: the connection to read through.
            vehicle_id: the vehicle to read points for.
            field_generic: the generalized field name to filter on.
            limit: the maximum number of points to return.

        Returns:
            Up to `limit` points, ordered by `_rank_order` (a valid `captured_at` first and
            newest first, falling back to `last_seen_at` for points with no valid timestamp).
        """
        rows = (
            await conn.execute(
                select(
                    data_points.c.field_name,
                    data_points.c.value_raw,
                    data_points.c.captured_at,
                    data_points.c.captured_at_quality,
                    data_points.c.first_seen_at,
                    data_points.c.seen_count,
                )
                .where(
                    data_points.c.vehicle_id == vehicle_id,
                    data_points.c.field_generic == field_generic,
                )
                .order_by(*_rank_order())
                .limit(limit)
            )
        ).all()
        return [
            FieldValueRecord(
                field_name=row.field_name,
                value_raw=row.value_raw,
                captured_at=row.captured_at,
                captured_at_quality=row.captured_at_quality,
                first_seen_at=row.first_seen_at,
                seen_count=row.seen_count,
            )
            for row in rows
        ]

    async def first_seen_by_dedup_keys(
        self, conn: AsyncConnection, vehicle_id: UUID, keys: Sequence[str]
    ) -> dict[str, tuple[UUID, datetime]]:
        """Resolve where each of `keys` was first stored for `vehicle_id`.

        Used to classify a freshly re-parsed delivery's values as new (this delivery is the
        first source) or already known (some earlier delivery was), without a query per value.

        Args:
            conn: the connection to read through.
            vehicle_id: the vehicle the dedup keys belong to.
            keys: the `storage.dedup.dedup_key` values to resolve.

        Returns:
            A mapping from dedup key to `(first_delivery_id, first_seen_at)`; a key never
            stored for this vehicle is simply absent.
        """
        result: dict[str, tuple[UUID, datetime]] = {}
        for chunk in _chunks(list(dict.fromkeys(keys))):
            rows = (
                await conn.execute(
                    select(
                        data_points.c.dedup_key,
                        data_points.c.first_delivery_id,
                        data_points.c.first_seen_at,
                    ).where(
                        data_points.c.vehicle_id == vehicle_id,
                        data_points.c.dedup_key.in_(chunk),
                    )
                )
            ).all()
            for row in rows:
                result[row.dedup_key] = (row.first_delivery_id, row.first_seen_at)
        return result

    async def list_first_seen_in_delivery(
        self, conn: AsyncConnection, delivery_id: UUID, *, limit: int, offset: int
    ) -> tuple[list[FirstSeenPointRecord], int]:
        """List the data points this delivery was the first to report, by field name.

        Used only when the delivery's `raw_payload` is unavailable (purged, or never stored
        for a placeholder) and the values it merely repeated can no longer be told apart from
        values it introduced, since both would need a re-parse of the original bytes.

        Args:
            conn: the connection to read through.
            delivery_id: the delivery to list first-seen points for.
            limit: the maximum number of points to return.
            offset: how many matching points to skip, for paging.

        Returns:
            The page of points and the total number of points this delivery first reported.
        """
        total = (
            await conn.execute(
                select(func.count())
                .select_from(data_points)
                .where(data_points.c.first_delivery_id == delivery_id)
            )
        ).scalar_one()
        rows = (
            await conn.execute(
                select(
                    data_points.c.key,
                    data_points.c.field_name,
                    data_points.c.value_raw,
                    data_points.c.captured_at,
                    data_points.c.captured_at_quality,
                    data_points.c.first_seen_at,
                )
                .where(data_points.c.first_delivery_id == delivery_id)
                .order_by(data_points.c.field_name)
                .limit(limit)
                .offset(offset)
            )
        ).all()
        return [
            FirstSeenPointRecord(
                key=row.key,
                field_name=row.field_name,
                value_raw=row.value_raw,
                captured_at=row.captured_at,
                captured_at_quality=row.captured_at_quality,
                first_seen_at=row.first_seen_at,
            )
            for row in rows
        ], total


def _rank_order() -> tuple[ColumnElement[Any], ...]:
    """Order data points "current first".

    A valid `captured_at` sorts before an invalid/missing one, newest `captured_at` first,
    falling back to `last_seen_at` as a tiebreaker.
    """
    return (
        (data_points.c.captured_at_quality != "invalid").desc(),
        data_points.c.captured_at.desc(),
        data_points.c.last_seen_at.desc(),
    )


class SignalValueRepository:
    """Reads and writes `signal_values`, derived from `data_points` by a `SignalMapper`."""

    async def add_many(
        self,
        conn: AsyncConnection,
        *,
        vehicle_id: UUID,
        values_with_source_ids: Sequence[tuple[SignalValue, UUID]],
    ) -> int:
        """Insert signal values, skipping any already stored for the same source point.

        Idempotent over `(source_data_point_id, signal, mapping_version)`: re-mapping the
        same data point with the same mapper version never creates a duplicate row, so a
        delivery re-parsed after a crash or a `remap` re-run over already-mapped points is
        safe to repeat.

        Args:
            conn: the connection to write through.
            vehicle_id: the vehicle every value belongs to.
            values_with_source_ids: `(value, source_data_point_id)` pairs, typically from
                `core.signals.associate_source_ids`.

        Returns:
            The number of rows actually inserted.
        """
        if not values_with_source_ids:
            return 0

        keys = [
            (source_id, value.signal, value.mapping_version)
            for value, source_id in values_with_source_ids
        ]
        existing: set[tuple[UUID, str, str]] = set()
        for chunk in _chunks(keys):
            source_ids = {key[0] for key in chunk}
            rows = (
                await conn.execute(
                    select(
                        signal_values.c.source_data_point_id,
                        signal_values.c.signal,
                        signal_values.c.mapping_version,
                    ).where(signal_values.c.source_data_point_id.in_(source_ids))
                )
            ).all()
            existing.update(
                (row.source_data_point_id, row.signal, row.mapping_version) for row in rows
            )

        new_rows: list[dict[str, Any]] = []
        seen_in_batch: set[tuple[UUID, str, str]] = set()
        for value, source_id in values_with_source_ids:
            dedup = (source_id, value.signal, value.mapping_version)
            if dedup in existing or dedup in seen_in_batch:
                continue
            seen_in_batch.add(dedup)
            # `bool` is a subclass of `int`, so it must be checked before the numeric case.
            is_bool = isinstance(value.value, bool)
            is_num = not is_bool and isinstance(value.value, (int, float))
            new_rows.append(
                {
                    "id": uuid4(),
                    "vehicle_id": vehicle_id,
                    "signal": value.signal,
                    "value_num": value.value if is_num else None,
                    "value_text": value.value if isinstance(value.value, str) else None,
                    "value_bool": value.value if is_bool else None,
                    "unit": value.unit,
                    "captured_at": value.captured_at,
                    "captured_at_quality": str(value.captured_at_quality),
                    "source_data_point_id": source_id,
                    "mapping_version": value.mapping_version,
                }
            )

        for chunk in _chunks(new_rows):
            await conn.execute(insert(signal_values), list(chunk))
        return len(new_rows)

    async def latest_for_vehicle(
        self, conn: AsyncConnection, vehicle_id: UUID
    ) -> dict[str, list[SignalValueRecord]]:
        """Return every stored signal value for `vehicle_id`, grouped by signal.

        Returns every source field's value, not just one "best" value per signal: picking
        the one to display is `core.signals.preferred`'s job, done at read time against a
        mapper's preference order, not baked into storage. Each value also carries the
        `data_requests.kind` of the delivery that first reported it, so callers can tell
        which values ever arrived through a `"partial"` request versus only through the
        one-off `"all"` dump.

        Args:
            conn: the connection to read through.
            vehicle_id: the vehicle to fetch values for.

        Returns:
            A mapping from signal name to its stored values, in no particular order.
        """
        rows = (
            await conn.execute(
                select(
                    signal_values,
                    data_points.c.field_name.label("source_field"),
                    data_points.c.first_seen_at.label("first_seen_at"),
                    data_requests.c.kind.label("source_request_kind"),
                )
                .select_from(signal_values)
                .join(data_points, signal_values.c.source_data_point_id == data_points.c.id)
                .join(deliveries, data_points.c.first_delivery_id == deliveries.c.id)
                .outerjoin(data_requests, deliveries.c.data_request_id == data_requests.c.id)
                .where(signal_values.c.vehicle_id == vehicle_id)
            )
        ).all()
        grouped: dict[str, list[SignalValueRecord]] = {}
        for row in rows:
            grouped.setdefault(row.signal, []).append(_signal_value_record(row))
        return grouped

    async def delete_for_vehicle(self, conn: AsyncConnection, vehicle_id: UUID) -> int:
        """Delete every signal value belonging to `vehicle_id`.

        Returns:
            The number of rows deleted.
        """
        result = await conn.execute(
            delete(signal_values).where(signal_values.c.vehicle_id == vehicle_id)
        )
        return result.rowcount


class CollectorRunRepository:
    """Reads and writes `collector_runs`."""

    async def add(
        self,
        conn: AsyncConnection,
        *,
        account_id: UUID,
        data_request_id: UUID | None,
        started_at: datetime,
        finished_at: datetime,
        outcome: str,
        listed: int | None,
        placeholders: int | None,
        downloaded: int | None,
        with_content: int | None,
        pending: int | None,
        oldest_pending_age_s: float | None,
        message: str | None,
    ) -> UUID:
        """Insert a new collector run record.

        Returns:
            The new run's id.
        """
        run_id = uuid4()
        await conn.execute(
            insert(collector_runs).values(
                id=run_id,
                account_id=account_id,
                data_request_id=data_request_id,
                started_at=started_at,
                finished_at=finished_at,
                outcome=outcome,
                listed=listed,
                placeholders=placeholders,
                downloaded=downloaded,
                with_content=with_content,
                pending=pending,
                oldest_pending_age_s=oldest_pending_age_s,
                message=message,
            )
        )
        return run_id

    async def exists(
        self,
        conn: AsyncConnection,
        *,
        account_id: UUID,
        data_request_id: UUID | None,
        started_at: datetime,
        outcome: str,
    ) -> bool:
        """Return whether a run with this exact identity is already stored.

        Used by the sampler import to avoid re-inserting a run it already imported on a
        previous pass; `(account_id, data_request_id, started_at, outcome)` is not a
        database-enforced unique key (the collector itself never needs one, since it only
        ever appends), so this is a plain existence check rather than an upsert.
        """
        request_match = (
            collector_runs.c.data_request_id.is_(None)
            if data_request_id is None
            else collector_runs.c.data_request_id == data_request_id
        )
        row = (
            await conn.execute(
                select(collector_runs.c.id).where(
                    collector_runs.c.account_id == account_id,
                    request_match,
                    collector_runs.c.started_at == started_at,
                    collector_runs.c.outcome == outcome,
                )
            )
        ).first()
        return row is not None

    async def latest_for_request(
        self, conn: AsyncConnection, data_request_id: UUID
    ) -> CollectorRunRecord | None:
        """Return the most recently started run for `data_request_id`, or `None`."""
        row = (
            await conn.execute(
                select(collector_runs)
                .where(collector_runs.c.data_request_id == data_request_id)
                .order_by(collector_runs.c.started_at.desc())
                .limit(1)
            )
        ).first()
        return _collector_run_record(row) if row is not None else None

    async def latest_for_account(
        self, conn: AsyncConnection, account_id: UUID
    ) -> CollectorRunRecord | None:
        """Return the most recently started run for `account_id`, or `None`."""
        row = (
            await conn.execute(
                select(collector_runs)
                .where(collector_runs.c.account_id == account_id)
                .order_by(collector_runs.c.started_at.desc())
                .limit(1)
            )
        ).first()
        return _collector_run_record(row) if row is not None else None

    async def list_recent_for_vehicle(
        self,
        conn: AsyncConnection,
        account_id: UUID,
        data_request_ids: Sequence[UUID],
        *,
        limit: int = 20,
    ) -> list[CollectorRunRecord]:
        """Return the runs covering one vehicle, newest first.

        Combines the vehicle's own requests' runs with the owning account's account-level
        runs (login failures before any request could be resolved), which are not tied to
        any one vehicle but still affect every vehicle under that account.

        Args:
            conn: the connection to read through.
            account_id: the vehicle's owning account.
            data_request_ids: the vehicle's own data request ids.
            limit: the maximum number of most-recent runs to return.

        Returns:
            Up to `limit` runs, newest `started_at` first.
        """
        scope: ColumnElement[bool] = collector_runs.c.data_request_id.is_(None)
        if data_request_ids:
            scope = or_(scope, collector_runs.c.data_request_id.in_(data_request_ids))
        rows = (
            await conn.execute(
                select(collector_runs)
                .where(collector_runs.c.account_id == account_id, scope)
                .order_by(collector_runs.c.started_at.desc())
                .limit(limit)
            )
        ).all()
        return [_collector_run_record(row) for row in rows]

    async def latest(self, conn: AsyncConnection) -> CollectorRunRecord | None:
        """Return the most recently started run across every account, or `None`."""
        row = (
            await conn.execute(
                select(collector_runs).order_by(collector_runs.c.started_at.desc()).limit(1)
            )
        ).first()
        return _collector_run_record(row) if row is not None else None

    async def count_consecutive_non_ok(
        self, conn: AsyncConnection, data_request_id: UUID, *, limit: int = 10
    ) -> int:
        """Count the most recent consecutive non-`ok` runs of a data request.

        Counts back from the newest run, stopping at the first `ok` outcome (or when no
        more runs exist). Used to size the collector's backoff after repeated failures;
        `limit` caps how many rows are read, since the backoff schedule itself caps out
        after a handful of consecutive failures.

        Args:
            conn: the connection to read through.
            data_request_id: the data request whose run history to inspect.
            limit: the maximum number of most-recent runs to consider.

        Returns:
            The number of consecutive non-`ok` runs, from 0 up to `limit`.
        """
        rows = (
            await conn.execute(
                select(collector_runs.c.outcome)
                .where(collector_runs.c.data_request_id == data_request_id)
                .order_by(collector_runs.c.started_at.desc())
                .limit(limit)
            )
        ).all()
        count = 0
        for row in rows:
            if row.outcome == "ok":
                break
            count += 1
        return count

    async def delete_for_vehicle(self, conn: AsyncConnection, vehicle_id: UUID) -> int:
        """Delete every run belonging to one of `vehicle_id`'s data requests.

        Returns:
            The number of rows deleted.
        """
        request_ids = select(data_requests.c.id).where(data_requests.c.vehicle_id == vehicle_id)
        result = await conn.execute(
            delete(collector_runs).where(collector_runs.c.data_request_id.in_(request_ids))
        )
        return result.rowcount

    async def delete_for_account(self, conn: AsyncConnection, account_id: UUID) -> int:
        """Delete every run belonging to `account_id`, including account-level ones.

        Called after every vehicle under this account has already had its own runs
        deleted, so only account-level runs (a login failure before any data request
        could be resolved) remain to delete here.

        Returns:
            The number of rows deleted.
        """
        result = await conn.execute(
            delete(collector_runs).where(collector_runs.c.account_id == account_id)
        )
        return result.rowcount


def _version_sort_key(catalog_version: str) -> tuple[int, str]:
    """Order catalog versions by recency, without a stored import timestamp.

    `catalog_version` is either a dotted version (`"6.0"`) or a `YYYYMMDD` date, per
    `services.catalog.default_catalog_version`. Both forms are purely digits-and-dots, so
    zero-padding every dot-separated component to a fixed width and comparing the result
    as a string sorts numerically within either form (a later date is always numerically
    larger than any plausible dotted version). Anything else falls back to a lower-ranked,
    plain lexicographic comparison, so an unexpected format still orders deterministically
    instead of raising.
    """
    parts = catalog_version.split(".")
    if all(part.isdigit() for part in parts):
        return (1, ".".join(part.zfill(10) for part in parts))
    return (0, catalog_version)


class CatalogEntryRepository:
    """Reads and writes `catalog_entries`, the locally imported Data Dictionary content."""

    async def upsert_many(
        self,
        conn: AsyncConnection,
        *,
        provider_id: str,
        catalog_version: str,
        kind: str,
        entries: Sequence[CatalogEntryInput],
    ) -> CatalogImportCounts:
        """Insert new entries and update existing ones for `(provider_id, catalog_version)`.

        Args:
            conn: the connection to write through.
            provider_id: the provider the dictionary belongs to.
            catalog_version: the version every entry is stored under.
            kind: `continuous` or `historical`, as detected from the PDF.
            entries: the parsed rows to store, already deduplicated by key within the file.

        Returns:
            How many entries were newly inserted versus updated.
        """
        if not entries:
            return CatalogImportCounts(new=0, updated=0)

        existing_ids: dict[str, UUID] = {}
        all_keys = [entry.key for entry in entries]
        for chunk in _chunks(all_keys):
            rows = (
                await conn.execute(
                    select(catalog_entries.c.key, catalog_entries.c.id).where(
                        catalog_entries.c.provider_id == provider_id,
                        catalog_entries.c.catalog_version == catalog_version,
                        catalog_entries.c.key.in_(chunk),
                    )
                )
            ).all()
            for row in rows:
                existing_ids[row.key] = row.id

        new_rows: list[dict[str, Any]] = []
        update_rows: list[dict[str, Any]] = []
        for entry in entries:
            fields = {
                "name": entry.name,
                "description": entry.description,
                "unit": entry.unit,
                "data_type": entry.data_type,
                "clusters": entry.clusters,
                "kind": kind,
            }
            if entry.key in existing_ids:
                update_rows.append({"_id": existing_ids[entry.key], **fields})
            else:
                new_rows.append(
                    {
                        "id": uuid4(),
                        "provider_id": provider_id,
                        "catalog_version": catalog_version,
                        "key": entry.key,
                        **fields,
                    }
                )

        for chunk in _chunks(new_rows):
            await conn.execute(insert(catalog_entries), list(chunk))

        if update_rows:
            statement = (
                update(catalog_entries)
                .where(catalog_entries.c.id == bindparam("_id"))
                .values(
                    name=bindparam("name"),
                    description=bindparam("description"),
                    unit=bindparam("unit"),
                    data_type=bindparam("data_type"),
                    clusters=bindparam("clusters"),
                    kind=bindparam("kind"),
                )
            )
            for chunk in _chunks(update_rows):
                await conn.execute(statement, list(chunk))

        return CatalogImportCounts(new=len(new_rows), updated=len(update_rows))

    async def latest_for_keys(
        self, conn: AsyncConnection, provider_id: str, keys: Sequence[str]
    ) -> dict[str, CatalogEntryRecord]:
        """Return the newest-imported catalog entry per key in `keys`.

        Args:
            conn: the connection to read through.
            provider_id: the provider to look entries up for.
            keys: the dictionary keys to resolve.

        Returns:
            One entry per key that has ever been imported, picking the entry with the
            highest `_version_sort_key(catalog_version)` if a key exists under more than
            one imported version. Keys never imported are simply absent.
        """
        if not keys:
            return {}

        rows: list[Row[Any]] = []
        for chunk in _chunks(list(keys)):
            rows.extend(
                (
                    await conn.execute(
                        select(catalog_entries).where(
                            catalog_entries.c.provider_id == provider_id,
                            catalog_entries.c.key.in_(chunk),
                        )
                    )
                ).all()
            )

        best_by_key: dict[str, Row[Any]] = {}
        for row in rows:
            current = best_by_key.get(row.key)
            if current is None or _version_sort_key(row.catalog_version) > _version_sort_key(
                current.catalog_version
            ):
                best_by_key[row.key] = row
        return {key: _catalog_entry_record(row) for key, row in best_by_key.items()}

    async def list_versions(self, conn: AsyncConnection) -> list[CatalogVersionSummary]:
        """List every imported `(provider_id, catalog_version)`, with its kind and entry count."""
        rows = (
            await conn.execute(
                select(
                    catalog_entries.c.provider_id,
                    catalog_entries.c.catalog_version,
                    catalog_entries.c.kind,
                    func.count().label("entry_count"),
                )
                .group_by(
                    catalog_entries.c.provider_id,
                    catalog_entries.c.catalog_version,
                    catalog_entries.c.kind,
                )
                .order_by(catalog_entries.c.provider_id, catalog_entries.c.catalog_version)
            )
        ).all()
        return [
            CatalogVersionSummary(
                provider_id=row.provider_id,
                catalog_version=row.catalog_version,
                kind=row.kind,
                entry_count=row.entry_count,
            )
            for row in rows
        ]


class BackupRepository:
    """Reads and writes `backups`."""

    async def add(
        self,
        conn: AsyncConnection,
        *,
        id: UUID,
        created_at: datetime,
        path: str,
        size_bytes: int,
        sha256: str,
        verified: bool,
        error: str | None,
    ) -> UUID:
        """Insert a new backup record, successful or failed.

        Returns:
            The new record's id.
        """
        await conn.execute(
            insert(backups).values(
                id=id,
                created_at=created_at,
                path=path,
                size_bytes=size_bytes,
                sha256=sha256,
                verified=verified,
                error=error,
            )
        )
        return id

    async def latest_verified(self, conn: AsyncConnection) -> BackupRecord | None:
        """Return the most recently created backup that passed its integrity check, or `None`."""
        row = (
            await conn.execute(
                select(backups)
                .where(backups.c.verified.is_(True))
                .order_by(backups.c.created_at.desc())
                .limit(1)
            )
        ).first()
        return _backup_record(row) if row is not None else None


@dataclass(frozen=True, slots=True)
class OperatorSessionRecord:
    """One row of `operator_sessions`.

    Attributes:
        token_hash: hex SHA-256 of the session token; the raw token is never stored.
        expires_at: the absolute end of the session, independent of activity.
    """

    id: UUID
    token_hash: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime


class OperatorSessionRepository:
    """Reads and writes `operator_sessions`."""

    async def add(
        self,
        conn: AsyncConnection,
        *,
        id: UUID,
        token_hash: str,
        created_at: datetime,
        last_seen_at: datetime,
        expires_at: datetime,
    ) -> UUID:
        """Insert a new session.

        Returns:
            The new session's id.
        """
        await conn.execute(
            insert(operator_sessions).values(
                id=id,
                token_hash=token_hash,
                created_at=created_at,
                last_seen_at=last_seen_at,
                expires_at=expires_at,
            )
        )
        return id

    async def get_by_token_hash(
        self, conn: AsyncConnection, token_hash: str
    ) -> OperatorSessionRecord | None:
        """Return the session with this token hash, or `None`."""
        row = (
            await conn.execute(
                select(operator_sessions).where(operator_sessions.c.token_hash == token_hash)
            )
        ).first()
        if row is None:
            return None
        return OperatorSessionRecord(
            id=row.id,
            token_hash=row.token_hash,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
            expires_at=row.expires_at,
        )

    async def touch(self, conn: AsyncConnection, session_id: UUID, last_seen_at: datetime) -> None:
        """Record activity on a session."""
        await conn.execute(
            update(operator_sessions)
            .where(operator_sessions.c.id == session_id)
            .values(last_seen_at=last_seen_at)
        )

    async def delete_by_token_hash(self, conn: AsyncConnection, token_hash: str) -> int:
        """Delete the session with this token hash.

        Returns:
            The number of rows deleted (0 or 1).
        """
        result = await conn.execute(
            delete(operator_sessions).where(operator_sessions.c.token_hash == token_hash)
        )
        return int(result.rowcount)

    async def delete_all(self, conn: AsyncConnection) -> int:
        """Delete every session.

        Returns:
            The number of rows deleted.
        """
        result = await conn.execute(delete(operator_sessions))
        return int(result.rowcount)

    async def delete_expired(
        self, conn: AsyncConnection, *, expired_before: datetime, idle_before: datetime
    ) -> int:
        """Delete sessions past their absolute expiry or idle for too long.

        Args:
            conn: the connection to run on.
            expired_before: sessions with `expires_at` at or before this are deleted.
            idle_before: sessions with `last_seen_at` at or before this are deleted.

        Returns:
            The number of rows deleted.
        """
        result = await conn.execute(
            delete(operator_sessions).where(
                or_(
                    operator_sessions.c.expires_at <= expired_before,
                    operator_sessions.c.last_seen_at <= idle_before,
                )
            )
        )
        return int(result.rowcount)
