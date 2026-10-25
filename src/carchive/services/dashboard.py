"""Dashboard and vehicle detail service: read-only views over collected data and monitoring.

Everything here only reads; interpretation (which value to show, how fresh it is, which
monitoring state applies) happens at read time against `core.signals`/`core.timeutil`, never
stored. Thresholds are module constants, separate from `services.collector`'s own defaults:
the collector sizes them per provider capability, the dashboard always shows a fixed view.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncConnection

from carchive.config import Settings
from carchive.core.models import SignalValue, TimestampQuality
from carchive.core.provider import ProviderRegistry
from carchive.core.signals import SignalKind, preferred, spec
from carchive.core.timeutil import Freshness, freshness
from carchive.services.backup import BackupService
from carchive.storage.db import Database
from carchive.storage.records import (
    AccountRecord,
    CollectorRunRecord,
    DataRequestRecord,
    SignalValueRecord,
    VehicleRecord,
)
from carchive.storage.repositories import (
    AccountRepository,
    CollectorRunRepository,
    DataRequestRepository,
    DeliveryRepository,
    SignalValueRepository,
    VehicleRepository,
)

# Fixed display order for the dashboard card; a signal not in `_BASE_SIGNALS` only shows up
# if the vehicle has ever reported it at all.
DASHBOARD_SIGNAL_ORDER: tuple[str, ...] = (
    "vehicle.odometer",
    "battery.soc",
    "fuel.level",
    "range.primary",
    "climate.outdoor_temperature",
    "charging.state",
    "charging.power",
    "plug.connection_state",
)
_BASE_SIGNALS = frozenset({"vehicle.odometer", "battery.soc", "fuel.level", "range.primary"})

# Monitoring thresholds; configurable defaults, kept as module constants until a
# settings field is needed.
_BACKLOG_THRESHOLD = 25
_RETENTION_THRESHOLD_S = 5 * 86400.0
_NO_CONTENT_THRESHOLD = timedelta(hours=6)
_NO_DELIVERIES_THRESHOLD = timedelta(hours=1)
_PORTAL_UNAVAILABLE_RUNS = 3
_PORTAL_UNAVAILABLE_OUTCOMES = frozenset({"error", "login_failed"})
_RECENT_RUNS_FOR_NOTICES = 10
_RECENT_RUNS_FOR_DETAIL = 20
BACKUP_WARNING_AGE = timedelta(hours=36)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    """How urgently a `Notice` should be shown."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Notice:
    """One monitoring finding or `needs_attention` reason, for the GUI to word.

    `kind` identifies which translated template the GUI uses; `params` are the values that
    template interpolates (e.g. a pending-file count or a data request's kind). Carrying no
    rendered text keeps every message translatable without the service layer knowing i18n.
    """

    kind: str
    severity: Severity
    params: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SignalCell:
    """One signal's current value on a vehicle card or detail page.

    Attributes:
        value: `None` means no value has ever been stored for this signal — never `0`.
        kind: the signal's `core.signals.SignalKind`; lets the GUI tell a portal enum value
            (shown as-is, never localized or number-formatted) from a measurement.
        age_s: seconds between `value`'s `captured_at` and the time the view was built, or
            `None` if there is no value or its timestamp could not be determined.
        freshness: `unknown` exactly when `age_s` is `None`.
    """

    signal: str
    value: float | str | bool | None
    unit: str | None
    kind: SignalKind
    captured_at: datetime | None
    captured_at_quality: TimestampQuality | None
    age_s: float | None
    freshness: Freshness


@dataclass(frozen=True, slots=True)
class VehicleCard:
    """One vehicle's dashboard card."""

    id: UUID
    label: str
    brand: str
    cells: tuple[SignalCell, ...]
    notices: tuple[Notice, ...]


@dataclass(frozen=True, slots=True)
class DashboardView:
    """Everything the dashboard page renders.

    Attributes:
        last_collector_run_age_s: age of the most recently started collector run across
            every account, or `None` if none has ever run.
        last_backup_age_s: age of the most recently created, verified backup, or `None` if
            there has never been one.
        backup_warning: `True` once the last verified backup is older than `BACKUP_WARNING_AGE`
            or there has never been one.
        accounts_needing_attention: labels of every account currently in state `needs_attention`.
    """

    cards: tuple[VehicleCard, ...]
    last_collector_run_age_s: float | None
    last_collector_run_outcome: str | None
    last_backup_age_s: float | None
    backup_warning: bool
    accounts_needing_attention: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceFieldValue:
    """One source field's contribution to a canonical signal, for the vehicle detail page."""

    source_field: str
    value: float | str | bool | None
    unit: str | None
    kind: SignalKind
    captured_at: datetime | None
    captured_at_quality: TimestampQuality
    first_seen_at: datetime


@dataclass(frozen=True, slots=True)
class DataRequestInfo:
    """One data request, as shown on the vehicle detail page."""

    kind: str
    state: str
    state_reason: str | None
    next_due_at: datetime | None
    last_success_at: datetime | None


@dataclass(frozen=True, slots=True)
class CollectorRunInfo:
    """One collector run, as shown on the vehicle detail page.

    Attributes:
        request_kind: the data request kind this run served, or `None` for an account-level
            run (a login failure before any request could be resolved).
    """

    started_at: datetime
    finished_at: datetime
    outcome: str
    request_kind: str | None
    listed: int | None
    placeholders: int | None
    downloaded: int | None
    with_content: int | None
    pending: int | None
    oldest_pending_age_s: float | None
    message: str | None


@dataclass(frozen=True, slots=True)
class VehicleDetail:
    """Everything the vehicle detail page renders."""

    id: UUID
    label: str
    brand: str
    signals: Mapping[str, tuple[SourceFieldValue, ...]]
    data_requests: tuple[DataRequestInfo, ...]
    collector_runs: tuple[CollectorRunInfo, ...]
    notices: tuple[Notice, ...]


def _ordered_signal_names(names: Sequence[str]) -> list[str]:
    """Order `names` by `DASHBOARD_SIGNAL_ORDER` first, then alphabetically."""
    rank = {name: index for index, name in enumerate(DASHBOARD_SIGNAL_ORDER)}
    unranked = len(DASHBOARD_SIGNAL_ORDER)
    return sorted(names, key=lambda name: (rank.get(name, unranked), name))


def _to_signal_value(record: SignalValueRecord) -> SignalValue:
    """Reconstruct a `core.models.SignalValue` from a stored `SignalValueRecord`."""
    if record.value_num is not None:
        value: float | str | bool = record.value_num
    elif record.value_bool is not None:
        value = record.value_bool
    else:
        value = record.value_text or ""
    return SignalValue(
        signal=record.signal,
        value=value,
        unit=record.unit,
        captured_at=record.captured_at,
        captured_at_quality=TimestampQuality(record.captured_at_quality),
        source_key="",
        source_field=record.source_field,
        mapping_version=record.mapping_version,
    )


def _to_source_field_value(record: SignalValueRecord) -> SourceFieldValue:
    value = _to_signal_value(record)
    return SourceFieldValue(
        source_field=record.source_field,
        value=value.value,
        unit=value.unit,
        kind=spec(record.signal).kind,
        captured_at=value.captured_at,
        captured_at_quality=TimestampQuality(record.captured_at_quality),
        first_seen_at=record.first_seen_at,
    )


class DashboardService:
    """Read-only views for the dashboard and vehicle detail pages.

    Args:
        db: the database to read through.
        registry: looks up a vehicle's provider to get its `SignalMapper`'s preference order.
        settings: the application's runtime configuration.
        backup: if given, consulted for the status strip's backup age; `None` reports no
            backup information at all (shown by the GUI the same as "no backup yet").
        clock: returns the current UTC time; overridable for tests.
    """

    def __init__(
        self,
        db: Database,
        registry: ProviderRegistry,
        settings: Settings,
        *,
        backup: BackupService | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._db = db
        self._registry = registry
        self._settings = settings
        self._backup = backup
        self._clock = clock
        self._accounts = AccountRepository()
        self._vehicles = VehicleRepository()
        self._requests = DataRequestRepository()
        self._deliveries = DeliveryRepository()
        self._signal_values = SignalValueRepository()
        self._runs = CollectorRunRepository()

    async def overview(self) -> DashboardView:
        """Build the dashboard: one card per active vehicle, plus the global status strip."""
        async with self._db.read() as conn:
            vehicles = [v for v in await self._vehicles.list_all(conn) if v.archived_at is None]
            accounts_by_id = {a.id: a for a in await self._accounts.list_all(conn)}
            last_run = await self._runs.latest(conn)

            cards: list[VehicleCard] = []
            for vehicle in vehicles:
                account = accounts_by_id.get(vehicle.account_id)
                if account is None:
                    continue
                cards.append(await self._build_card(conn, vehicle, account))

        attention_labels = sorted(
            account.label
            for account in accounts_by_id.values()
            if account.state == "needs_attention"
        )
        backup_age = (
            await self._backup.latest_verified_age(self._clock())
            if self._backup is not None
            else None
        )
        last_run_age_s = (
            (self._clock() - last_run.started_at).total_seconds() if last_run is not None else None
        )
        return DashboardView(
            cards=tuple(cards),
            last_collector_run_age_s=last_run_age_s,
            last_collector_run_outcome=last_run.outcome if last_run else None,
            last_backup_age_s=backup_age.total_seconds() if backup_age is not None else None,
            backup_warning=backup_age is None or backup_age > BACKUP_WARNING_AGE,
            accounts_needing_attention=tuple(attention_labels),
        )

    async def vehicle_detail(self, vehicle_id: UUID) -> VehicleDetail | None:
        """Build the detail page for `vehicle_id`, or return `None` if it does not exist."""
        async with self._db.read() as conn:
            vehicle = await self._vehicles.get(conn, vehicle_id)
            if vehicle is None:
                return None
            account = await self._accounts.get(conn, vehicle.account_id)
            if account is None:
                return None

            grouped = await self._signal_values.latest_for_vehicle(conn, vehicle_id)
            requests = await self._requests.list_for_vehicle(conn, vehicle_id)
            recent_runs = await self._runs.list_recent_for_vehicle(
                conn, account.id, [r.id for r in requests], limit=_RECENT_RUNS_FOR_DETAIL
            )
            notices = await self._vehicle_notices(
                conn, account, requests, grouped, recent_runs=recent_runs
            )

        kind_by_request_id = {request.id: request.kind for request in requests}
        signals = {
            signal: tuple(
                _to_source_field_value(record)
                for record in sorted(
                    grouped[signal],
                    key=lambda r: r.captured_at or datetime.min.replace(tzinfo=UTC),
                    reverse=True,
                )
            )
            for signal in _ordered_signal_names(list(grouped))
        }
        return VehicleDetail(
            id=vehicle.id,
            label=vehicle.label,
            brand=vehicle.brand,
            signals=signals,
            data_requests=tuple(
                DataRequestInfo(
                    kind=r.kind,
                    state=r.state,
                    state_reason=r.state_reason,
                    next_due_at=r.next_due_at,
                    last_success_at=r.last_success_at,
                )
                for r in requests
            ),
            collector_runs=tuple(
                CollectorRunInfo(
                    started_at=run.started_at,
                    finished_at=run.finished_at,
                    outcome=run.outcome,
                    request_kind=(
                        kind_by_request_id.get(run.data_request_id)
                        if run.data_request_id is not None
                        else None
                    ),
                    listed=run.listed,
                    placeholders=run.placeholders,
                    downloaded=run.downloaded,
                    with_content=run.with_content,
                    pending=run.pending,
                    oldest_pending_age_s=run.oldest_pending_age_s,
                    message=run.message,
                )
                for run in recent_runs
            ),
            notices=notices,
        )

    async def _build_card(
        self, conn: AsyncConnection, vehicle: VehicleRecord, account: AccountRecord
    ) -> VehicleCard:
        grouped = await self._signal_values.latest_for_vehicle(conn, vehicle.id)
        requests = await self._requests.list_for_vehicle(conn, vehicle.id)
        preference = self._preference_fn(account.provider_id)

        cells: list[SignalCell] = []
        for signal in DASHBOARD_SIGNAL_ORDER:
            records = grouped.get(signal, [])
            if not records and signal not in _BASE_SIGNALS:
                continue
            cells.append(self._build_cell(signal, records, preference))

        notices = await self._vehicle_notices(conn, account, requests, grouped)
        return VehicleCard(
            id=vehicle.id,
            label=vehicle.label,
            brand=vehicle.brand,
            cells=tuple(cells),
            notices=notices,
        )

    def _preference_fn(self, provider_id: str) -> Callable[[str], tuple[str, ...]]:
        try:
            mapper = self._registry.get(provider_id).mapper()
        except (KeyError, NotImplementedError):
            return lambda _signal: ()
        return mapper.preference

    def _build_cell(
        self,
        signal: str,
        records: Sequence[SignalValueRecord],
        preference: Callable[[str], tuple[str, ...]],
    ) -> SignalCell:
        signal_spec = spec(signal)
        if not records:
            return SignalCell(
                signal=signal,
                value=None,
                unit=None,
                kind=signal_spec.kind,
                captured_at=None,
                captured_at_quality=None,
                age_s=None,
                freshness=Freshness.UNKNOWN,
            )
        values = [_to_signal_value(record) for record in records]
        chosen = preferred(values, preference(signal))
        assert chosen is not None  # `values` is non-empty, so `preferred` never returns `None`.
        now = self._clock()
        age_s = (
            (now - chosen.captured_at).total_seconds() if chosen.captured_at is not None else None
        )
        return SignalCell(
            signal=signal,
            value=chosen.value,
            unit=chosen.unit,
            kind=signal_spec.kind,
            captured_at=chosen.captured_at,
            captured_at_quality=chosen.captured_at_quality,
            age_s=age_s,
            freshness=freshness(
                chosen.captured_at, now, signal_spec.amber_after, signal_spec.red_after
            ),
        )

    async def _vehicle_notices(
        self,
        conn: AsyncConnection,
        account: AccountRecord,
        requests: Sequence[DataRequestRecord],
        grouped: Mapping[str, list[SignalValueRecord]],
        *,
        recent_runs: Sequence[CollectorRunRecord] | None = None,
    ) -> tuple[Notice, ...]:
        """Compute every monitoring notice and `needs_attention` reason for one vehicle."""
        notices: list[Notice] = []
        now = self._clock()
        request_ids = [request.id for request in requests]

        if account.state == "needs_attention":
            notices.append(
                Notice("account_needs_attention", Severity.ERROR, {"reason": account.state_reason})
            )
        for request in requests:
            if request.state == "needs_attention":
                notices.append(
                    Notice(
                        "request_needs_attention",
                        Severity.ERROR,
                        {"kind": request.kind, "reason": request.state_reason},
                    )
                )

        for request in requests:
            run = await self._runs.latest_for_request(conn, request.id)
            if run is None:
                continue
            if run.pending is not None and run.pending >= _BACKLOG_THRESHOLD:
                notices.append(
                    Notice(
                        "backlog_at_risk",
                        Severity.WARNING,
                        {"kind": request.kind, "pending": run.pending},
                    )
                )
            if (
                run.oldest_pending_age_s is not None
                and run.oldest_pending_age_s >= _RETENTION_THRESHOLD_S
            ):
                notices.append(
                    Notice(
                        "retention_at_risk",
                        Severity.ERROR,
                        {"kind": request.kind, "age_s": run.oldest_pending_age_s},
                    )
                )

        activity = await self._deliveries.activity_summary(conn, request_ids)
        if activity.placeholders_since_content > 0:
            reference = activity.latest_content_at or activity.earliest_delivery_at
            if reference is not None and now - reference >= _NO_CONTENT_THRESHOLD:
                notices.append(
                    Notice(
                        "no_content",
                        Severity.INFO,
                        {
                            "last_content_age_s": (
                                (now - activity.latest_content_at).total_seconds()
                                if activity.latest_content_at is not None
                                else None
                            ),
                            "empty_count": activity.placeholders_since_content,
                        },
                    )
                )

        for request in requests:
            if request.state != "active":
                continue
            request_activity = await self._deliveries.activity_summary(conn, [request.id])
            if (
                request_activity.latest_delivery_at is not None
                and now - request_activity.latest_delivery_at >= _NO_DELIVERIES_THRESHOLD
            ):
                notices.append(
                    Notice(
                        "no_deliveries",
                        Severity.WARNING,
                        {
                            "kind": request.kind,
                            "since_age_s": (
                                now - request_activity.latest_delivery_at
                            ).total_seconds(),
                        },
                    )
                )

        freshest_signal, freshest_value = self._freshest_signal(grouped)
        if freshest_signal is not None and freshest_value is not None:
            signal_spec = spec(freshest_signal)
            if (
                freshness(
                    freshest_value.captured_at, now, signal_spec.amber_after, signal_spec.red_after
                )
                == Freshness.STALE
            ):
                assert freshest_value.captured_at is not None  # implied by `Freshness.STALE`
                notices.append(
                    Notice(
                        "stale_values",
                        Severity.WARNING,
                        {
                            "signal": freshest_signal,
                            "newest_age_s": (now - freshest_value.captured_at).total_seconds(),
                        },
                    )
                )

        runs = (
            recent_runs
            if recent_runs is not None
            else await self._runs.list_recent_for_vehicle(
                conn, account.id, request_ids, limit=_RECENT_RUNS_FOR_NOTICES
            )
        )
        consecutive = 0
        for run in runs:
            if run.outcome not in _PORTAL_UNAVAILABLE_OUTCOMES:
                break
            consecutive += 1
        if consecutive >= _PORTAL_UNAVAILABLE_RUNS:
            notices.append(Notice("portal_unavailable", Severity.ERROR, {"count": consecutive}))

        return tuple(notices)

    def _freshest_signal(
        self, grouped: Mapping[str, list[SignalValueRecord]]
    ) -> tuple[str | None, SignalValue | None]:
        """Return the `(signal, value)` with the single newest `captured_at` across `grouped`.

        Picks, per signal, the mapper-independent newest valid value (ties do not matter
        here, only the timestamp does), then the overall newest among those. Used by the
        `stale_values` notice: if even the freshest thing this vehicle has ever reported is
        stale by its own signal's threshold, the vehicle is stale across the board.
        """
        best_signal: str | None = None
        best_value: SignalValue | None = None
        best_captured_at: datetime | None = None
        for signal, records in grouped.items():
            for record in records:
                value = _to_signal_value(record)
                captured_at = value.captured_at
                if captured_at is None or value.captured_at_quality == TimestampQuality.INVALID:
                    continue
                if best_captured_at is None or captured_at > best_captured_at:
                    best_signal, best_value, best_captured_at = signal, value, captured_at
        return best_signal, best_value
