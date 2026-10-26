"""Tests for `carchive.services.dashboard`."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert

from carchive.config import Settings
from carchive.core.provider import ProviderRegistry
from carchive.core.signals import SignalKind
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.services.backup import BackupService
from carchive.services.dashboard import DashboardService, Severity
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.schema import (
    accounts,
    backups,
    collector_runs,
    data_points,
    data_requests,
    deliveries,
    signal_values,
    vehicles,
)
from tests.services.fakes import FakeProvider

_NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
_VIN = "WAUZZZ4V0JA123456"


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data")


def _registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    provider = FakeProvider()
    provider.set_mapper(VwGroupMapper())
    registry.register(provider)
    return registry


def _service(
    db: Database, settings: Settings, *, backup: BackupService | None = None, now: datetime = _NOW
) -> DashboardService:
    return DashboardService(db, _registry(), settings, backup=backup, clock=lambda: now)


async def _seed_account(
    db: Database, *, state: str = "active", state_reason: str | None = None
) -> UUID:
    account_id = uuid4()
    async with db.write() as conn:
        await conn.execute(
            insert(accounts).values(
                id=account_id,
                provider_id="fake",
                brand="fake",
                label="acc",
                credential_ref="ref1",
                state=state,
                state_reason=state_reason,
                created_at=_NOW,
            )
        )
    return account_id


async def _seed_vehicle(
    db: Database, account_id: UUID, *, archived: bool = False, vin: str = _VIN
) -> UUID:
    vehicle_id = uuid4()
    async with db.write() as conn:
        await conn.execute(
            insert(vehicles).values(
                id=vehicle_id,
                account_id=account_id,
                vin=vin,
                label="car",
                brand="fake",
                model=None,
                created_at=_NOW,
                archived_at=_NOW if archived else None,
            )
        )
    return vehicle_id


async def _seed_request(
    db: Database,
    vehicle_id: UUID,
    *,
    kind: str = "partial",
    state: str = "active",
    state_reason: str | None = None,
    next_due_at: datetime | None = None,
    last_success_at: datetime | None = None,
) -> UUID:
    request_id = uuid4()
    async with db.write() as conn:
        await conn.execute(
            insert(data_requests).values(
                id=request_id,
                vehicle_id=vehicle_id,
                kind=kind,
                remote_id="r1",
                interval_s=900,
                next_due_at=next_due_at,
                state=state,
                state_reason=state_reason,
                last_success_at=last_success_at,
            )
        )
    return request_id


async def _seed_run(
    db: Database,
    account_id: UUID,
    request_id: UUID | None,
    *,
    started_at: datetime,
    outcome: str = "ok",
    pending: int | None = None,
    oldest_pending_age_s: float | None = None,
) -> None:
    async with db.write() as conn:
        await conn.execute(
            insert(collector_runs).values(
                id=uuid4(),
                account_id=account_id,
                data_request_id=request_id,
                started_at=started_at,
                finished_at=started_at,
                outcome=outcome,
                listed=0,
                placeholders=0,
                downloaded=0,
                with_content=0,
                pending=pending,
                oldest_pending_age_s=oldest_pending_age_s,
                message=None,
            )
        )


async def _seed_delivery(
    db: Database,
    request_id: UUID,
    *,
    remote_name: str,
    fetched_at: datetime,
    has_content: bool = True,
) -> UUID:
    delivery_id = uuid4()
    async with db.write() as conn:
        await conn.execute(
            insert(deliveries).values(
                id=delivery_id,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name=remote_name,
                delivered_at=fetched_at,
                fetched_at=fetched_at,
                has_content=has_content,
                sha256="0" * 64,
                size_bytes=1,
                parse_state="parsed" if has_content else "empty",
                parser_version="v1",
                raw_payload=None,
            )
        )
    return delivery_id


async def _seed_signal(
    db: Database,
    vehicle_id: UUID,
    delivery_id: UUID,
    *,
    signal: str,
    source_field: str,
    value: float,
    captured_at: datetime | None,
    quality: str = "exact",
    key: str | None = None,
    first_seen_at: datetime = _NOW,
) -> None:
    point_id = uuid4()
    async with db.write() as conn:
        await conn.execute(
            insert(data_points).values(
                id=point_id,
                vehicle_id=vehicle_id,
                key=key or source_field,
                field_name=source_field,
                value_raw=str(value),
                value_type="num",
                value_num=value,
                value_text=None,
                value_bool=None,
                value_time=None,
                captured_at=captured_at,
                captured_at_quality=quality,
                first_delivery_id=delivery_id,
                first_seen_at=first_seen_at,
                last_seen_at=first_seen_at,
                seen_count=1,
                dedup_key=f"dedup-{uuid4()}",
            )
        )
        await conn.execute(
            insert(signal_values).values(
                id=uuid4(),
                vehicle_id=vehicle_id,
                signal=signal,
                value_num=value,
                value_text=None,
                value_bool=None,
                unit="km" if "odometer" in signal else "%",
                captured_at=captured_at,
                captured_at_quality=quality,
                source_data_point_id=point_id,
                mapping_version="v1",
            )
        )


# --- preferred value selection on the card -----------------------------------


async def test_card_prefers_newer_value_over_mapper_priority(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    # "batteryStatus.currentSOC_pct" is the mapper's second choice, but it is newer.
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="currentSOCInPct",
        value=50.0,
        captured_at=_NOW - timedelta(hours=1),
    )
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="batteryStatus.currentSOC_pct",
        value=60.0,
        captured_at=_NOW,
    )

    view = await _service(db, settings).overview()

    soc_cell = next(c for c in view.cards[0].cells if c.signal == "battery.soc")
    assert soc_cell.value == 60.0


async def test_card_prefers_valid_value_over_newer_invalid_timestamp(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="currentSOCInPct",
        value=50.0,
        captured_at=_NOW - timedelta(days=10),
    )
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="batteryStatus.currentSOC_pct",
        value=99.0,
        captured_at=None,
        quality="invalid",
    )

    view = await _service(db, settings).overview()

    soc_cell = next(c for c in view.cards[0].cells if c.signal == "battery.soc")
    assert soc_cell.value == 50.0


# --- "no value" vs 0 ----------------------------------------------------------


async def test_zero_value_is_shown_but_absent_signal_is_none_not_zero(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="currentSOCInPct",
        value=0.0,
        captured_at=_NOW,
    )

    view = await _service(db, settings).overview()

    cells = {c.signal: c for c in view.cards[0].cells}
    assert cells["battery.soc"].value == 0.0
    # A base signal with no delivered value ever stays `None`, not `0`.
    assert cells["vehicle.odometer"].value is None
    assert cells["vehicle.odometer"].freshness == "unknown"


async def test_card_cell_reports_signal_kind_even_without_a_value(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="charging.state",
        source_field="chargingState",
        value=1.0,
        captured_at=_NOW,
    )

    view = await _service(db, settings).overview()

    cells = {c.signal: c for c in view.cards[0].cells}
    assert cells["charging.state"].kind == SignalKind.ENUM
    # A base numeric signal reports its kind even while it has no value at all yet.
    assert cells["vehicle.odometer"].value is None
    assert cells["vehicle.odometer"].kind == SignalKind.NUMERIC


async def test_non_base_signal_without_data_is_omitted_from_the_card(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    await _seed_request(db, vehicle_id)

    view = await _service(db, settings).overview()

    signals = {c.signal for c in view.cards[0].cells}
    assert "charging.power" not in signals
    assert "vehicle.odometer" in signals  # a base signal always appears


# --- freshness thresholds ------------------------------------------------------


async def test_freshness_levels_at_thresholds(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    # battery.soc thresholds: amber at 2 h, red at 24 h.
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="currentSOCInPct",
        value=42.0,
        captured_at=_NOW - timedelta(hours=2),
    )

    view = await _service(db, settings).overview()

    soc_cell = next(c for c in view.cards[0].cells if c.signal == "battery.soc")
    assert soc_cell.freshness == "aging"
    assert soc_cell.age_s == timedelta(hours=2).total_seconds()


# --- monitoring states ----------------------------------------------------------


async def test_backlog_at_risk_fires_at_threshold(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_run(db, account_id, request_id, started_at=_NOW, pending=25)

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "backlog_at_risk" in kinds


async def test_backlog_at_risk_does_not_fire_below_threshold(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_run(db, account_id, request_id, started_at=_NOW, pending=24)

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "backlog_at_risk" not in kinds


async def test_retention_at_risk_fires_at_five_days(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_run(
        db,
        account_id,
        request_id,
        started_at=_NOW,
        oldest_pending_age_s=timedelta(days=5).total_seconds(),
    )

    view = await _service(db, settings).overview()

    notice = next(n for n in view.cards[0].notices if n.kind == "retention_at_risk")
    assert notice.severity == Severity.ERROR


async def test_retention_at_risk_does_not_fire_below_five_days(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_run(
        db,
        account_id,
        request_id,
        started_at=_NOW,
        oldest_pending_age_s=timedelta(days=4, hours=23).total_seconds(),
    )

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "retention_at_risk" not in kinds


async def test_no_content_fires_after_six_hours_of_placeholders(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_delivery(
        db,
        request_id,
        remote_name="content.zip",
        fetched_at=_NOW - timedelta(hours=7),
        has_content=True,
    )
    await _seed_delivery(
        db,
        request_id,
        remote_name="empty1.zip",
        fetched_at=_NOW - timedelta(hours=6, minutes=30),
        has_content=False,
    )

    view = await _service(db, settings).overview()

    notice = next(n for n in view.cards[0].notices if n.kind == "no_content")
    assert notice.params["empty_count"] == 1


async def test_no_content_does_not_fire_without_any_placeholder(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_delivery(
        db, request_id, remote_name="content.zip", fetched_at=_NOW - timedelta(hours=7)
    )

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "no_content" not in kinds


async def test_no_content_reports_never_when_content_was_never_delivered(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_delivery(
        db,
        request_id,
        remote_name="empty1.zip",
        fetched_at=_NOW - timedelta(hours=7),
        has_content=False,
    )

    view = await _service(db, settings).overview()

    notice = next(n for n in view.cards[0].notices if n.kind == "no_content")
    assert notice.params["last_content_age_s"] is None


async def test_no_deliveries_fires_after_one_hour_of_silence_on_active_request(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id, state="active")
    await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW - timedelta(hours=2))

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "no_deliveries" in kinds


async def test_no_deliveries_does_not_fire_for_a_disabled_request(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id, state="disabled")
    await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW - timedelta(hours=2))

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "no_deliveries" not in kinds


async def test_stale_values_fires_when_even_the_newest_value_is_past_its_red_threshold(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    # battery.soc's red threshold is 24 h; this is the single newest value this vehicle has.
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="currentSOCInPct",
        value=10.0,
        captured_at=_NOW - timedelta(hours=25),
    )

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "stale_values" in kinds


async def test_stale_values_does_not_fire_when_a_newer_signal_exists(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="battery.soc",
        source_field="currentSOCInPct",
        value=10.0,
        captured_at=_NOW - timedelta(hours=25),
    )
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="vehicle.odometer",
        source_field="mileage",
        value=1000.0,
        captured_at=_NOW,
    )

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "stale_values" not in kinds


async def test_portal_unavailable_fires_on_three_consecutive_failures(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    for i, outcome in enumerate(("error", "login_failed", "error")):
        await _seed_run(
            db, account_id, request_id, started_at=_NOW - timedelta(minutes=i), outcome=outcome
        )

    view = await _service(db, settings).overview()

    notice = next(n for n in view.cards[0].notices if n.kind == "portal_unavailable")
    assert notice.severity == Severity.ERROR
    assert notice.params == {"count": 3}


async def test_portal_unavailable_does_not_fire_if_broken_by_an_ok_run(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    await _seed_run(db, account_id, request_id, started_at=_NOW, outcome="error")
    await _seed_run(
        db, account_id, request_id, started_at=_NOW - timedelta(minutes=1), outcome="ok"
    )
    await _seed_run(
        db, account_id, request_id, started_at=_NOW - timedelta(minutes=2), outcome="error"
    )

    view = await _service(db, settings).overview()

    kinds = {n.kind for n in view.cards[0].notices}
    assert "portal_unavailable" not in kinds


async def test_account_needs_attention_notice(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db, state="needs_attention", state_reason="login expired")
    vehicle_id = await _seed_vehicle(db, account_id)
    await _seed_request(db, vehicle_id)

    view = await _service(db, settings).overview()

    notice = next(n for n in view.cards[0].notices if n.kind == "account_needs_attention")
    assert notice.params["reason"] == "login expired"
    assert notice.severity == Severity.ERROR


async def test_request_needs_attention_notice(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    await _seed_request(db, vehicle_id, state="needs_attention", state_reason="invalid identifier")

    view = await _service(db, settings).overview()

    notice = next(n for n in view.cards[0].notices if n.kind == "request_needs_attention")
    assert notice.params["reason"] == "invalid identifier"


# --- archived vehicles ----------------------------------------------------------


async def test_archived_vehicle_has_no_card(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db)
    await _seed_vehicle(db, account_id, archived=True)

    view = await _service(db, settings).overview()

    assert view.cards == ()


# --- backup status --------------------------------------------------------------


async def test_backup_status_error_when_none_exists(db: Database, settings: Settings) -> None:
    backup = BackupService(Path("/nonexistent/db.sqlite3"), Path("/nonexistent/backups"), db)
    view = await _service(db, settings, backup=backup).overview()

    assert view.last_backup_age_s is None
    assert view.backup_warning is True


async def test_backup_status_warning_past_36_hours(db: Database, settings: Settings) -> None:
    async with db.write() as conn:
        await conn.execute(
            insert(backups).values(
                id=uuid4(),
                created_at=_NOW - timedelta(hours=40),
                path="/x",
                size_bytes=1,
                sha256="0" * 64,
                verified=True,
                error=None,
            )
        )
    backup = BackupService(Path("/nonexistent/db.sqlite3"), Path("/nonexistent/backups"), db)

    view = await _service(db, settings, backup=backup).overview()

    assert view.last_backup_age_s == timedelta(hours=40).total_seconds()
    assert view.backup_warning is True


async def test_backup_status_ok_when_fresh(db: Database, settings: Settings) -> None:
    async with db.write() as conn:
        await conn.execute(
            insert(backups).values(
                id=uuid4(),
                created_at=_NOW - timedelta(hours=1),
                path="/x",
                size_bytes=1,
                sha256="0" * 64,
                verified=True,
                error=None,
            )
        )
    backup = BackupService(Path("/nonexistent/db.sqlite3"), Path("/nonexistent/backups"), db)

    view = await _service(db, settings, backup=backup).overview()

    assert view.backup_warning is False


# --- vehicle detail --------------------------------------------------------------


async def test_vehicle_detail_unknown_id_returns_none(db: Database, settings: Settings) -> None:
    detail = await _service(db, settings).vehicle_detail(uuid4())
    assert detail is None


async def test_vehicle_detail_includes_source_fields_and_data_requests(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    await _seed_signal(
        db,
        vehicle_id,
        delivery_id,
        signal="vehicle.odometer",
        source_field="mileage",
        value=1234.0,
        captured_at=_NOW,
    )

    detail = await _service(db, settings).vehicle_detail(vehicle_id)

    assert detail is not None
    assert detail.signals["vehicle.odometer"][0].source_field == "mileage"
    assert detail.signals["vehicle.odometer"][0].value == 1234.0
    assert detail.signals["vehicle.odometer"][0].kind == SignalKind.NUMERIC
    assert len(detail.data_requests) == 1
    assert detail.data_requests[0].kind == "partial"


async def test_vehicle_detail_caps_collector_history_at_twenty_runs(
    db: Database, settings: Settings
) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    for i in range(25):
        await _seed_run(
            db, account_id, request_id, started_at=_NOW - timedelta(minutes=i), outcome="ok"
        )

    detail = await _service(db, settings).vehicle_detail(vehicle_id)

    assert detail is not None
    assert len(detail.collector_runs) == 20


async def test_vehicle_detail_paginates_signal_values(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)
    request_id = await _seed_request(db, vehicle_id)
    delivery_id = await _seed_delivery(db, request_id, remote_name="d1.zip", fetched_at=_NOW)
    for i in range(30):
        await _seed_signal(
            db,
            vehicle_id,
            delivery_id,
            signal="vehicle.odometer",
            source_field="mileage",
            value=float(i),
            captured_at=_NOW - timedelta(hours=i),
        )

    service = _service(db, settings)
    first_page = await service.vehicle_detail(vehicle_id, signals_page_size=25)
    second_page = await service.vehicle_detail(vehicle_id, signals_page=2, signals_page_size=25)

    assert first_page is not None
    assert second_page is not None
    assert first_page.signals_total == 30
    assert first_page.signals_page_size == 25
    assert first_page.signals_total_pages == 2
    assert sum(len(v) for v in first_page.signals.values()) == 25
    assert second_page.signals_page == 2
    assert sum(len(v) for v in second_page.signals.values()) == 5


async def test_vehicle_detail_rejects_unknown_page_size(db: Database, settings: Settings) -> None:
    account_id = await _seed_account(db)
    vehicle_id = await _seed_vehicle(db, account_id)

    detail = await _service(db, settings).vehicle_detail(vehicle_id, signals_page_size=9999)

    assert detail is not None
    assert detail.signals_page_size == 50
