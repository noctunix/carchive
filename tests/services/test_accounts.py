"""Tests for `carchive.services.accounts`."""

from __future__ import annotations

import logging
import stat
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, insert, select

from carchive.config import (
    ConfigError,
    Settings,
    load_secrets,
    remove_credentials,
    vault_key_path,
    write_credentials,
)
from carchive.core.models import RemoteVehicle
from carchive.core.provider import ProviderRegistry
from carchive.core.redact import redact
from carchive.services.accounts import (
    AccountNotFoundError,
    AccountService,
    InvalidLabelError,
    InvalidPasswordError,
    LabelConflictError,
    LoginRejectedError,
    NoStoredCredentialsError,
    UnknownProviderError,
    UnsupportedBrandError,
    VehicleNotFoundError,
)
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import (
    AccountRepository,
    CollectorRunRepository,
    VehicleRepository,
)
from carchive.storage.schema import (
    collector_runs,
    data_points,
    data_requests,
    deliveries,
    import_batches,
    signal_values,
    vehicles,
)
from tests.services.fakes import FakeProvider

_NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)


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
    return Settings(data_dir=tmp_path / "data", secrets_file=tmp_path / "secrets.toml")


@pytest.fixture
def registry() -> ProviderRegistry:
    reg = ProviderRegistry()
    reg.register(FakeProvider())
    return reg


def _clock() -> datetime:
    return _NOW


@pytest.fixture
def service(db: Database, registry: ProviderRegistry, settings: Settings) -> AccountService:
    return AccountService(db, registry, settings, clock=_clock)


# --- add_account --------------------------------------------------------------


async def test_add_account_creates_account_and_owner_only_secrets(
    service: AccountService, settings: Settings, db: Database
) -> None:
    account_id = await service.add_account(
        "fake", "fake", "myacct", {"user": "user", "password": "s3cret-password"}
    )

    async with db.read() as conn:
        account = await AccountRepository().get(conn, account_id)
    assert account is not None
    assert account.label == "myacct"
    assert account.credential_ref == "myacct"
    assert account.state == "active"

    secrets = load_secrets(settings.secrets_file)
    assert secrets["myacct"] == {"user": "user", "password": "s3cret-password"}
    assert stat.S_IMODE(settings.secrets_file.stat().st_mode) == 0o600


@pytest.mark.parametrize("label", ["", "a" * 41, "has space", "slash/no"])
async def test_add_account_rejects_invalid_label(service: AccountService, label: str) -> None:
    with pytest.raises(InvalidLabelError):
        await service.add_account("fake", "fake", label, {"user": "u", "password": "pw12345"})


async def test_add_account_rejects_unknown_provider(service: AccountService) -> None:
    with pytest.raises(UnknownProviderError):
        await service.add_account("nope", "fake", "acct", {"user": "u", "password": "pw12345"})


async def test_add_account_rejects_unsupported_brand(service: AccountService) -> None:
    with pytest.raises(UnsupportedBrandError):
        await service.add_account(
            "fake", "not-a-brand", "acct", {"user": "u", "password": "pw12345"}
        )


async def test_add_account_rejects_duplicate_label_and_creates_nothing(
    service: AccountService, settings: Settings, db: Database
) -> None:
    await service.add_account("fake", "fake", "acct", {"user": "u", "password": "pw12345"})

    with pytest.raises(LabelConflictError):
        await service.add_account("fake", "fake", "acct", {"user": "u2", "password": "pw67890"})

    async with db.read() as conn:
        accounts = await AccountRepository().list_all(conn)
    assert len(accounts) == 1
    secrets = load_secrets(settings.secrets_file)
    assert secrets["acct"] == {"user": "u", "password": "pw12345"}


async def test_add_account_rejects_conflicting_credential_reference(
    service: AccountService, settings: Settings
) -> None:
    settings.secrets_file.parent.mkdir(parents=True, exist_ok=True)
    settings.secrets_file.write_text('[credentials.acct]\nuser = "other"\npassword = "other-pw"\n')
    settings.secrets_file.chmod(0o600)

    with pytest.raises(LabelConflictError):
        await service.add_account("fake", "fake", "acct", {"user": "u", "password": "pw12345"})


# --- login testing -------------------------------------------------------------


async def test_test_login_ok(service: AccountService) -> None:
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )

    result = await service.test_login(account_id)

    assert result.ok is True
    assert result.reason is None


async def test_test_login_failure_reason_never_contains_the_password(
    service: AccountService, registry: ProviderRegistry, settings: Settings
) -> None:
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    fake_provider = registry.get("fake")
    assert isinstance(fake_provider, FakeProvider)
    # Overwrite the account's secrets on disk so the stored password no longer matches.
    write_credentials(
        settings.secrets_file,
        "acct",
        {"user": "user", "password": "wrong-password"},
        overwrite=True,
    )

    result = await service.test_login(account_id)

    assert result.ok is False
    assert result.reason is not None
    assert "wrong-password" not in result.reason


async def test_test_login_unknown_account_raises(service: AccountService) -> None:
    with pytest.raises(AccountNotFoundError):
        await service.test_login(uuid4())


async def test_check_login_registers_the_password_before_calling_the_provider(
    service: AccountService,
) -> None:
    """Even an unexpected error from the provider must never leak the raw password.

    `redact` only scrubs values it already knows about, so registration has to happen
    before the first provider call, not after a successful `add_account`.
    """
    await service.check_login("fake", "fake", {"user": "user", "password": "never-seen-again"})

    assert redact("the password is never-seen-again") == "the password is ***"


# --- vehicles --------------------------------------------------------------


async def test_remote_vehicles_returns_the_providers_list(
    service: AccountService, registry: ProviderRegistry
) -> None:
    fake_provider = registry.get("fake")
    assert isinstance(fake_provider, FakeProvider)
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )

    result = await service.remote_vehicles(account_id)

    assert [v.vin for v in result] == ["WAUZZZ4V0JA123456"]


async def test_add_vehicles_only_adds_vins_the_account_actually_reports(
    service: AccountService, registry: ProviderRegistry, db: Database
) -> None:
    fake_provider = registry.get("fake")
    assert isinstance(fake_provider, FakeProvider)
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )

    added = await service.add_vehicles(account_id, ["WAUZZZ4V0JA123456", "NOT-REPORTED-00000"])

    assert len(added) == 1
    async with db.read() as conn:
        stored = await VehicleRepository().list_for_account(conn, account_id)
    assert [v.vin for v in stored] == ["WAUZZZ4V0JA123456"]


async def test_add_vehicles_skips_already_added_vins(
    service: AccountService, registry: ProviderRegistry, db: Database
) -> None:
    fake_provider = registry.get("fake")
    assert isinstance(fake_provider, FakeProvider)
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    await service.add_vehicles(account_id, ["WAUZZZ4V0JA123456"])

    added_again = await service.add_vehicles(account_id, ["WAUZZZ4V0JA123456"])

    assert added_again == []
    async with db.read() as conn:
        stored = await VehicleRepository().list_for_account(conn, account_id)
    assert len(stored) == 1


# --- listing -----------------------------------------------------------------


async def test_list_accounts_reports_state_and_last_run(
    service: AccountService, db: Database
) -> None:
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    async with db.write() as conn:
        await CollectorRunRepository().add(
            conn,
            account_id=account_id,
            data_request_id=None,
            started_at=_NOW,
            finished_at=_NOW,
            outcome="ok",
            listed=None,
            placeholders=None,
            downloaded=None,
            with_content=None,
            pending=None,
            oldest_pending_age_s=None,
            message=None,
        )

    infos = await service.list_accounts()

    assert len(infos) == 1
    assert infos[0].label == "acct"
    assert infos[0].last_run_outcome == "ok"


async def test_list_vehicles_reports_account_label(
    service: AccountService, registry: ProviderRegistry
) -> None:
    fake_provider = registry.get("fake")
    assert isinstance(fake_provider, FakeProvider)
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    await service.add_vehicles(account_id, ["WAUZZZ4V0JA123456"])

    infos = await service.list_vehicles()

    assert len(infos) == 1
    assert infos[0].account_label == "acct"
    assert infos[0].archived is False


async def test_get_account_by_label(service: AccountService) -> None:
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )

    found = await service.get_account_by_label("acct")
    missing = await service.get_account_by_label("does-not-exist")

    assert found is not None
    assert found.id == account_id
    assert missing is None


async def test_get_vehicle_by_id(service: AccountService, registry: ProviderRegistry) -> None:
    fake_provider = registry.get("fake")
    assert isinstance(fake_provider, FakeProvider)
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    (vehicle_id,) = await service.add_vehicles(account_id, ["WAUZZZ4V0JA123456"])

    found = await service.get_vehicle(vehicle_id)
    missing = await service.get_vehicle(uuid4())

    assert found is not None
    assert found.vin == "WAUZZZ4V0JA123456"
    assert missing is None


# --- deletion ----------------------------------------------------------------


async def _seed_full_vehicle_data(db: Database, vehicle_id: UUID, account_id: UUID) -> None:
    """Insert one row into every table that can reference `vehicle_id`."""
    async with db.write() as conn:
        request_id = uuid4()
        await conn.execute(
            insert(data_requests).values(
                id=request_id,
                vehicle_id=vehicle_id,
                kind="partial",
                remote_id="remote-1",
                interval_s=900,
                next_due_at=None,
                state="active",
                state_reason=None,
                last_success_at=None,
            )
        )
        batch_id = uuid4()
        await conn.execute(
            insert(import_batches).values(
                id=batch_id,
                vehicle_id=vehicle_id,
                kind="historical",
                source_name="export.json",
                sha256="0" * 64,
                size_bytes=1,
                state="done",
                progress=1.0,
                started_at=_NOW,
                finished_at=_NOW,
                error=None,
            )
        )
        delivery_id = uuid4()
        await conn.execute(
            insert(deliveries).values(
                id=delivery_id,
                data_request_id=request_id,
                import_batch_id=None,
                remote_name="20261023120000_VIN_no_content_found.zip",
                delivered_at=_NOW,
                fetched_at=_NOW,
                has_content=True,
                sha256="1" * 64,
                size_bytes=10,
                parse_state="parsed",
                parser_version="v1",
                raw_payload=b"x",
            )
        )
        batch_delivery_id = uuid4()
        await conn.execute(
            insert(deliveries).values(
                id=batch_delivery_id,
                data_request_id=None,
                import_batch_id=batch_id,
                remote_name="export.json",
                delivered_at=None,
                fetched_at=_NOW,
                has_content=True,
                sha256="2" * 64,
                size_bytes=10,
                parse_state="parsed",
                parser_version="v1",
                raw_payload=b"y",
            )
        )
        point_id = uuid4()
        await conn.execute(
            insert(data_points).values(
                id=point_id,
                vehicle_id=vehicle_id,
                key="k",
                field_name="f",
                value_raw="1",
                value_type="num",
                value_num=1.0,
                value_text=None,
                value_bool=None,
                value_time=None,
                captured_at=_NOW,
                captured_at_quality="exact",
                first_delivery_id=delivery_id,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
                seen_count=1,
                dedup_key="dedup-1",
            )
        )
        await conn.execute(
            insert(signal_values).values(
                id=uuid4(),
                vehicle_id=vehicle_id,
                signal="battery.soc",
                value_num=80.0,
                value_text=None,
                value_bool=None,
                unit="%",
                captured_at=_NOW,
                captured_at_quality="exact",
                source_data_point_id=point_id,
                mapping_version="v1",
            )
        )
        await conn.execute(
            insert(collector_runs).values(
                id=uuid4(),
                account_id=account_id,
                data_request_id=request_id,
                started_at=_NOW,
                finished_at=_NOW,
                outcome="ok",
                listed=1,
                placeholders=0,
                downloaded=1,
                with_content=1,
                pending=0,
                oldest_pending_age_s=None,
                message=None,
            )
        )


async def _row_counts_for_vehicle(db: Database, vehicle_id: UUID) -> dict[str, int]:
    async with db.read() as conn:
        counts = {}
        counts["data_points"] = (
            await conn.execute(select(func.count()).where(data_points.c.vehicle_id == vehicle_id))
        ).scalar_one()
        counts["signal_values"] = (
            await conn.execute(select(func.count()).where(signal_values.c.vehicle_id == vehicle_id))
        ).scalar_one()
        counts["data_requests"] = (
            await conn.execute(select(func.count()).where(data_requests.c.vehicle_id == vehicle_id))
        ).scalar_one()
        counts["import_batches"] = (
            await conn.execute(
                select(func.count()).where(import_batches.c.vehicle_id == vehicle_id)
            )
        ).scalar_one()
        request_ids = select(data_requests.c.id).where(data_requests.c.vehicle_id == vehicle_id)
        batch_ids = select(import_batches.c.id).where(import_batches.c.vehicle_id == vehicle_id)
        counts["deliveries"] = (
            await conn.execute(
                select(func.count()).where(
                    (deliveries.c.data_request_id.in_(request_ids))
                    | (deliveries.c.import_batch_id.in_(batch_ids))
                )
            )
        ).scalar_one()
        counts["collector_runs"] = (
            await conn.execute(
                select(func.count()).where(collector_runs.c.data_request_id.in_(request_ids))
            )
        ).scalar_one()
        counts["vehicles"] = (
            await conn.execute(select(func.count()).where(vehicles.c.id == vehicle_id))
        ).scalar_one()
    return counts


async def test_delete_vehicle_removes_every_row_without_touching_other_vehicles(
    service: AccountService, db: Database
) -> None:
    account_id = uuid4()
    async with db.write() as conn:
        await AccountRepository().add(
            conn,
            id=account_id,
            provider_id="fake",
            brand="fake",
            label="acct",
            credential_ref="acct",
            state="active",
            state_reason=None,
            created_at=_NOW,
        )
    vehicle_id = uuid4()
    other_vehicle_id = uuid4()
    async with db.write() as conn:
        for vid, vin in (
            (vehicle_id, "WAUZZZ4V0JA123456"),
            (other_vehicle_id, "WAUZZZ4V0JA654321"),
        ):
            await VehicleRepository().add(
                conn,
                id=vid,
                account_id=account_id,
                vin=vin,
                label=vin,
                brand="fake",
                model=None,
                created_at=_NOW,
            )
    await _seed_full_vehicle_data(db, vehicle_id, account_id)
    await _seed_full_vehicle_data(db, other_vehicle_id, account_id)

    result = await service.delete_vehicle(vehicle_id)

    assert result.oldest_backup_age is None
    deleted_counts = await _row_counts_for_vehicle(db, vehicle_id)
    assert all(count == 0 for count in deleted_counts.values())
    kept_counts = await _row_counts_for_vehicle(db, other_vehicle_id)
    assert kept_counts["vehicles"] == 1
    assert kept_counts["data_points"] == 1
    assert kept_counts["signal_values"] == 1
    assert kept_counts["deliveries"] == 2
    assert kept_counts["collector_runs"] == 1


async def test_delete_vehicle_unknown_id_raises(service: AccountService) -> None:
    with pytest.raises(VehicleNotFoundError):
        await service.delete_vehicle(uuid4())


async def test_delete_account_removes_vehicles_data_and_credentials(
    service: AccountService, settings: Settings, db: Database
) -> None:
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    vehicle_id = uuid4()
    async with db.write() as conn:
        await VehicleRepository().add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin="WAUZZZ4V0JA123456",
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
    await _seed_full_vehicle_data(db, vehicle_id, account_id)
    async with db.write() as conn:
        await CollectorRunRepository().add(
            conn,
            account_id=account_id,
            data_request_id=None,
            started_at=_NOW,
            finished_at=_NOW,
            outcome="login_failed",
            listed=None,
            placeholders=None,
            downloaded=None,
            with_content=None,
            pending=None,
            oldest_pending_age_s=None,
            message=None,
        )

    await service.delete_account("acct")

    async with db.read() as conn:
        assert await AccountRepository().get(conn, account_id) is None
        assert await VehicleRepository().get(conn, vehicle_id) is None
        remaining_runs = (
            await conn.execute(
                select(func.count()).where(collector_runs.c.account_id == account_id)
            )
        ).scalar_one()
    assert remaining_runs == 0
    assert load_secrets(settings.secrets_file) == {}


async def test_delete_account_unknown_label_raises(service: AccountService) -> None:
    with pytest.raises(AccountNotFoundError):
        await service.delete_account("does-not-exist")


async def test_delete_vehicle_reports_oldest_backup_age(
    db: Database, registry: ProviderRegistry, settings: Settings, tmp_path: Path
) -> None:
    from carchive.services.backup import BackupService

    backup = BackupService(tmp_path / "data" / "carchive.sqlite3", tmp_path / "backups", None)
    service = AccountService(db, registry, settings, backup=backup, clock=_clock)
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    vehicle_id = uuid4()
    async with db.write() as conn:
        await VehicleRepository().add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin="WAUZZZ4V0JA123456",
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
    backup_time = _NOW - timedelta(days=3)
    backup_path = tmp_path / "backups"
    backup_path.mkdir(parents=True)
    archive = backup_path / f"carchive-{backup_time.strftime('%Y%m%dT%H%M%SZ')}.sqlite3.gz"
    archive.write_bytes(b"not a real backup, only the name is read here")

    result = await service.delete_vehicle(vehicle_id)

    assert result.oldest_backup_age == timedelta(days=3)


# --- fetch helpers -----------------------------------------------------------


async def test_due_account_ids_only_lists_accounts_with_due_work(
    service: AccountService, db: Database
) -> None:
    due_account_id = await service.add_account(
        "fake", "fake", "due", {"user": "user", "password": "s3cret-password"}
    )
    await service.add_account("fake", "fake", "idle", {"user": "u2", "password": "pw234567"})
    async with db.write() as conn:
        await VehicleRepository().add(
            conn,
            id=uuid4(),
            account_id=due_account_id,
            vin="WAUZZZ4V0JA123456",
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )

    due = await service.due_account_ids()

    assert due == [due_account_id]


async def test_describe_request_resolves_account_label_vin_and_kind(
    service: AccountService, db: Database
) -> None:
    account_id = await service.add_account(
        "fake", "fake", "acct", {"user": "user", "password": "s3cret-password"}
    )
    vehicle_id = uuid4()
    request_id = uuid4()
    async with db.write() as conn:
        await VehicleRepository().add(
            conn,
            id=vehicle_id,
            account_id=account_id,
            vin="WAUZZZ4V0JA123456",
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
        await conn.execute(
            insert(data_requests).values(
                id=request_id,
                vehicle_id=vehicle_id,
                kind="partial",
                remote_id="remote-1",
                interval_s=900,
                next_due_at=None,
                state="active",
                state_reason=None,
                last_success_at=None,
            )
        )

    description = await service.describe_request(request_id)

    assert description is not None
    assert description.account_label == "acct"
    assert description.vin == "WAUZZZ4V0JA123456"
    assert description.kind == "partial"


async def test_describe_request_unknown_id_returns_none(service: AccountService) -> None:
    assert await service.describe_request(uuid4()) is None


# --- set_password ---------------------------------------------------------------

_OLD_PASSWORD = "old-portal-passphrase"
_NEW_PASSWORD = "new-portal-passphrase"


def _service_accepting(
    db: Database, settings: Settings, password: str, user: str = "user"
) -> AccountService:
    registry = ProviderRegistry()
    registry.register(FakeProvider(user=user, password=password))
    return AccountService(db, registry, settings, clock=_clock)


async def _account_with_vehicle(
    db: Database, settings: Settings, label: str = "myacct"
) -> AccountService:
    service = _service_accepting(db, settings, _NEW_PASSWORD)
    await service.add_account("fake", "fake", label, {"user": "user", "password": _OLD_PASSWORD})
    account = await service.get_account_by_label(label)
    assert account is not None
    async with db.write() as conn:
        await VehicleRepository().add(
            conn,
            id=uuid4(),
            account_id=account.id,
            vin="WAUZZZ4V0JA123456",
            label="car",
            brand="fake",
            model=None,
            created_at=_NOW,
        )
    return service


async def test_set_password_replaces_only_the_password_and_keeps_data(
    db: Database, settings: Settings
) -> None:
    service = await _account_with_vehicle(db, settings)
    before = await service.get_account_by_label("myacct")

    await service.set_password("myacct", _NEW_PASSWORD)

    assert load_secrets(settings.secrets_file) == {
        "myacct": {"user": "user", "password": _NEW_PASSWORD}
    }
    assert _NEW_PASSWORD not in settings.secrets_file.read_text()
    assert stat.S_IMODE(settings.secrets_file.stat().st_mode) == 0o600
    assert await service.get_account_by_label("myacct") == before
    assert len(await service.list_vehicles()) == 1


async def test_set_password_unknown_account(db: Database, settings: Settings) -> None:
    service = _service_accepting(db, settings, _NEW_PASSWORD)

    with pytest.raises(AccountNotFoundError):
        await service.set_password("nope", _NEW_PASSWORD)

    assert not settings.secrets_file.exists()


@pytest.mark.parametrize("password", ["", "x" * 1025])
async def test_set_password_rejects_empty_and_oversized_input(
    db: Database, settings: Settings, password: str
) -> None:
    service = await _account_with_vehicle(db, settings)

    with pytest.raises(InvalidPasswordError):
        await service.set_password("myacct", password)

    assert load_secrets(settings.secrets_file)["myacct"]["password"] == _OLD_PASSWORD


async def test_set_password_not_accepted_by_portal_stores_nothing(
    db: Database, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    await _account_with_vehicle(db, settings)
    service = _service_accepting(db, settings, "something-else-entirely")
    content_before = settings.secrets_file.read_bytes()

    with pytest.raises(LoginRejectedError) as exc_info:
        await service.set_password("myacct", _NEW_PASSWORD)

    assert settings.secrets_file.read_bytes() == content_before
    assert _NEW_PASSWORD not in str(exc_info.value) + caplog.text


async def test_set_password_without_stored_credentials(db: Database, settings: Settings) -> None:
    service = await _account_with_vehicle(db, settings)
    assert remove_credentials(settings.secrets_file, "myacct") is True

    with pytest.raises(NoStoredCredentialsError):
        await service.set_password("myacct", _NEW_PASSWORD)


async def test_set_password_works_after_the_vault_key_was_lost(
    db: Database, settings: Settings
) -> None:
    service = await _account_with_vehicle(db, settings)
    vault_key_path(settings.secrets_file).unlink()
    with pytest.raises(ConfigError):
        load_secrets(settings.secrets_file)

    await service.set_password("myacct", _NEW_PASSWORD)

    assert vault_key_path(settings.secrets_file).stat().st_size == 32
    assert stat.S_IMODE(vault_key_path(settings.secrets_file).stat().st_mode) == 0o600
    assert load_secrets(settings.secrets_file) == {
        "myacct": {"user": "user", "password": _NEW_PASSWORD}
    }


async def test_set_password_with_lost_key_fails_while_other_passwords_stay_unreadable(
    db: Database, settings: Settings
) -> None:
    service = await _account_with_vehicle(db, settings, "first")
    await service.add_account("fake", "fake", "second", {"user": "user", "password": _OLD_PASSWORD})
    key_file = vault_key_path(settings.secrets_file)
    key_file.unlink()
    content_before = settings.secrets_file.read_bytes()

    with pytest.raises(ConfigError, match="1 other reference"):
        await service.set_password("first", _NEW_PASSWORD)

    assert not key_file.exists()
    assert settings.secrets_file.read_bytes() == content_before


async def test_unreadable_password_labels_after_key_loss_and_recovery_in_one_write(
    db: Database, settings: Settings
) -> None:
    service = await _account_with_vehicle(db, settings, "first")
    await service.add_account("fake", "fake", "second", {"user": "user", "password": _OLD_PASSWORD})
    assert await service.unreadable_password_labels() == []
    vault_key_path(settings.secrets_file).unlink()

    assert await service.unreadable_password_labels() == ["first", "second"]
    await service.check_new_password("first", _NEW_PASSWORD)
    await service.check_new_password("second", _NEW_PASSWORD)
    await service.set_passwords({"first": _NEW_PASSWORD, "second": _NEW_PASSWORD})

    assert await service.unreadable_password_labels() == []
    assert {ref: f["password"] for ref, f in load_secrets(settings.secrets_file).items()} == {
        "first": _NEW_PASSWORD,
        "second": _NEW_PASSWORD,
    }


async def test_set_passwords_with_a_partial_set_after_key_loss_changes_nothing(
    db: Database, settings: Settings
) -> None:
    service = await _account_with_vehicle(db, settings, "first")
    await service.add_account("fake", "fake", "second", {"user": "user", "password": _OLD_PASSWORD})
    vault_key_path(settings.secrets_file).unlink()
    content_before = settings.secrets_file.read_bytes()

    with pytest.raises(ConfigError, match="second"):
        await service.set_passwords({"first": _NEW_PASSWORD})
    with pytest.raises(AccountNotFoundError):
        await service.set_passwords({"nope": _NEW_PASSWORD})
    with pytest.raises(InvalidPasswordError):
        await service.set_passwords({"first": ""})

    assert settings.secrets_file.read_bytes() == content_before
    assert not vault_key_path(settings.secrets_file).exists()


async def test_check_password_replaceable_names_the_other_unreadable_accounts(
    db: Database, settings: Settings
) -> None:
    service = await _account_with_vehicle(db, settings, "first")
    await service.add_account("fake", "fake", "second", {"user": "user", "password": _OLD_PASSWORD})
    await service.check_password_replaceable("first")
    vault_key_path(settings.secrets_file).unlink()

    with pytest.raises(ConfigError, match=r"\(second\)"):
        await service.check_password_replaceable("first")
    with pytest.raises(AccountNotFoundError):
        await service.check_password_replaceable("nope")


async def test_unreadable_password_without_an_account_is_reported(
    db: Database, settings: Settings
) -> None:
    service = await _account_with_vehicle(db, settings, "first")
    write_credentials(settings.secrets_file, "stale", {"password": _OLD_PASSWORD}, overwrite=False)
    vault_key_path(settings.secrets_file).unlink()

    with pytest.raises(ConfigError, match="belong to no account: stale"):
        await service.unreadable_password_labels()


async def test_set_password_never_reaches_logs_or_files_in_plaintext(
    db: Database, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    service = await _account_with_vehicle(db, settings)

    await service.set_password("myacct", _NEW_PASSWORD)

    assert _NEW_PASSWORD not in caplog.text
    assert redact(f"login {_NEW_PASSWORD}") == "login ***"
    assert all(
        _NEW_PASSWORD.encode() not in path.read_bytes()
        for path in settings.secrets_file.parent.iterdir()
        if path.is_file() and path.suffix != ".sqlite3"
    )
