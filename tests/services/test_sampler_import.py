"""Tests for `carchive.services.sampler_import`."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import delete, select, update

import eu_data_act_sampler as sampler
from carchive.config import InsecureSecretsError, Settings, load_secrets
from carchive.core.provider import ProviderRegistry
from carchive.providers.vwgroup.provider import VwGroupProvider
from carchive.services import sampler_import as sampler_import_module
from carchive.services.reparse import Reparser
from carchive.services.sampler_import import (
    KindVerification,
    SamplerImporter,
    VerifyReport,
    _stored_json_sha256,
    _wrap_json_as_zip,
)
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import (
    AccountRepository,
    DataRequestRepository,
    DeliveryRepository,
    SignalValueRepository,
    VehicleRepository,
)
from carchive.storage.schema import collector_runs, deliveries

_NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
_VIN1 = "WAUZZZ4V0JA123456"
_VIN2 = "TMBZZZ0000N000002"
_VIN3 = "TMBZZZ0000N000003"
_DEFAULT_PASSWORD = "s3cr%etpass"
_ACCT2_PASSWORD = "otherpass123"


def _write_config(path: Path) -> None:
    path.write_text(
        "[portal]\n"
        "brand = Audi\n"
        "user = owner@example.com\n"
        f"password = {_DEFAULT_PASSWORD}\n"
        f"vin = {_VIN1}\n"
        "\n"
        "[account:acct2]\n"
        "brand = Skoda\n"
        "user = other@example.com\n"
        f"password = {_ACCT2_PASSWORD}\n"
        f"vins = {_VIN2}, {_VIN3}\n"
        "\n"
        "[account:bad]\n"
        "brand = Tesla\n"
        "user = x@example.com\n"
        "password = whatever123\n"
    )


def _dataset_name(ts: str, vin: str, suffix: str) -> str:
    return f"{ts}_{vin}_{suffix}"


def _capture_json(vin: str) -> str:
    return json.dumps(
        {
            "vin": vin,
            "Data": [
                {
                    "key": "k1",
                    "dataFieldName": "mileage",
                    "timestampUtc": "2026-10-01T00:00:00Z",
                    "value": "12345",
                }
            ],
        }
    )


def _seed_sampler_dbs(sampler_data_dir: Path) -> None:
    """Populate both accounts' sampler databases using the sampler's own write helpers."""
    default_conn = sampler._open_database(sampler_data_dir / "captures.sqlite3")
    try:
        sampler._store_capture(
            default_conn,
            sampler.DatasetInfo(
                name=_dataset_name("20261001120000", _VIN1, "data.zip"), created_on=None
            ),
            "all",
            _capture_json(_VIN1),
        )
        sampler._store_placeholder(
            default_conn,
            sampler.DatasetInfo(
                name=_dataset_name("20261002120000", _VIN1, "no_content_found.zip"), created_on=None
            ),
            "all",
            b"placeholder-bytes",
        )
        sampler._record_run(
            default_conn,
            _NOW,
            _VIN1,
            "all",
            "ok",
            sampler.FetchStats(listed=2, placeholders=1, downloaded=2, with_content=1, pending=0),
        )
        sampler._record_run(
            default_conn,
            _NOW,
            "*",
            "*",
            "login_failed",
            message=f"login failed: bad credentials for {_DEFAULT_PASSWORD}",
        )
    finally:
        default_conn.close()

    acct2_dir = sampler_data_dir / "acct2"
    acct2_conn = sampler._open_database(acct2_dir / "captures.sqlite3")
    try:
        sampler._store_capture(
            acct2_conn,
            sampler.DatasetInfo(
                name=_dataset_name("20261001120000", _VIN2, "data.zip"), created_on=None
            ),
            "partial",
            _capture_json(_VIN2),
        )
        sampler._store_capture(
            acct2_conn,
            sampler.DatasetInfo(
                name=_dataset_name("20261001130000", _VIN3, "data.zip"), created_on=None
            ),
            "partial",
            _capture_json(_VIN3),
        )
        sampler._record_run(
            acct2_conn,
            _NOW,
            _VIN2,
            "all",
            "unavailable",
            message="no 'all' data request configured",
        )
    finally:
        acct2_conn.close()


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
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "sampler-config.ini"
    _write_config(path)
    return path


@pytest.fixture
def sampler_data_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "sampler-data"
    _seed_sampler_dbs(data_dir)
    return data_dir


def _stat_fingerprint(path: Path) -> tuple[int, float]:
    result = path.stat()
    return result.st_size, result.st_mtime


async def test_plan_writes_nothing(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)

    plan = await importer.plan(config_path, sampler_data_dir)

    async with db.read() as conn:
        assert await AccountRepository().list_all(conn) == []
    assert not settings.secrets_file.exists()

    by_name = {account.name: account for account in plan.accounts}
    assert by_name["default"].vehicles_new == 1
    assert by_name["default"].deliveries_with_content_new == 1
    assert by_name["default"].deliveries_placeholder_new == 1
    assert by_name["default"].runs_new == 2
    assert by_name["acct2"].vehicles_new == 2
    assert by_name["acct2"].deliveries_with_content_new == 2
    assert by_name["acct2"].runs_new == 1
    assert any("unknown brand" in problem for problem in plan.problems)
    assert "bad" not in by_name


async def test_apply_imports_accounts_vehicles_deliveries_and_runs(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)

    report = await importer.apply(plan)

    by_name = {account.name: account for account in report.accounts}
    assert by_name["default"].account_new is True
    assert by_name["default"].credential_state == "new"
    assert by_name["default"].vehicles_new == 1
    assert by_name["default"].deliveries_with_content_new == 1
    assert by_name["default"].deliveries_placeholder_new == 1
    assert by_name["default"].runs_new == 2
    assert by_name["acct2"].vehicles_new == 2
    assert by_name["acct2"].deliveries_with_content_new == 2

    async with db.read() as conn:
        accounts = {a.label: a for a in await AccountRepository().list_all(conn)}
        assert set(accounts) == {"default", "acct2"}
        assert accounts["default"].brand == "audi"
        assert accounts["default"].credential_ref == "default"

        default_vehicles = await VehicleRepository().list_for_account(conn, accounts["default"].id)
        assert len(default_vehicles) == 1
        assert default_vehicles[0].vin == _VIN1

        acct2_vehicles = await VehicleRepository().list_for_account(conn, accounts["acct2"].id)
        assert {v.vin for v in acct2_vehicles} == {_VIN2, _VIN3}

        requests = await DataRequestRepository().list_for_vehicle(conn, default_vehicles[0].id)
        assert len(requests) == 1
        assert requests[0].kind == "all"
        assert requests[0].remote_id is None
        assert requests[0].next_due_at is None  # immediately due

        pending = await DeliveryRepository().list_pending(conn)
        assert len(pending) == 3  # one per vehicle with content; placeholders are "empty"

    secrets = load_secrets(settings.secrets_file)
    assert secrets["default"] == {"user": "owner@example.com", "password": _DEFAULT_PASSWORD}
    assert secrets["acct2"] == {"user": "other@example.com", "password": _ACCT2_PASSWORD}
    assert stat.S_IMODE(settings.secrets_file.stat().st_mode) == 0o600


async def test_placeholder_delivery_has_no_payload_and_is_marked_empty(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)
    await importer.apply(plan)

    async with db.read() as conn:
        rows = (
            await conn.execute(select(deliveries).where(deliveries.c.has_content.is_(False)))
        ).all()
        assert len(rows) == 1
        assert rows[0].raw_payload is None
        assert rows[0].parse_state == "empty"


async def test_runs_are_imported_including_account_level_login_failure(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)
    await importer.apply(plan)

    async with db.read() as conn:
        accounts = {a.label: a.id for a in await AccountRepository().list_all(conn)}
        rows = (
            await conn.execute(
                select(collector_runs).where(collector_runs.c.account_id == accounts["default"])
            )
        ).all()
        outcomes = {row.outcome for row in rows}
        assert outcomes == {"ok", "login_failed"}
        login_failed = next(row for row in rows if row.outcome == "login_failed")
        assert login_failed.data_request_id is None
        assert login_failed.message is not None
        assert _DEFAULT_PASSWORD not in login_failed.message
        assert "***" in login_failed.message


async def test_apply_is_idempotent(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)
    await importer.apply(plan)

    second_plan = await importer.plan(config_path, sampler_data_dir)
    second_report = await importer.apply(second_plan)

    for account in second_report.accounts:
        assert account.account_new is False
        assert account.credential_state == "same"
        assert account.vehicles_new == 0
        assert account.deliveries_with_content_new == 0
        assert account.deliveries_placeholder_new == 0
        assert account.runs_new == 0

    async with db.read() as conn:
        default_account = await AccountRepository().get_by_label(conn, "default")
        assert default_account is not None
        vehicles = await VehicleRepository().list_for_account(conn, default_account.id)
        assert len(vehicles) == 1  # no duplicate vehicle rows


async def test_parse_pending_turns_imported_deliveries_into_signal_values(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)
    await importer.apply(plan)

    registry = ProviderRegistry()
    registry.register(VwGroupProvider())
    reparser = Reparser(db, registry)

    result = await reparser.parse_pending()

    assert result.parsed == 3  # one per vehicle with content: vin1, vin2, vin3
    assert result.failed == 0

    async with db.read() as conn:
        accounts = {a.label: a.id for a in await AccountRepository().list_all(conn)}
        default_vehicle = (await VehicleRepository().list_for_account(conn, accounts["default"]))[0]
        values = await SignalValueRepository().latest_for_vehicle(conn, default_vehicle.id)
        assert "vehicle.odometer" in values


async def test_conflicting_password_is_reported_and_not_overwritten(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    settings.secrets_file.parent.mkdir(parents=True, exist_ok=True)
    settings.secrets_file.write_text(
        '[credentials.default]\nuser = "owner@example.com"\npassword = "a-different-password"\n'
    )
    settings.secrets_file.chmod(0o600)

    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)
    report = await importer.apply(plan)

    by_name = {account.name: account for account in report.accounts}
    assert by_name["default"].credential_state == "conflict"
    assert any("credentials" in problem for problem in report.problems)
    secrets = load_secrets(settings.secrets_file)
    assert secrets["default"] == {"user": "owner@example.com", "password": "a-different-password"}


async def test_insecure_secrets_file_aborts(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    settings.secrets_file.parent.mkdir(parents=True, exist_ok=True)
    settings.secrets_file.write_text('[credentials.default]\nuser = "x"\npassword = "y"\n')
    settings.secrets_file.chmod(0o644)

    importer = SamplerImporter(db, settings, clock=lambda: _NOW)

    with pytest.raises(InsecureSecretsError):
        await importer.plan(config_path, sampler_data_dir)


async def test_broken_section_is_reported_rest_still_imported(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)

    plan = await importer.plan(config_path, sampler_data_dir)

    names = {account.name for account in plan.accounts}
    assert names == {"default", "acct2"}
    assert any("bad" in problem and "unknown brand" in problem for problem in plan.problems)


async def test_sampler_database_is_never_modified(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> None:
    capture_db = sampler_data_dir / "captures.sqlite3"
    before = _stat_fingerprint(capture_db)
    before_bytes = capture_db.read_bytes()

    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)
    await importer.apply(plan)

    after_bytes = capture_db.read_bytes()
    assert before_bytes == after_bytes
    assert _stat_fingerprint(capture_db) == before


async def test_plan_and_report_never_leak_password_or_full_vin(
    db: Database,
    settings: Settings,
    config_path: Path,
    sampler_data_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    plan = await importer.plan(config_path, sampler_data_dir)
    report = await importer.apply(plan)

    for blob in (str(plan), str(report)):
        assert _DEFAULT_PASSWORD not in blob
        assert _ACCT2_PASSWORD not in blob
        assert _VIN1 not in blob
        assert _VIN2 not in blob
        assert _VIN3 not in blob

    log_text = caplog.text
    assert _DEFAULT_PASSWORD not in log_text
    assert _ACCT2_PASSWORD not in log_text
    assert _VIN1 not in log_text
    assert _VIN2 not in log_text
    assert _VIN3 not in log_text


# --- verify ---------------------------------------------------------------------


@pytest.fixture
def clean_config_path(tmp_path: Path) -> Path:
    """The two-account config without the unimportable `bad` section."""
    path = tmp_path / "clean-config.ini"
    _write_config(path)
    text = path.read_text()
    path.write_text(text[: text.index("[account:bad]")])
    return path


async def _apply(
    db: Database, settings: Settings, config_path: Path, sampler_data_dir: Path
) -> SamplerImporter:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)
    await importer.apply(await importer.plan(config_path, sampler_data_dir))
    return importer


def _kinds(report: VerifyReport, account: str) -> dict[str, KindVerification]:
    by_name = {a.name: a for a in report.accounts}
    return {k.kind: k for k in by_name[account].kinds}


async def test_verify_complete_after_import(
    db: Database, settings: Settings, clean_config_path: Path, sampler_data_dir: Path
) -> None:
    importer = await _apply(db, settings, clean_config_path, sampler_data_dir)

    report = await importer.verify(clean_config_path, sampler_data_dir)

    assert report.complete
    assert report.problems == ()
    assert _kinds(report, "default")["all"] == KindVerification("all", 2, 2, 0, 0)
    assert _kinds(report, "acct2")["partial"] == KindVerification("partial", 2, 2, 0, 0)


async def test_verify_before_import_reports_everything_missing(
    db: Database, settings: Settings, clean_config_path: Path, sampler_data_dir: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)

    report = await importer.verify(clean_config_path, sampler_data_dir)

    assert not report.complete
    assert all(not a.account_present for a in report.accounts)
    assert _kinds(report, "default")["all"] == KindVerification("all", 2, 0, 2, 0)
    assert _kinds(report, "acct2")["partial"] == KindVerification("partial", 2, 0, 2, 0)
    async with db.read() as conn:
        assert await AccountRepository().list_all(conn) == []


async def test_verify_detects_a_missing_file(
    db: Database, settings: Settings, clean_config_path: Path, sampler_data_dir: Path
) -> None:
    importer = await _apply(db, settings, clean_config_path, sampler_data_dir)
    async with db.write() as conn:
        await conn.execute(
            delete(deliveries).where(deliveries.c.remote_name.like(f"%{_VIN3}_data.zip"))
        )
    report = await importer.verify(clean_config_path, sampler_data_dir)

    assert not report.complete
    assert _kinds(report, "default")["all"] == KindVerification("all", 2, 2, 0, 0)
    assert _kinds(report, "acct2")["partial"] == KindVerification("partial", 2, 1, 1, 0)


async def test_verify_detects_changed_content(
    db: Database, settings: Settings, clean_config_path: Path, sampler_data_dir: Path
) -> None:
    importer = await _apply(db, settings, clean_config_path, sampler_data_dir)
    other_payload = _wrap_json_as_zip(_capture_json("SOMETHINGELSE"))
    async with db.write() as conn:
        await conn.execute(
            update(deliveries)
            .where(deliveries.c.remote_name.like(f"%{_VIN1}_data.zip"))
            .values(raw_payload=other_payload)
        )
        await conn.execute(
            update(deliveries)
            .where(deliveries.c.remote_name.like(f"%{_VIN2}_data.zip"))
            .values(raw_payload=b"not a zip")
        )
        await conn.execute(
            update(deliveries)
            .where(deliveries.c.remote_name.like("%no_content_found.zip"))
            .values(sha256="0" * 64)
        )

    report = await importer.verify(clean_config_path, sampler_data_dir)

    assert not report.complete
    assert _kinds(report, "default")["all"] == KindVerification("all", 2, 2, 0, 2)
    assert _kinds(report, "acct2")["partial"] == KindVerification("partial", 2, 2, 0, 1)


async def test_verify_ignores_zip_repacking(
    db: Database, settings: Settings, clean_config_path: Path, sampler_data_dir: Path
) -> None:
    importer = await _apply(db, settings, clean_config_path, sampler_data_dir)
    repacked = _wrap_json_as_zip(_capture_json(_VIN1))
    async with db.write() as conn:
        await conn.execute(
            update(deliveries)
            .where(deliveries.c.remote_name.like(f"%{_VIN1}_data.zip"))
            .values(raw_payload=repacked, sha256="f" * 64)
        )

    report = await importer.verify(clean_config_path, sampler_data_dir)

    assert report.complete


async def test_verify_with_an_empty_sampler_database_is_complete(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    sampler_dir = tmp_path / "empty-sampler"
    sampler._open_database(sampler_dir / "captures.sqlite3").close()
    config = tmp_path / "empty-config.ini"
    config.write_text(
        f"[portal]\nbrand = Audi\nuser = owner@example.com\npassword = x12345678\nvin = {_VIN1}\n"
    )
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)

    report = await importer.verify(config, sampler_dir)

    assert report.complete
    assert [(a.name, a.kinds) for a in report.accounts] == [("default", ())]


async def test_verify_reports_a_missing_sampler_database_and_skipped_sections(
    db: Database, settings: Settings, config_path: Path, tmp_path: Path
) -> None:
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)

    report = await importer.verify(config_path, tmp_path / "no-such-dir")

    assert not report.complete
    assert any("missing or unreadable" in p for p in report.problems)
    assert any("unknown brand" in p for p in report.problems)


async def test_verify_with_no_valid_account_is_not_complete(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    config = tmp_path / "bad.ini"
    config.write_text("[account:bad]\nbrand = Tesla\nuser = x@example.com\npassword = pw123456\n")
    importer = SamplerImporter(db, settings, clock=lambda: _NOW)

    report = await importer.verify(config, tmp_path)

    assert report.accounts == ()
    assert not report.complete


async def test_verify_counts_files_of_unconfigured_vehicles_as_missing(
    db: Database, settings: Settings, tmp_path: Path
) -> None:
    sampler_dir = tmp_path / "sampler"
    conn = sampler._open_database(sampler_dir / "captures.sqlite3")
    try:
        sampler._store_capture(
            conn,
            sampler.DatasetInfo(
                name=_dataset_name("20261001120000", _VIN3, "data.zip"), created_on=None
            ),
            "all",
            _capture_json(_VIN3),
        )
    finally:
        conn.close()
    config = tmp_path / "config.ini"
    config.write_text(
        f"[portal]\nbrand = Audi\nuser = owner@example.com\npassword = x12345678\nvin = {_VIN1}\n"
    )
    importer = await _apply(db, settings, config, sampler_dir)

    report = await importer.verify(config, sampler_dir)

    assert not report.complete
    assert _kinds(report, "default")["all"] == KindVerification("all", 1, 0, 1, 0)


async def test_verify_is_read_only_and_leaks_nothing(
    db: Database,
    settings: Settings,
    clean_config_path: Path,
    sampler_data_dir: Path,
    tmp_path: Path,
) -> None:
    importer = await _apply(db, settings, clean_config_path, sampler_data_dir)
    capture_db = sampler_data_dir / "captures.sqlite3"
    before_bytes = capture_db.read_bytes()
    before = _stat_fingerprint(capture_db)
    async with db.read() as conn:
        delivery_count = len((await conn.execute(select(deliveries.c.id))).all())

    report = await importer.verify(clean_config_path, sampler_data_dir)

    assert capture_db.read_bytes() == before_bytes
    assert _stat_fingerprint(capture_db) == before
    async with db.read() as conn:
        assert len((await conn.execute(select(deliveries.c.id))).all()) == delivery_count
    blob = str(report)
    for secret in (_DEFAULT_PASSWORD, _ACCT2_PASSWORD, _VIN1, _VIN2, _VIN3):
        assert secret not in blob


def _zip_with(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_stored_json_sha256_accepts_exactly_one_member() -> None:
    payload = _zip_with({"anything.json": b"{}"})
    assert _stored_json_sha256(payload) == hashlib.sha256(b"{}").hexdigest()


@pytest.mark.parametrize(
    "payload",
    [b"", b"not a zip", _zip_with({}), _zip_with({"a": b"1", "b": b"2"})],
    ids=["empty", "garbage", "no-member", "two-members"],
)
def test_stored_json_sha256_rejects_unusable_archives(payload: bytes) -> None:
    assert _stored_json_sha256(payload) is None


def test_stored_json_sha256_enforces_the_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sampler_import_module, "_MAX_VERIFIED_MEMBER_BYTES", 10)
    assert _stored_json_sha256(_zip_with({"a": b"x" * 11})) is None
    assert _stored_json_sha256(_zip_with({"a": b"x" * 10})) is not None
