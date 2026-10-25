"""Tests for carchive.cli."""

from __future__ import annotations

import io
import json
import logging
import os
import re
import sqlite3
import stat
import sys
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import uvicorn

from carchive import __version__
from carchive.cli import main
from carchive.config import (
    Settings,
    load_operator_hash,
    load_secrets,
    vault_key_path,
    write_credentials,
    write_operator_hash,
)
from carchive.core.models import RemoteDataRequest, RemoteDelivery, RemoteVehicle
from carchive.core.provider import ProviderRegistry
from carchive.logging_setup import configure_logging
from carchive.services import backup as backup_module
from carchive.services import user_service
from carchive.services.lock import DataDirLock
from tests.services.fakes import FakeProvider
from tests.services.test_user_service import FakeSystemd
from tests.services.tls_fixtures import TlsFiles, make_files


@pytest.fixture(autouse=True)
def _isolated_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every XDG/Carchive env var at a fresh tmp dir, never the real home."""
    monkeypatch.delenv("CARCHIVE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))


@pytest.fixture(autouse=True)
def _restore_umask() -> Generator[None]:
    """`main()` changes the process umask; restore it so that does not leak into other tests."""
    original = os.umask(0)
    os.umask(original)
    yield
    os.umask(original)


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


def test_version_subcommand_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["version"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == __version__


def test_no_subcommand_prints_help_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([])
    assert exit_code == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_json_log_format_emits_one_json_object_per_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(verbose=False, fmt="json")
    logging.getLogger("carchive.test").info("hello", extra={"vin": "ignored"})

    lines = [line for line in capsys.readouterr().err.splitlines() if line]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "hello"
    assert record["level"] == "info"


def test_check_all_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials.audi]\nuser = "me"\npassword = "secretpass"\n')
    secrets_file.chmod(0o600)
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "secretpass" not in out
    for line in out.splitlines():
        if line.startswith(("container mode:", "tls:", "auth:", "vault:")):
            continue
        assert line.endswith("ok")


def test_check_vault_line_counts_plaintext_then_encrypted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials.audi]\nuser = "me"\npassword = "secretpass"\n')
    secrets_file.chmod(0o600)
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "vault: no key file yet; 0 encrypted, 1 plaintext password(s)" in out
    assert "next credential write encrypts them" in out

    write_credentials(secrets_file, "vw", {"user": "u", "password": "p"}, overwrite=False)

    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "vault: key present, mode ok; 2 encrypted, 0 plaintext password(s)" in out
    assert "secretpass" not in out


def test_check_fails_when_vault_key_is_missing_for_encrypted_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = tmp_path / "secrets.toml"
    write_credentials(
        secrets_file, "audi", {"user": "me", "password": "secretpass"}, overwrite=False
    )
    (tmp_path / "vault.key").unlink()
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "vault: error:" in out
    assert "secretpass" not in out


def test_check_reports_insecure_secrets_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials.audi]\npassword = "secretpass"\n')
    secrets_file.chmod(0o644)
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "secretpass" not in out
    assert "chmod 600" in out


def test_check_reports_non_loopback_bind_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "false")

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert any("bind host: error: non-loopback binds require TLS" in ln for ln in out.splitlines())


def test_check_accepts_non_loopback_bind_host_with_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("CARCHIVE_ALLOWED_HOSTS", '["localhost", "box.lan.test"]')

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "bind host: ok" in out.splitlines()


def test_check_reports_no_password_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(tmp_path / "secrets.toml"))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert (
        "auth: no password set (open http://127.0.0.1:8470/login and choose one; "
        "whoever submits the form first becomes the operator)"
    ) in out.splitlines()


def test_check_reports_password_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = tmp_path / "secrets.toml"
    write_operator_hash(secrets_file, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g")
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "auth: password set" in out.splitlines()
    assert "argon2" not in out


def test_check_reports_broken_login_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text("[operator\nbroken")
    secrets_file.chmod(0o600)
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert any(line.startswith("auth: error:") for line in out.splitlines())


def test_check_reports_container_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_CONTAINER", "1")

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "container mode: enabled" in out


def test_check_container_mode_accepts_non_loopback_bind_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_CONTAINER", "1")
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert any("bind host: ok" in line for line in out.splitlines())


def test_db_upgrade_migrates_a_fresh_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["db", "upgrade"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "(none) ->" in out
    data_dir = tmp_path / "data-dir"
    assert (data_dir / "carchive.sqlite3").is_file()


def test_db_upgrade_creates_data_dir_db_and_lock_owner_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))

    exit_code = main(["db", "upgrade"])
    capsys.readouterr()

    assert exit_code == 0
    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((data_dir / "carchive.sqlite3").stat().st_mode) == 0o600
    assert stat.S_IMODE((data_dir / "carchive.lock").stat().st_mode) == 0o600


def test_db_upgrade_does_not_print_alembic_info_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    main(["db", "upgrade"])

    captured = capsys.readouterr()
    assert "Context impl" not in captured.out
    assert "Context impl" not in captured.err


def test_db_upgrade_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    first = main(["db", "upgrade"])
    capsys.readouterr()
    second = main(["db", "upgrade"])
    out = capsys.readouterr().out

    assert first == 0
    assert second == 0
    assert "(none) ->" not in out


def test_db_status_reports_up_to_date_after_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    main(["db", "upgrade"])
    capsys.readouterr()

    exit_code = main(["db", "status"])

    out = capsys.readouterr().out
    assert exit_code == 0
    lines = {line.split(": ", 1)[0]: line.split(": ", 1)[1] for line in out.splitlines()}
    assert lines["current"] == lines["head"]
    assert lines["current"] != "(none)"


def test_db_status_reports_behind_before_any_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["db", "status"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "current: (none)" in out


def test_db_upgrade_refuses_while_data_dir_is_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))

    with DataDirLock(data_dir):
        exit_code = main(["db", "upgrade"])

    err = capsys.readouterr().err
    assert exit_code == 1
    assert "locked" in err


def test_db_without_subcommand_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    with pytest.raises(SystemExit) as exc_info:
        main(["db"])

    assert exc_info.value.code == 2
    assert "subcommand" in capsys.readouterr().err


def test_db_upgrade_backs_up_an_existing_db_before_a_real_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import carchive.cli as cli_module
    from carchive.storage.migrate import head_revision as real_head_revision

    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()
    real_head = real_head_revision()
    monkeypatch.setattr(cli_module, "head_revision", lambda: f"{real_head}-not-yet-applied")

    exit_code = main(["db", "upgrade"])

    assert exit_code == 0
    backups = list((data_dir / "backups").glob("carchive-*.sqlite3.gz"))
    assert len(backups) == 1


# --- parse-pending ---------------------------------------------------------------


def test_parse_pending_with_no_pending_deliveries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    main(["db", "upgrade"])
    capsys.readouterr()

    exit_code = main(["parse-pending"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "parsed 0, failed 0" in out


def test_parse_pending_refuses_while_data_dir_is_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()

    with DataDirLock(data_dir):
        exit_code = main(["parse-pending"])

    err = capsys.readouterr().err
    assert exit_code == 1
    assert "locked" in err


def test_parse_pending_processes_a_pending_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio
    import io
    import json
    import zipfile
    from datetime import UTC, datetime
    from uuid import uuid4

    from carchive.storage.db import Database
    from carchive.storage.repositories import (
        AccountRepository,
        DataRequestRepository,
        DeliveryRepository,
        VehicleRepository,
    )

    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()

    now = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
    vin = "WAUZZZ4V0JA123456"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "dataset.json",
            json.dumps(
                {
                    "vin": vin,
                    "Data": [
                        {
                            "key": "k1",
                            "dataFieldName": "mileage",
                            "timestampUtc": "2026-10-01T00:00:00Z",
                            "value": "1",
                        }
                    ],
                }
            ),
        )
    payload = buf.getvalue()

    async def _seed() -> None:
        db = Database()
        await db.connect(data_dir / "carchive.sqlite3")
        try:
            account_id = uuid4()
            vehicle_id = uuid4()
            async with db.write() as conn:
                await AccountRepository().add(
                    conn,
                    id=account_id,
                    provider_id="vwgroup-euda",
                    brand="audi",
                    label="acc",
                    credential_ref="ref",
                    state="active",
                    state_reason=None,
                    created_at=now,
                )
                await VehicleRepository().add(
                    conn,
                    id=vehicle_id,
                    account_id=account_id,
                    vin=vin,
                    label="car",
                    brand="audi",
                    model=None,
                    created_at=now,
                )
                request_id = await DataRequestRepository().upsert(
                    conn, vehicle_id=vehicle_id, kind="partial", remote_id="r1", interval_s=900
                )
                await DeliveryRepository().add(
                    conn,
                    data_request_id=request_id,
                    import_batch_id=None,
                    remote_name="f.zip",
                    delivered_at=now,
                    fetched_at=now,
                    has_content=True,
                    sha256="a" * 64,
                    size_bytes=len(payload),
                    parse_state="pending",
                    parser_version=None,
                    raw_payload=payload,
                )
        finally:
            await db.close()

    asyncio.run(_seed())

    exit_code = main(["parse-pending"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "parsed 1, failed 0" in out


# --- backup --------------------------------------------------------------------


def test_backup_create_then_list_shows_it_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    main(["db", "upgrade"])
    capsys.readouterr()

    create_exit = main(["backup", "create"])
    created_out = capsys.readouterr().out
    list_exit = main(["backup", "list"])
    list_out = capsys.readouterr().out

    assert create_exit == 0
    assert "created" in created_out
    assert list_exit == 0
    assert "verified" in list_out
    assert "not verified" not in list_out


def test_backup_create_files_are_owner_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()

    main(["backup", "create"])

    backup_dir = data_dir / "backups"
    assert stat.S_IMODE(backup_dir.stat().st_mode) == 0o700
    archives = list(backup_dir.glob("carchive-*.sqlite3.gz"))
    assert len(archives) == 1
    assert stat.S_IMODE(archives[0].stat().st_mode) == 0o600


def test_backup_verify_reports_a_tampered_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()
    main(["backup", "create"])
    capsys.readouterr()
    archive = next((data_dir / "backups").glob("carchive-*.sqlite3.gz"))
    archive.with_name(archive.name + ".sha256").write_text(f"{'0' * 64}  {archive.name}\n")

    exit_code = main(["backup", "verify", str(archive)])

    assert exit_code == 1
    assert "mismatch" in capsys.readouterr().err


def test_backup_prune_reports_nothing_to_prune_on_a_fresh_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    main(["db", "upgrade"])
    capsys.readouterr()
    main(["backup", "create"])
    capsys.readouterr()

    exit_code = main(["backup", "prune"])

    assert exit_code == 0
    assert "nothing to prune" in capsys.readouterr().out


def test_backup_restore_names_the_previous_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()
    main(["backup", "create"])
    capsys.readouterr()
    archive = next((data_dir / "backups").glob("carchive-*.sqlite3.gz"))

    exit_code = main(["backup", "restore", str(archive)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "before-restore" in out


def test_backup_restore_refuses_while_data_dir_is_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()
    main(["backup", "create"])
    capsys.readouterr()
    archive = next((data_dir / "backups").glob("carchive-*.sqlite3.gz"))

    with DataDirLock(data_dir):
        exit_code = main(["backup", "restore", str(archive)])

    err = capsys.readouterr().err
    assert exit_code == 1
    assert "locked" in err


def test_serve_rejects_non_loopback_bind_host_without_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`serve` must refuse a non-loopback bind host before touching the lock or the database."""
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "false")

    exit_code = main(["serve"])

    err = capsys.readouterr().err
    assert exit_code == 2
    assert "non-loopback binds require TLS" in err
    assert not data_dir.exists()


def test_serve_no_longer_accepts_the_unauthenticated_network_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["serve", "--allow-unauthenticated-network"])

    assert exc_info.value.code == 2
    assert "--allow-unauthenticated-network" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("bind_host", "container", "tls_enabled", "expect_refused"),
    [
        ("127.0.0.1", False, False, False),
        ("::1", False, False, False),
        ("0.0.0.0", False, False, True),
        ("192.0.2.10", False, True, False),
        ("0.0.0.0", True, False, False),
        ("0.0.0.0", True, True, False),
    ],
)
def test_serve_bind_refusal(
    bind_host: str, container: bool, tls_enabled: bool, expect_refused: bool
) -> None:
    from carchive.cli import _serve_bind_refusal

    refusal = _serve_bind_refusal(bind_host, container, tls_enabled)

    assert (refusal is not None) is expect_refused
    if refusal is not None:
        assert "non-loopback binds require TLS" in refusal


def test_serve_container_mode_logs_startup_reminder_and_does_not_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """`CARCHIVE_CONTAINER=1` must log a reminder and allow a non-loopback bind host.

    Stops short of actually starting the server (which would block forever) by raising
    out of the mocked `_serve` right after the pre-server checks have run.
    """
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CARCHIVE_CONTAINER", "1")
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")

    import carchive.cli as cli_module

    class _StopHereError(Exception):
        pass

    async def _fail_serve(*_args: object, **_kwargs: object) -> None:
        raise _StopHereError

    monkeypatch.setattr(cli_module, "_serve", _fail_serve)

    with caplog.at_level("INFO", logger="carchive.cli"), pytest.raises(_StopHereError):
        cli_module._run_serve()

    assert any("cli.container_mode" in record.message for record in caplog.records)


# --- TLS --------------------------------------------------------------------------


def _use_tls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, files: TlsFiles) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", str(files.certfile))
    monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", str(files.keyfile))


def test_check_reports_tls_not_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["check"])

    assert exit_code == 0
    assert "tls: not configured" in capsys.readouterr().out.splitlines()


def test_check_reports_a_valid_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_tls(monkeypatch, tmp_path, make_files(tmp_path))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert any(
        line.startswith("tls: ok (expires in") and "names: localhost, 127.0.0.1" in line
        for line in out.splitlines()
    )


def test_check_fails_on_a_key_file_that_is_too_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_tls(monkeypatch, tmp_path, make_files(tmp_path, key_mode=0o644))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "tls: error:" in out
    assert "chmod 600" in out


def test_check_fails_on_an_expired_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    start = datetime.now(UTC) - timedelta(days=30)
    files = make_files(tmp_path, not_before=start, valid_for=timedelta(days=10))
    _use_tls(monkeypatch, tmp_path, files)

    exit_code = main(["check"])

    assert exit_code == 1
    assert "tls: error: certificate expired" in capsys.readouterr().out


def test_check_warns_but_passes_for_a_soon_expiring_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_tls(monkeypatch, tmp_path, make_files(tmp_path, valid_for=timedelta(days=5)))

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "tls: warning: certificate expires in" in out


def test_check_warns_when_allowed_hosts_are_not_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_tls(monkeypatch, tmp_path, make_files(tmp_path))
    monkeypatch.setenv("CARCHIVE_ALLOWED_HOSTS", '["localhost", "carchive.example.org"]')

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "tls: warning: none of the allowed_hosts" in out


@pytest.mark.parametrize("command", ["check", "serve"])
def test_only_one_tls_setting_is_a_config_error(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", str(tmp_path / "cert.pem"))

    exit_code = main([command])

    assert exit_code == 2
    assert "must be set together" in capsys.readouterr().err


def test_serve_refuses_to_start_with_unusable_tls_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_tls(monkeypatch, tmp_path, make_files(tmp_path, key_mode=0o640))

    exit_code = main(["serve"])

    err = capsys.readouterr().err
    assert exit_code == 2
    assert "error: tls:" in err
    assert not (tmp_path / "data-dir").exists()


def test_serve_does_not_refuse_an_expired_certificate_but_logs_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    start = datetime.now(UTC) - timedelta(days=30)
    files = make_files(tmp_path, not_before=start, valid_for=timedelta(days=10))
    _use_tls(monkeypatch, tmp_path, files)

    import carchive.cli as cli_module

    class _StopHereError(Exception):
        pass

    async def _fail_serve(*_args: object, **_kwargs: object) -> None:
        raise _StopHereError

    monkeypatch.setattr(cli_module, "_serve", _fail_serve)

    with caplog.at_level("INFO", logger="carchive.cli"), pytest.raises(_StopHereError):
        cli_module._run_serve()

    records = [r for r in caplog.records if "cli.tls_certificate_expired" in r.message]
    assert records
    assert records[0].levelname == "ERROR"
    assert any("https://127.0.0.1:8470" in r.message for r in caplog.records)


def test_serve_allows_a_non_loopback_bind_with_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_tls(monkeypatch, tmp_path, make_files(tmp_path))
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")

    import carchive.cli as cli_module

    class _StopHereError(Exception):
        pass

    async def _fail_serve(*_args: object, **_kwargs: object) -> None:
        raise _StopHereError

    monkeypatch.setattr(cli_module, "_serve", _fail_serve)

    with pytest.raises(_StopHereError):
        cli_module._run_serve()


# --- automatic self-signed certificate -----------------------------------------------


def _use_selfsigned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, bind_host: str = "127.0.0.1"
) -> Path:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CARCHIVE_BIND_HOST", bind_host)
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "true")
    monkeypatch.setenv("CARCHIVE_ALLOWED_HOSTS", '["localhost", "127.0.0.1", "box.lan.test"]')
    return data_dir


def test_check_reports_a_certificate_that_will_be_generated_without_writing_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = _use_selfsigned(monkeypatch, tmp_path)

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert (
        "tls: ok (self-signed (automatic), a new certificate will be generated on start: missing)"
        in out
    )
    assert not (data_dir / "tls").exists()


def test_check_prints_fingerprint_expiry_and_names_of_the_automatic_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from carchive.services import tls_selfsigned

    data_dir = _use_selfsigned(monkeypatch, tmp_path)
    certificate = tls_selfsigned.ensure_selfsigned(
        data_dir, ("localhost", "127.0.0.1", "box.lan.test")
    )

    exit_code = main(["check"])

    lines = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    assert any(
        re.match(r"tls: ok \(self-signed \(automatic\), expires in 109[45] days, names: ", line)
        and "box.lan.test" in line
        for line in lines
    )
    assert f"tls: sha256 fingerprint: {certificate.info.fingerprint}" in lines
    assert "PRIVATE KEY" not in "\n".join(lines)


def test_check_reports_names_changed_for_an_outdated_automatic_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from carchive.services import tls_selfsigned

    data_dir = _use_selfsigned(monkeypatch, tmp_path)
    tls_selfsigned.ensure_selfsigned(data_dir, ("localhost",))

    main(["check"])

    out = capsys.readouterr().out
    assert "will be generated on start: names_changed" in out
    assert "tls: sha256 fingerprint:" in out


def test_check_fails_for_a_host_that_cannot_go_into_a_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_selfsigned(monkeypatch, tmp_path)
    monkeypatch.setenv("CARCHIVE_ALLOWED_HOSTS", '["bad host"]')

    exit_code = main(["check"])

    assert exit_code == 1
    assert "tls: error: allowed_hosts entry" in capsys.readouterr().out


def test_check_says_not_configured_for_loopback_without_selfsigned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    main(["check"])

    assert "tls: not configured" in capsys.readouterr().out.splitlines()


@pytest.mark.parametrize(
    ("env", "scheme"),
    [
        ({}, "http"),
        ({"CARCHIVE_BIND_HOST": "0.0.0.0"}, "https"),
        ({"CARCHIVE_BIND_HOST": "0.0.0.0", "CARCHIVE_TLS_SELFSIGNED": "false"}, "http"),
        ({"CARCHIVE_BIND_HOST": "0.0.0.0", "CARCHIVE_CONTAINER": "1"}, "https"),
        (
            {
                "CARCHIVE_BIND_HOST": "0.0.0.0",
                "CARCHIVE_CONTAINER": "1",
                "CARCHIVE_TLS_SELFSIGNED": "false",
            },
            "http",
        ),
        ({"CARCHIVE_TLS_SELFSIGNED": "true"}, "https"),
    ],
)
def test_server_url_scheme_follows_the_tls_mode(
    env: dict[str, str], scheme: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from carchive.cli import _server_url
    from carchive.config import load_settings

    for name, value in env.items():
        monkeypatch.setenv(name, value)

    assert _server_url(load_settings()).startswith(f"{scheme}://")


def test_serve_still_refuses_a_non_loopback_bind_when_selfsigned_is_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "false")

    exit_code = main(["serve"])

    assert exit_code == 2
    assert "non-loopback" in capsys.readouterr().err


def test_serve_reports_an_automatic_certificate_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import carchive.cli as cli_module
    from carchive.services.tls_selfsigned import SelfSignedError

    _use_selfsigned(monkeypatch, tmp_path)

    async def _fail_serve(*_args: object, **_kwargs: object) -> None:
        raise SelfSignedError("disk full")

    monkeypatch.setattr(cli_module, "_serve", _fail_serve)

    exit_code = main(["serve"])

    assert exit_code == 2
    assert "error: tls: disk full" in capsys.readouterr().err


class _FakeServer:
    """Stands in for `uvicorn.Server`: records the config and whether renewal is running."""

    config: object = None
    renewal_running_during_serve = False
    ssl_context_present = False

    def __init__(self, config: object) -> None:
        type(self).config = config

    async def serve(self) -> None:
        import asyncio

        tasks = [t for t in asyncio.all_tasks() if t.get_name() == "tls-selfsigned-renewal"]
        type(self).renewal_running_during_serve = len(tasks) == 1 and not tasks[0].done()
        type(self).ssl_context_present = getattr(self.config, "ssl", None) is not None
        type(self).tasks = tasks  # type: ignore[attr-defined]


async def test_serve_runs_the_renewal_task_for_the_automatic_certificate_and_stops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import carchive.cli as cli_module
    from carchive.config import load_settings

    data_dir = _use_selfsigned(monkeypatch, tmp_path)
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    data_dir.mkdir(mode=0o700)
    settings = load_settings()
    caplog.set_level("INFO", logger="carchive.cli")

    await cli_module._serve(settings, data_dir / "carchive.sqlite3")

    assert _FakeServer.renewal_running_during_serve
    assert _FakeServer.ssl_context_present
    assert all(task.done() for task in _FakeServer.tasks)  # type: ignore[attr-defined]
    assert (data_dir / "tls" / "selfsigned.pem").is_file()
    record = next(r for r in caplog.records if "cli.tls_selfsigned" in r.message)
    assert "PRIVATE KEY" not in record.message


async def test_serve_without_tls_starts_no_renewal_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import carchive.cli as cli_module
    from carchive.config import load_settings

    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    _FakeServer.renewal_running_during_serve = False
    settings = load_settings()
    settings.data_dir.mkdir(mode=0o700)

    await cli_module._serve(settings, settings.data_dir / "carchive.sqlite3")

    assert not _FakeServer.renewal_running_during_serve
    assert not (settings.data_dir / "tls").exists()


async def test_serve_on_loopback_announces_setup_without_a_network_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import carchive.cli as cli_module
    from carchive.config import load_settings

    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    settings = load_settings()
    settings.data_dir.mkdir(mode=0o700)
    caplog.set_level("INFO")

    await cli_module._serve(settings, settings.data_dir / "carchive.sqlite3")

    records = [r for r in caplog.records if "operator.setup_required" in r.getMessage()]
    assert len(records) == 1
    assert "http://127.0.0.1:8470/login" in records[0].getMessage()
    assert records[0].levelname == "INFO"
    assert not any("operator.setup_open_to_network" in r.getMessage() for r in caplog.records)
    assert not (settings.data_dir / "setup_token").exists()


@pytest.mark.parametrize(
    "env",
    [
        {"CARCHIVE_CONTAINER": "1", "CARCHIVE_BIND_HOST": "0.0.0.0"},
        {"CARCHIVE_CONTAINER": "1"},
        {"CARCHIVE_BIND_HOST": "0.0.0.0", "CARCHIVE_TLS_SELFSIGNED": "true"},
    ],
)
async def test_serve_warns_loudly_when_setup_is_open_to_the_network(
    env: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import carchive.cli as cli_module
    from carchive.config import load_settings

    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_ALLOWED_HOSTS", '["localhost", "127.0.0.1", "box.lan.test"]')
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    settings = load_settings()
    settings.data_dir.mkdir(mode=0o700)
    caplog.set_level("INFO")

    await cli_module._serve(settings, settings.data_dir / "carchive.sqlite3")

    records = [r for r in caplog.records if "operator.setup_open_to_network" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelname == "WARNING"
    assert "operator.setup_required" not in "".join(r.getMessage() for r in caplog.records)


async def test_serve_does_not_warn_about_open_setup_once_a_password_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import carchive.cli as cli_module
    from carchive.config import load_settings

    secrets_file = tmp_path / "secrets.toml"
    write_operator_hash(secrets_file, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g")
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    monkeypatch.setenv("CARCHIVE_CONTAINER", "1")
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    settings = load_settings()
    settings.data_dir.mkdir(mode=0o700)
    caplog.set_level("INFO")

    await cli_module._serve(settings, settings.data_dir / "carchive.sqlite3")

    assert not any("operator.setup_" in r.getMessage() for r in caplog.records)


async def test_serve_does_not_announce_setup_once_a_password_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import carchive.cli as cli_module
    from carchive.config import load_settings

    secrets_file = tmp_path / "secrets.toml"
    write_operator_hash(secrets_file, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g")
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    settings = load_settings()
    settings.data_dir.mkdir(mode=0o700)
    caplog.set_level("INFO")

    await cli_module._serve(settings, settings.data_dir / "carchive.sqlite3")

    assert not any("operator.setup_required" in r.getMessage() for r in caplog.records)


async def test_serve_fails_on_a_broken_secrets_file_instead_of_assuming_no_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import carchive.cli as cli_module
    from carchive.config import ConfigError, load_settings

    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text("[operator\nbroken")
    secrets_file.chmod(0o600)
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    settings = load_settings()
    settings.data_dir.mkdir(mode=0o700)

    with pytest.raises(ConfigError):
        await cli_module._serve(settings, settings.data_dir / "carchive.sqlite3")


# --- import-sampler -------------------------------------------------------------


def _write_sampler_config(path: Path, vin: str) -> None:
    path.write_text(
        f"[portal]\nbrand = Audi\nuser = owner@example.com\npassword = secretpass\nvin = {vin}\n"
    )


def _seed_sampler_db(data_dir: Path, vin: str) -> None:
    import eu_data_act_sampler as sampler

    conn = sampler._open_database(data_dir / "captures.sqlite3")
    try:
        sampler._store_capture(
            conn,
            sampler.DatasetInfo(name=f"20261001120000_{vin}_data.zip", created_on=None),
            "all",
            json.dumps(
                {
                    "vin": vin,
                    "Data": [
                        {
                            "key": "k1",
                            "dataFieldName": "mileage",
                            "timestampUtc": "2026-10-01T00:00:00Z",
                            "value": "1",
                        }
                    ],
                }
            ),
        )
    finally:
        conn.close()


def test_import_sampler_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    exit_code = main(
        [
            "import-sampler",
            "--config",
            str(sampler_config),
            "--sampler-data-dir",
            str(sampler_data_dir),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "default:" in out
    assert "secretpass" not in out
    assert vin not in out
    assert not data_dir.exists()  # a dry run never creates the data directory or its db
    assert not (tmp_path / "config" / "carchive" / "secrets.toml").exists()


def test_import_sampler_dry_run_in_a_fresh_xdg_tree_uses_xdg_defaults_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bare dry run (no `--config`/`--sampler-data-dir`) must stay inside the isolated XDG
    tree, never fall back to the real `~/.config`/`~/.local/share`."""
    config_home = tmp_path / "xdg-config"
    data_home = tmp_path / "xdg-data"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    monkeypatch.delenv("CARCHIVE_DATA_DIR", raising=False)
    monkeypatch.delenv("CARCHIVE_CONFIG", raising=False)
    vin = "WAUZZZ4V0JA123456"
    sampler_config = config_home / "carchive" / "config.ini"
    sampler_config.parent.mkdir(parents=True)
    _write_sampler_config(sampler_config, vin)
    _seed_sampler_db(data_home / "carchive", vin)

    exit_code = main(["import-sampler"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "default:" in out
    assert not (data_home / "carchive" / "carchive.sqlite3").exists()
    assert not (config_home / "carchive" / "secrets.toml").exists()


def test_import_sampler_apply_imports_and_parses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    secrets_file = tmp_path / "secrets.toml"
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    exit_code = main(
        [
            "import-sampler",
            "--config",
            str(sampler_config),
            "--sampler-data-dir",
            str(sampler_data_dir),
            "--apply",
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "default:" in out
    assert "parsed 1, failed 0" in out
    assert secrets_file.is_file()
    assert stat.S_IMODE(secrets_file.stat().st_mode) == 0o600


def _verify_args(sampler_config: Path, sampler_data_dir: Path, *extra: str) -> list[str]:
    return [
        "import-sampler",
        "--config",
        str(sampler_config),
        "--sampler-data-dir",
        str(sampler_data_dir),
        *extra,
    ]


def test_import_sampler_verify_before_and_after_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(tmp_path / "secrets.toml"))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    before = main(_verify_args(sampler_config, sampler_data_dir, "--verify"))
    out_before = capsys.readouterr().out
    assert before == 1
    assert "default [all]" in out_before
    assert "missing 1" in out_before
    assert "verify: INCOMPLETE" in out_before
    assert not data_dir.exists()  # verifying never creates the data directory

    assert main(_verify_args(sampler_config, sampler_data_dir, "--apply")) == 0
    capsys.readouterr()

    after = main(_verify_args(sampler_config, sampler_data_dir, "--verify"))
    out_after = capsys.readouterr().out
    assert after == 0
    assert "sampler 1, in Carchive 1, missing 0, content differs 0" in out_after
    assert "verify: complete" in out_after
    assert vin not in out_after
    assert "secretpass" not in out_after


def test_import_sampler_verify_refuses_while_data_dir_is_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    with DataDirLock(data_dir):
        exit_code = main(_verify_args(sampler_config, sampler_data_dir, "--verify"))

    assert exit_code == 1
    assert "locked" in capsys.readouterr().err


def test_import_sampler_verify_is_incompatible_with_apply(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["import-sampler", "--verify", "--apply"])

    assert excinfo.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_import_sampler_verify_missing_config_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["import-sampler", "--verify", "--config", str(tmp_path / "nope.ini")])

    assert exit_code == 2
    assert "not found" in capsys.readouterr().err


def test_import_sampler_no_parse_skips_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    exit_code = main(
        [
            "import-sampler",
            "--config",
            str(sampler_config),
            "--sampler-data-dir",
            str(sampler_data_dir),
            "--apply",
            "--no-parse",
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "parsed" not in out


def test_import_sampler_refuses_while_data_dir_is_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    with DataDirLock(data_dir):
        exit_code = main(
            [
                "import-sampler",
                "--config",
                str(sampler_config),
                "--sampler-data-dir",
                str(sampler_data_dir),
            ]
        )

    err = capsys.readouterr().err
    assert exit_code == 1
    assert "locked" in err


def test_import_sampler_reports_insecure_secrets_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials.default]\nuser = "me"\npassword = "secretpass"\n')
    secrets_file.chmod(0o644)
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    exit_code = main(
        [
            "import-sampler",
            "--config",
            str(sampler_config),
            "--sampler-data-dir",
            str(sampler_data_dir),
        ]
    )

    out_err = capsys.readouterr().err
    assert exit_code == 2
    assert "secretpass" not in out_err
    assert "chmod 600" in out_err


def test_import_sampler_missing_config_file_errors_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))

    exit_code = main(["import-sampler", "--config", str(tmp_path / "does-not-exist.ini")])

    out, err = capsys.readouterr()
    assert exit_code == 2
    assert out == ""
    assert "not found" in err
    assert not data_dir.exists()


def test_import_sampler_with_no_importable_account_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    sampler_config = tmp_path / "sampler-config.ini"
    sampler_config.write_text(
        "[account:bad]\nbrand = Tesla\nuser = x@example.com\npassword = whatever123\n"
    )

    exit_code = main(["import-sampler", "--config", str(sampler_config)])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "unknown brand" in out


def test_import_sampler_dry_run_against_an_outdated_database_reports_the_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    data_dir.mkdir()
    (data_dir / "carchive.sqlite3").write_bytes(b"")  # exists, but has none of the tables
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    exit_code = main(
        [
            "import-sampler",
            "--config",
            str(sampler_config),
            "--sampler-data-dir",
            str(sampler_data_dir),
        ]
    )

    err = capsys.readouterr().err
    assert exit_code == 2
    assert "db upgrade" in err


def test_import_sampler_dry_run_against_an_up_to_date_existing_database_still_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data-dir"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    main(["db", "upgrade"])
    capsys.readouterr()
    vin = "WAUZZZ4V0JA123456"
    sampler_config = tmp_path / "sampler-config.ini"
    _write_sampler_config(sampler_config, vin)
    sampler_data_dir = tmp_path / "sampler-data"
    _seed_sampler_db(sampler_data_dir, vin)

    exit_code = main(
        [
            "import-sampler",
            "--config",
            str(sampler_config),
            "--sampler-data-dir",
            str(sampler_data_dir),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "default:" in out
    # No backup was taken (a dry run never migrates, and only a migration backs up), and
    # the dry run's own read connection never inserted any row into the real database.
    assert not (data_dir / "backups").exists()
    with sqlite3.connect(data_dir / "carchive.sqlite3") as conn:
        assert conn.execute("SELECT count(*) FROM accounts").fetchone() == (0,)


def test_backup_without_subcommand_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    with pytest.raises(SystemExit) as exc_info:
        main(["backup"])

    assert exc_info.value.code == 2
    assert "subcommand" in capsys.readouterr().err


# --- account/vehicle/fetch --------------------------------------------------------


def _patch_fake_provider(monkeypatch: pytest.MonkeyPatch, fake_provider: FakeProvider) -> None:
    """Make every `build_services` call use `fake_provider` instead of the real VW-group one."""
    _patch_fake_providers(monkeypatch, fake_provider)


def _patch_fake_providers(monkeypatch: pytest.MonkeyPatch, *fake_providers: FakeProvider) -> None:
    """Make every `build_services` call use `fake_providers` instead of the real VW-group one."""
    import carchive.bootstrap as bootstrap_module

    registry = ProviderRegistry()
    for fake_provider in fake_providers:
        registry.register(fake_provider)
    monkeypatch.setattr(bootstrap_module, "build_provider_registry", lambda: registry)


def _patch_answers(monkeypatch: pytest.MonkeyPatch, *answers: str) -> None:
    """Patch `input()` to return `answers` in order, one per call."""
    remaining = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(remaining))


def _patch_password(monkeypatch: pytest.MonkeyPatch, password: str) -> None:
    monkeypatch.setattr("carchive.cli.getpass.getpass", lambda prompt="": password)


def test_account_add_creates_account_and_selected_vehicle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    _patch_fake_provider(monkeypatch, fake_provider)
    _patch_answers(monkeypatch, "1", "myacct", "user", "all")
    _patch_password(monkeypatch, "s3cret-password")

    exit_code = main(["account", "add"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "login ok" in out
    assert "added 1 vehicle(s)" in out
    assert "s3cret-password" not in out


def test_account_add_login_failure_is_not_saved_without_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    _patch_fake_provider(monkeypatch, fake_provider)
    _patch_answers(monkeypatch, "1", "myacct", "user", "n")
    _patch_password(monkeypatch, "wrong-password")

    exit_code = main(["account", "add"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "not saved" in out

    capsys.readouterr()
    list_exit_code = main(["account", "list"])
    assert list_exit_code == 0
    assert "no accounts yet" in capsys.readouterr().out


def test_account_add_login_failure_can_be_kept_on_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    _patch_fake_provider(monkeypatch, fake_provider)
    _patch_answers(monkeypatch, "1", "myacct", "user", "y")
    _patch_password(monkeypatch, "wrong-password")

    exit_code = main(["account", "add"])

    assert exit_code == 0
    capsys.readouterr()
    list_exit_code = main(["account", "list"])
    assert list_exit_code == 0
    assert "myacct" in capsys.readouterr().out


def test_account_add_lists_every_brand_sorted_and_numbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    first_provider = FakeProvider(user="user", password="s3cret-password")
    first_provider.id = "zz"
    first_provider.brands = frozenset({"zoo"})
    second_provider = FakeProvider(user="user", password="s3cret-password")
    second_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    _patch_fake_providers(monkeypatch, first_provider, second_provider)
    _patch_answers(monkeypatch, "2", "myacct", "user", "all")
    _patch_password(monkeypatch, "s3cret-password")

    exit_code = main(["account", "add"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "1) fake" in out
    assert "2) zoo" in out
    assert out.index("1) fake") < out.index("2) zoo")


def test_account_add_invalid_brand_number_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    _patch_fake_provider(monkeypatch, fake_provider)
    _patch_answers(monkeypatch, "7")

    exit_code = main(["account", "add"])

    assert exit_code == 2
    assert "no brand numbered 7" in capsys.readouterr().err


def test_account_add_non_numeric_brand_answer_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    _patch_fake_provider(monkeypatch, fake_provider)
    _patch_answers(monkeypatch, "audi")

    exit_code = main(["account", "add"])

    assert exit_code == 2
    assert "is not a number" in capsys.readouterr().err


def _add_account_with_one_vehicle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> FakeProvider:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA123456", name="A6")]
    _patch_fake_provider(monkeypatch, fake_provider)
    _patch_answers(monkeypatch, "1", "myacct", "user", "all")
    _patch_password(monkeypatch, "s3cret-password")
    assert main(["account", "add"]) == 0
    capsys.readouterr()
    return fake_provider


def test_account_remove_without_yes_only_previews(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)

    exit_code = main(["account", "remove", "myacct"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "would remove" in out
    list_exit_code = main(["account", "list"])
    assert "myacct" in capsys.readouterr().out
    assert list_exit_code == 0


def test_account_remove_with_yes_deletes_account_and_vehicles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)

    exit_code = main(["account", "remove", "myacct", "--yes"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "deleted" in out
    list_exit_code = main(["vehicle", "list"])
    assert "no vehicles yet" in capsys.readouterr().out
    assert list_exit_code == 0


def test_account_remove_unknown_label_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["account", "remove", "does-not-exist"])

    assert exit_code == 2
    assert "no account" in capsys.readouterr().err


_NEW_PORTAL_PASSWORD = "brand-new-portal-passphrase"


def test_account_set_password_replaces_password_and_keeps_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    _patch_fake_provider(monkeypatch, FakeProvider(user="user", password=_NEW_PORTAL_PASSWORD))
    _patch_tty_and_passwords(monkeypatch, _NEW_PORTAL_PASSWORD, _NEW_PORTAL_PASSWORD)

    exit_code = main(["account", "set-password", "myacct"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert _NEW_PORTAL_PASSWORD not in captured.out + captured.err
    secrets_file = Settings().secrets_file
    assert load_secrets(secrets_file)["myacct"] == {
        "user": "user",
        "password": _NEW_PORTAL_PASSWORD,
    }
    assert _NEW_PORTAL_PASSWORD not in secrets_file.read_text()
    assert main(["vehicle", "list"]) == 0
    assert "myacct" in capsys.readouterr().out


def test_account_set_password_unknown_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    _patch_tty_and_passwords(monkeypatch, _NEW_PORTAL_PASSWORD, _NEW_PORTAL_PASSWORD)

    exit_code = main(["account", "set-password", "does-not-exist"])

    assert exit_code == 2
    assert "no account" in capsys.readouterr().err


def test_account_set_password_without_tty_exits_2_and_never_prompts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    _patch_tty_and_passwords(monkeypatch, tty=False)

    exit_code = main(["account", "set-password", "myacct"])

    assert exit_code == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert not (tmp_path / "data-dir").exists()


def test_account_set_password_mismatch_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    _patch_tty_and_passwords(monkeypatch, _NEW_PORTAL_PASSWORD, _NEW_PORTAL_PASSWORD + "x")

    exit_code = main(["account", "set-password", "myacct"])

    assert exit_code == 1
    assert "do not match" in capsys.readouterr().err
    assert load_secrets(Settings().secrets_file)["myacct"]["password"] == "s3cret-password"


def test_account_set_password_rejected_by_portal_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    _patch_tty_and_passwords(monkeypatch, "not-the-portal-one", "not-the-portal-one")

    exit_code = main(["account", "set-password", "myacct"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "nothing was changed" in captured.err
    assert "not-the-portal-one" not in captured.out + captured.err
    assert load_secrets(Settings().secrets_file)["myacct"]["password"] == "s3cret-password"


def test_account_set_password_recovers_a_lost_vault_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    secrets_file = Settings().secrets_file
    vault_key_path(secrets_file).unlink()
    _patch_fake_provider(monkeypatch, FakeProvider(user="user", password=_NEW_PORTAL_PASSWORD))
    _patch_tty_and_passwords(monkeypatch, _NEW_PORTAL_PASSWORD, _NEW_PORTAL_PASSWORD)

    exit_code = main(["account", "set-password", "myacct"])

    assert exit_code == 0
    assert load_secrets(secrets_file)["myacct"]["password"] == _NEW_PORTAL_PASSWORD
    assert stat.S_IMODE(vault_key_path(secrets_file).stat().st_mode) == 0o600


def _add_second_account(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], label: str
) -> None:
    fake_provider = FakeProvider(user="user", password="s3cret-password")
    fake_provider.vehicles = [RemoteVehicle(vin="WAUZZZ4V0JA654321", name="Q4")]
    _patch_fake_provider(monkeypatch, fake_provider)
    _patch_answers(monkeypatch, "1", label, "user", "all")
    _patch_password(monkeypatch, "s3cret-password")
    assert main(["account", "add"]) == 0
    capsys.readouterr()


def _two_accounts_with_lost_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Path:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    _add_second_account(monkeypatch, capsys, "second")
    secrets_file = Settings().secrets_file
    vault_key_path(secrets_file).unlink()
    _patch_fake_provider(monkeypatch, FakeProvider(user="user", password=_NEW_PORTAL_PASSWORD))
    return secrets_file


def test_account_set_password_without_label_recovers_every_unreadable_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = _two_accounts_with_lost_key(tmp_path, monkeypatch, capsys)
    _patch_tty_and_passwords(monkeypatch, *[_NEW_PORTAL_PASSWORD] * 4)

    exit_code = main(["account", "set-password"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "2 account(s)" in captured.out
    assert _NEW_PORTAL_PASSWORD not in captured.out + captured.err
    loaded = load_secrets(secrets_file)
    assert {ref: fields["password"] for ref, fields in loaded.items()} == {
        "myacct": _NEW_PORTAL_PASSWORD,
        "second": _NEW_PORTAL_PASSWORD,
    }
    assert stat.S_IMODE(vault_key_path(secrets_file).stat().st_mode) == 0o600
    assert main(["vehicle", "list"]) == 0
    assert "second" in capsys.readouterr().out


def test_account_set_password_without_label_aborted_midway_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = _two_accounts_with_lost_key(tmp_path, monkeypatch, capsys)
    content_before = secrets_file.read_bytes()
    _patch_tty_and_passwords(
        monkeypatch,
        _NEW_PORTAL_PASSWORD,
        _NEW_PORTAL_PASSWORD,
        _NEW_PORTAL_PASSWORD,
        _NEW_PORTAL_PASSWORD + "x",
    )

    exit_code = main(["account", "set-password"])

    assert exit_code == 1
    assert "do not match" in capsys.readouterr().err
    assert secrets_file.read_bytes() == content_before
    assert not vault_key_path(secrets_file).exists()


def test_account_set_password_without_label_stops_when_the_portal_rejects_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = _two_accounts_with_lost_key(tmp_path, monkeypatch, capsys)
    content_before = secrets_file.read_bytes()
    _patch_tty_and_passwords(
        monkeypatch, _NEW_PORTAL_PASSWORD, _NEW_PORTAL_PASSWORD, "rejected-one", "rejected-one"
    )

    exit_code = main(["account", "set-password"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "nothing was changed" in captured.err
    assert "rejected-one" not in captured.out + captured.err
    assert secrets_file.read_bytes() == content_before
    assert not vault_key_path(secrets_file).exists()


def test_account_set_password_with_label_names_the_other_unreadable_accounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = _two_accounts_with_lost_key(tmp_path, monkeypatch, capsys)
    content_before = secrets_file.read_bytes()
    _patch_tty_and_passwords(monkeypatch)

    exit_code = main(["account", "set-password", "myacct"])

    err = capsys.readouterr().err
    assert exit_code == 2
    assert "1 other reference(s) (second)" in err
    assert "without a label" in err
    assert secrets_file.read_bytes() == content_before


def test_account_set_password_without_label_needs_something_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    _patch_tty_and_passwords(monkeypatch)

    exit_code = main(["account", "set-password"])

    assert exit_code == 2
    assert "no stored password is unreadable" in capsys.readouterr().err


def test_account_remove_works_after_the_vault_key_was_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_file = _two_accounts_with_lost_key(tmp_path, monkeypatch, capsys)

    assert main(["account", "remove", "myacct"]) == 0
    assert main(["account", "remove", "myacct", "--yes"]) == 0

    assert "deleted" in capsys.readouterr().out
    assert "myacct" not in secrets_file.read_text()
    assert "second" in secrets_file.read_text()


def test_vehicle_list_shows_added_vehicle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)

    exit_code = main(["vehicle", "list"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "myacct" in out
    assert "WAU" in out  # masked VIN keeps the first three characters


def test_vehicle_sync_adds_newly_reported_vehicle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_provider = _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    fake_provider.vehicles.append(RemoteVehicle(vin="WVWZZZ1KZAW123456", name="Golf"))
    _patch_answers(monkeypatch, "all")

    exit_code = main(["vehicle", "sync", "myacct"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "added 1 vehicle(s)" in out


def test_vehicle_sync_unknown_account_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["vehicle", "sync", "does-not-exist"])

    assert exit_code == 2
    assert "no account" in capsys.readouterr().err


def _vehicle_id_prefix(capsys: pytest.CaptureFixture[str]) -> str:
    """Run `vehicle list` and return the first (and only) vehicle's printed id prefix."""
    exit_code = main(["vehicle", "list"])
    assert exit_code == 0
    line = capsys.readouterr().out.strip().splitlines()[0]
    return line.split()[0]


def test_vehicle_remove_without_yes_only_previews(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    prefix = _vehicle_id_prefix(capsys)

    exit_code = main(["vehicle", "remove", prefix])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "would remove" in out
    list_exit_code = main(["vehicle", "list"])
    assert "WAU" in capsys.readouterr().out
    assert list_exit_code == 0


def test_vehicle_remove_with_yes_deletes_the_vehicle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    prefix = _vehicle_id_prefix(capsys)

    exit_code = main(["vehicle", "remove", prefix, "--yes"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "deleted" in out
    list_exit_code = main(["vehicle", "list"])
    assert "no vehicles yet" in capsys.readouterr().out
    assert list_exit_code == 0


def test_vehicle_remove_unknown_prefix_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)

    exit_code = main(["vehicle", "remove", "0000000000"])

    assert exit_code == 2
    assert "no vehicle" in capsys.readouterr().err


def test_fetch_with_no_due_work_reports_nothing_due(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_provider = _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    fake_provider.data_requests_by_vin["WAUZZZ4V0JA123456"] = []

    exit_code = main(["fetch"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "nothing due" in out


def test_fetch_downloads_a_due_delivery_and_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    vin = "WAUZZZ4V0JA123456"
    fake_provider = _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)
    fake_provider.data_requests_by_vin[vin] = [
        RemoteDataRequest(vin=vin, kind="partial", remote_id="remote-1")
    ]
    fake_provider.deliveries_by_remote_id["remote-1"] = [
        RemoteDelivery(remote_name="delivery-1", delivered_at=None, has_content=True)
    ]
    fake_provider.payloads["delivery-1"] = b"{}"

    exit_code = main(["fetch"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "account 'myacct' partial" in out
    assert "downloaded 1" in out


def test_fetch_unknown_account_label_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _add_account_with_one_vehicle(tmp_path, monkeypatch, capsys)

    exit_code = main(["fetch", "--account", "does-not-exist"])

    assert exit_code == 2
    assert "no account" in capsys.readouterr().err


# --- catalog ---------------------------------------------------------------------


def _build_dictionary_pdf(path: Path) -> None:
    from tests.services.pdf_fixtures import CONTINUOUS_HEADER, build_dictionary_pdf

    build_dictionary_pdf(
        path,
        title="List of Continuous Data",
        header=CONTINUOUS_HEADER,
        rows=[
            [
                "11111111-1111-1111-1111-111111111111",
                "mileage",
                "odometer reading",
                "km",
                "int",
                "General",
            ]
        ],
    )


def test_catalog_import_reports_new_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    pdf_path = tmp_path / "20260724_DataDictionary_V6.0_Continuous_Data.pdf"
    _build_dictionary_pdf(pdf_path)

    exit_code = main(["catalog", "import", str(pdf_path)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "imported continuous dictionary as version 6.0" in out
    assert "1 new" in out


def test_catalog_import_with_explicit_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    pdf_path = tmp_path / "dict.pdf"
    _build_dictionary_pdf(pdf_path)

    exit_code = main(["catalog", "import", str(pdf_path), "--catalog-version", "9.9"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "version 9.9" in out


def test_catalog_import_missing_file_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))

    exit_code = main(["catalog", "import", str(tmp_path / "missing.pdf")])

    assert exit_code == 2
    assert "no such file" in capsys.readouterr().err


def test_catalog_import_without_derivable_version_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    pdf_path = tmp_path / "dictionary.pdf"
    _build_dictionary_pdf(pdf_path)

    exit_code = main(["catalog", "import", str(pdf_path)])

    assert exit_code == 2
    assert "cannot derive a catalog version" in capsys.readouterr().err


def test_catalog_list_then_import_then_list_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    pdf_path = tmp_path / "dict_V1.0.pdf"
    _build_dictionary_pdf(pdf_path)

    before_exit = main(["catalog", "list"])
    before_out = capsys.readouterr().out
    main(["catalog", "import", str(pdf_path)])
    capsys.readouterr()
    after_exit = main(["catalog", "list"])
    after_out = capsys.readouterr().out

    assert before_exit == 0
    assert "no catalog imported yet" in before_out
    assert after_exit == 0
    assert "vwgroup-euda 1.0 (continuous): 1 entries" in after_out


# --- service ---------------------------------------------------------------------------


@pytest.fixture
def fake_systemd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeSystemd:
    """Route `service` commands to a fake; the real `systemctl` etc. must never run."""
    fake = FakeSystemd()
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    monkeypatch.setattr(user_service, "run_command", fake)
    monkeypatch.setattr(
        user_service,
        "detect_host",
        lambda: user_service.Host(uid=1000, user="alice", systemctl="/usr/bin/systemctl"),
    )
    return fake


def _unit_file(tmp_path: Path) -> Path:
    return tmp_path / "config" / "systemd" / "user" / "carchive.service"


def test_service_install_writes_unit_and_reports_each_step(
    tmp_path: Path, fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["service", "install"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ExecStart=" in _unit_file(tmp_path).read_text()
    assert "enable --now carchive.service" in fake_systemd.subcommands()
    assert captured.err == ""
    assert "wrote" in captured.out
    assert "enabled lingering" in captured.out


def test_service_install_no_start_only_enables(tmp_path: Path, fake_systemd: FakeSystemd) -> None:
    exit_code = main(["service", "install", "--no-start"])

    assert exit_code == 0
    assert "enable carchive.service" in fake_systemd.subcommands()
    assert not any("--now" in sub for sub in fake_systemd.subcommands())


def test_service_install_linger_failure_warns_with_exact_command_and_exits_zero(
    tmp_path: Path, fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_systemd.enable_linger_rc = 1

    exit_code = main(["service", "install"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert _unit_file(tmp_path).exists()
    assert "sudo loginctl enable-linger alice" in captured.err


def test_service_install_as_root_exits_two_and_writes_nothing(
    tmp_path: Path,
    fake_systemd: FakeSystemd,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        user_service, "detect_host", lambda: user_service.Host(0, "root", "/usr/bin/systemctl")
    )

    exit_code = main(["service", "install"])

    assert exit_code == 2
    assert "root" in capsys.readouterr().err
    assert not _unit_file(tmp_path).exists()


def test_service_install_without_systemctl_exits_two_and_points_to_readme(
    tmp_path: Path,
    fake_systemd: FakeSystemd,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(user_service, "detect_host", lambda: user_service.Host(1000, "alice", None))

    exit_code = main(["service", "install"])

    assert exit_code == 2
    assert "Running Carchive" in capsys.readouterr().err
    assert fake_systemd.calls == []


def test_service_install_without_user_manager_exits_two(
    tmp_path: Path, fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_systemd.user_manager_ok = False

    exit_code = main(["service", "install"])

    assert exit_code == 2
    assert "user manager" in capsys.readouterr().err
    assert not _unit_file(tmp_path).exists()


def test_service_install_daemon_reload_failure_exits_one_without_traceback(
    fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_systemd.failing["daemon-reload"] = 1

    exit_code = main(["service", "install"])

    err = capsys.readouterr().err
    assert exit_code == 1
    assert err.startswith("error: ")
    assert "exit 1" in err
    assert "Traceback" not in err


def test_service_install_subprocess_timeout_exits_one(
    fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_systemd.timing_out.add("daemon-reload")

    exit_code = main(["service", "install"])

    assert exit_code == 1
    assert "timed out" in capsys.readouterr().err


def test_service_install_twice_leaves_unit_untouched(
    tmp_path: Path, fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["service", "install"]) == 0
    inode = _unit_file(tmp_path).stat().st_ino
    capsys.readouterr()

    assert main(["service", "install"]) == 0

    assert _unit_file(tmp_path).stat().st_ino == inode
    assert "unit unchanged" in capsys.readouterr().out


def test_service_uninstall_removes_unit_and_is_idempotent(
    tmp_path: Path, fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["service", "install"])
    capsys.readouterr()

    assert main(["service", "uninstall"]) == 0
    assert not _unit_file(tmp_path).exists()
    assert "lingering left unchanged" in capsys.readouterr().out
    assert main(["service", "uninstall"]) == 0
    assert "not installed" in capsys.readouterr().out


def test_service_status_healthy_exits_zero_and_shows_url_and_journal(
    fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["service", "install"])
    capsys.readouterr()

    exit_code = main(["service", "status"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "url: http://127.0.0.1:8470" in captured.out
    assert captured.out.splitlines()[-2:] == ["line one", "line two"]
    assert captured.err == ""


def test_service_status_degraded_exits_one_and_names_what_is_missing(
    fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["service", "status"])

    err = capsys.readouterr().err
    assert exit_code == 1
    assert "not installed" in err
    assert "not running" in err
    assert "sudo loginctl enable-linger alice" in err


def test_service_status_active_without_linger_exits_one(
    fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["service", "install"])
    fake_systemd.linger = False
    capsys.readouterr()

    exit_code = main(["service", "status"])

    assert exit_code == 1
    assert "lingering is off" in capsys.readouterr().err


def test_service_status_fails_closed_without_user_manager(
    fake_systemd: FakeSystemd, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_systemd.user_manager_ok = False

    assert main(["service", "status"]) == 2
    assert "user manager" in capsys.readouterr().err


def test_service_without_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["service"])
    assert exc_info.value.code == 2


_OPERATOR_PASSWORD = "synthetic-operator-passphrase"


def _operator_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    data_dir = tmp_path / "data-dir"
    secrets_file = tmp_path / "config" / "secrets.toml"
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(secrets_file))
    return data_dir, secrets_file


def _patch_tty_and_passwords(
    monkeypatch: pytest.MonkeyPatch, *answers: str, tty: bool = True
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty)
    queue = list(answers)
    monkeypatch.setattr("carchive.cli.getpass.getpass", lambda _prompt="": queue.pop(0))


def test_operator_set_password_succeeds_and_keeps_accounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, secrets_file = _operator_env(tmp_path, monkeypatch)
    write_credentials(secrets_file, "audi", {"user": "me", "password": "pw"}, overwrite=False)
    _patch_tty_and_passwords(monkeypatch, _OPERATOR_PASSWORD, _OPERATOR_PASSWORD)

    exit_code = main(["operator", "set-password"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "password set; all sessions revoked" in captured.out
    assert _OPERATOR_PASSWORD not in captured.out + captured.err
    assert load_operator_hash(secrets_file) is not None
    assert stat.S_IMODE(secrets_file.stat().st_mode) == 0o600
    assert load_secrets(secrets_file) == {"audi": {"user": "me", "password": "pw"}}


def test_operator_set_password_policy_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, secrets_file = _operator_env(tmp_path, monkeypatch)
    _patch_tty_and_passwords(monkeypatch, "short", "short")

    exit_code = main(["operator", "set-password"])

    assert exit_code == 1
    assert "at least 16" in capsys.readouterr().err
    assert not secrets_file.exists()


def test_operator_set_password_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, secrets_file = _operator_env(tmp_path, monkeypatch)
    _patch_tty_and_passwords(monkeypatch, _OPERATOR_PASSWORD, _OPERATOR_PASSWORD + "x")

    exit_code = main(["operator", "set-password"])

    assert exit_code == 1
    assert "do not match" in capsys.readouterr().err
    assert not secrets_file.exists()


def test_operator_set_password_without_tty_never_reads_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir, secrets_file = _operator_env(tmp_path, monkeypatch)
    _patch_tty_and_passwords(monkeypatch, tty=False)

    exit_code = main(["operator", "set-password"])

    assert exit_code == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert not secrets_file.exists()
    assert not data_dir.exists()


def test_operator_set_password_refuses_while_data_dir_is_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir, secrets_file = _operator_env(tmp_path, monkeypatch)
    _patch_tty_and_passwords(monkeypatch, _OPERATOR_PASSWORD, _OPERATOR_PASSWORD)

    with DataDirLock(data_dir):
        exit_code = main(["operator", "set-password"])

    assert exit_code == 1
    assert "locked" in capsys.readouterr().err
    assert not secrets_file.exists()


def test_operator_set_password_fails_on_corrupt_secrets_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, secrets_file = _operator_env(tmp_path, monkeypatch)
    secrets_file.parent.mkdir(parents=True)
    secrets_file.write_text("= = =")
    secrets_file.chmod(0o600)
    _patch_tty_and_passwords(monkeypatch, _OPERATOR_PASSWORD, _OPERATOR_PASSWORD)

    exit_code = main(["operator", "set-password"])

    assert exit_code == 2
    assert "invalid secrets file" in capsys.readouterr().err
    assert secrets_file.read_text() == "= = ="


def _migrate_db(data_dir: Path) -> Path:
    """Migrate the database to head via `db upgrade`, for operator fallback-path tests."""
    assert main(["db", "upgrade"]) == 0
    return data_dir / "carchive.sqlite3"


def _stamp_db_behind_head(db_path: Path) -> None:
    """Rewrite the migrated database's stamped revision to an older one."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE alembic_version SET version_num = '0002'")


def test_operator_set_password_succeeds_while_locked_when_db_is_on_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir, secrets_file = _operator_env(tmp_path, monkeypatch)
    _migrate_db(data_dir)
    capsys.readouterr()
    _patch_tty_and_passwords(monkeypatch, _OPERATOR_PASSWORD, _OPERATOR_PASSWORD)

    def _fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("must not migrate while the data directory is locked by a server")

    monkeypatch.setattr("carchive.cli._upgrade_with_backup_sync", _fail_if_called)

    with DataDirLock(data_dir):
        exit_code = main(["operator", "set-password"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "password set; all sessions revoked" in captured.out
    assert load_operator_hash(secrets_file) is not None


def test_operator_set_password_refuses_while_locked_when_db_is_behind_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir, secrets_file = _operator_env(tmp_path, monkeypatch)
    db_path = _migrate_db(data_dir)
    _stamp_db_behind_head(db_path)
    capsys.readouterr()
    _patch_tty_and_passwords(monkeypatch, _OPERATOR_PASSWORD, _OPERATOR_PASSWORD)

    with DataDirLock(data_dir):
        exit_code = main(["operator", "set-password"])

    assert exit_code == 1
    assert "locked" in capsys.readouterr().err
    assert not secrets_file.exists()


def test_operator_setup_token_subcommand_no_longer_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir, _ = _operator_env(tmp_path, monkeypatch)

    with pytest.raises(SystemExit) as exc_info:
        main(["operator", "setup-token"])

    assert exc_info.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert not (data_dir / "setup_token").exists()


def test_operator_without_subcommand_errors(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["operator"])

    assert exc_info.value.code == 2
    assert "requires a subcommand: set-password" in capsys.readouterr().err


# --- backup credentials and encryption ---------------------------------------------

_BACKUP_PASSPHRASE = "an example passphrase"


@pytest.fixture
def backup_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A data dir with a migrated database, credential files and a passphrase file."""
    monkeypatch.setattr(backup_module, "DEFAULT_TIME_COST", 1)
    monkeypatch.setattr(backup_module, "DEFAULT_MEMORY_COST", 64)
    monkeypatch.setattr(backup_module, "DEFAULT_PARALLELISM", 1)
    data_dir = tmp_path / "data-dir"
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "secrets.toml").write_bytes(b"[credentials]\n")
    (cfg / "vault.key").write_bytes(bytes(range(32)))
    passphrase_file = cfg / "backup-passphrase"
    passphrase_file.write_text(_BACKUP_PASSPHRASE + "\n")
    for name in ("secrets.toml", "vault.key", "backup-passphrase"):
        (cfg / name).chmod(0o600)
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CARCHIVE_SECRETS_FILE", str(cfg / "secrets.toml"))
    assert main(["db", "upgrade"]) == 0
    return data_dir


def _use_passphrase_file(monkeypatch: pytest.MonkeyPatch, backup_env: Path) -> None:
    monkeypatch.setenv(
        "CARCHIVE_BACKUP_PASSPHRASE_FILE", str(backup_env.parent / "cfg" / "backup-passphrase")
    )


def test_backup_create_encrypted_with_credentials_then_list_verify_restore(
    backup_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_passphrase_file(monkeypatch, backup_env)
    capsys.readouterr()

    assert main(["backup", "create", "--encrypt", "--include-credentials"]) == 0
    archive = next((backup_env / "backups").glob("carchive-*.tar.gz.enc"))
    capsys.readouterr()
    assert main(["backup", "list"]) == 0
    list_out = capsys.readouterr().out
    assert main(["backup", "verify", str(archive)]) == 0
    capsys.readouterr()
    secrets = backup_env.parent / "cfg" / "secrets.toml"
    secrets.write_bytes(b"changed")
    assert main(["backup", "restore", str(archive)]) == 0
    hint = capsys.readouterr().out
    assert main(["backup", "restore", str(archive), "--restore-credentials"]) == 1
    refused = capsys.readouterr().err
    assert (
        main(
            ["backup", "restore", str(archive), "--restore-credentials", "--overwrite-credentials"]
        )
        == 0
    )

    assert "encrypted=yes  credentials=unknown  verified" in list_out
    assert "--restore-credentials" in hint
    assert "already exists" in refused
    assert secrets.read_bytes() == b"[credentials]\n"
    assert list(secrets.parent.glob("secrets.toml.before-restore-*"))
    assert _BACKUP_PASSPHRASE not in list_out + hint + refused


def test_backup_create_refuses_credentials_without_encryption(
    backup_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()

    exit_code = main(["backup", "create", "--include-credentials"])

    assert exit_code == 1
    assert "unencrypted" in capsys.readouterr().err
    assert not list((backup_env / "backups").glob("carchive-*"))


def test_backup_create_allow_plaintext_credentials_warns(
    backup_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()

    exit_code = main(["backup", "create", "--include-credentials", "--allow-plaintext-credentials"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "warning" in captured.err
    assert list((backup_env / "backups").glob("carchive-*.tar.gz"))


def test_backup_settings_are_overridden_by_flags(
    backup_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_passphrase_file(monkeypatch, backup_env)
    monkeypatch.setenv("CARCHIVE_BACKUP_ENCRYPT", "true")
    monkeypatch.setenv("CARCHIVE_BACKUP_INCLUDE_CREDENTIALS", "true")

    assert main(["backup", "create"]) == 0
    assert main(["backup", "create", "--no-include-credentials"]) == 0

    suffixes = {
        re.sub(r"^carchive-\d{8}T\d+Z", "", p.name)
        for p in (backup_env / "backups").glob("carchive-*")
        if not p.name.endswith(".sha256")
    }
    assert suffixes == {".tar.gz.enc", ".sqlite3.gz.enc"}


def test_backup_create_encrypt_without_passphrase_source_exits_2(
    backup_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    capsys.readouterr()

    exit_code = main(["backup", "create", "--encrypt"])

    assert exit_code == 2
    assert "passphrase" in capsys.readouterr().err


def test_backup_create_prompts_twice_on_a_terminal(
    backup_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter([_BACKUP_PASSPHRASE, _BACKUP_PASSPHRASE, _BACKUP_PASSPHRASE])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))

    assert main(["backup", "create", "--encrypt"]) == 0
    archive = next((backup_env / "backups").glob("carchive-*.sqlite3.gz.enc"))
    assert main(["backup", "verify", str(archive)]) == 0

    assert next(answers, None) is None


def test_backup_create_mismatching_prompts_exit_2(
    backup_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter([_BACKUP_PASSPHRASE, "something else entirely"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    capsys.readouterr()

    exit_code = main(["backup", "create", "--encrypt"])

    err = capsys.readouterr().err
    assert exit_code == 2
    assert "do not match" in err
    assert _BACKUP_PASSPHRASE not in err


def test_backup_verify_encrypted_without_passphrase_exits_2(
    backup_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_passphrase_file(monkeypatch, backup_env)
    assert main(["backup", "create", "--encrypt"]) == 0
    archive = next((backup_env / "backups").glob("carchive-*.enc"))
    monkeypatch.delenv("CARCHIVE_BACKUP_PASSPHRASE_FILE")
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    capsys.readouterr()

    verify_exit = main(["backup", "verify", str(archive)])
    list_exit = main(["backup", "list"])

    captured = capsys.readouterr()
    assert verify_exit == 2
    assert list_exit == 0
    assert "checksum ok, content not checked" in captured.out


def test_backup_restore_overwrite_requires_restore_credentials(
    backup_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as info:
        main(["backup", "restore", "whatever", "--overwrite-credentials"])

    assert info.value.code == 2
