"""Tests for credential inclusion, encryption and restore of credentials in the backup service."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import sqlite3
import stat
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from structlog.testing import capture_logs

from carchive.core.redact import SecretRegistry
from carchive.services import backup as backup_module
from carchive.services.backup import (
    BackupError,
    BackupOptions,
    BackupService,
    PassphraseUnavailableError,
    read_passphrase_file,
)
from carchive.storage.migrate import upgrade_to_head

_NOW = datetime(2026, 10, 22, 3, 0, 0, tzinfo=UTC)
_PASS = "an example passphrase"
_SECRETS = b'[credentials.main]\nuser = "user@example.org"\npassword = "enc:v2:abcdef"\n'
_KEY = bytes(range(32))


@pytest.fixture(autouse=True)
def _cheap_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup_module, "DEFAULT_TIME_COST", 1)
    monkeypatch.setattr(backup_module, "DEFAULT_MEMORY_COST", 64)
    monkeypatch.setattr(backup_module, "DEFAULT_PARALLELISM", 1)


def _write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


async def _make_db(path: Path, marker: int = 4242) -> None:
    await upgrade_to_head(path)
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {marker}")
    conn.close()


def _marker(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _make_secrets(directory: Path) -> Path:
    secrets_path = directory / "secrets.toml"
    _write_private(secrets_path, _SECRETS)
    _write_private(directory / "vault.key", _KEY)
    return secrets_path


def _service(
    tmp_path: Path,
    *,
    include: bool = False,
    encrypt: bool = False,
    allow_plaintext: bool = False,
    passphrase: str | None = _PASS,
    clock: datetime = _NOW,
    secrets_path: Path | None = None,
    backup_dir: Path | None = None,
    db_path: Path | None = None,
) -> BackupService:
    options = BackupOptions(
        include_credentials=include,
        encrypt=encrypt,
        allow_plaintext_credentials=allow_plaintext,
        secrets_path=secrets_path
        if secrets_path is not None
        else tmp_path / "cfg" / "secrets.toml",
        passphrase=(lambda: passphrase) if passphrase is not None else None,
    )
    return BackupService(
        db_path or tmp_path / "data" / "carchive.sqlite3",
        backup_dir or tmp_path / "backups",
        None,
        clock=lambda: clock,
        options=options,
    )


async def _prepared(tmp_path: Path) -> tuple[Path, Path]:
    db_path = tmp_path / "data" / "carchive.sqlite3"
    db_path.parent.mkdir(parents=True)
    await _make_db(db_path)
    return db_path, _make_secrets(tmp_path / "cfg")


def _archive_with_members(path: Path, members: list[tuple[str, bytes, bytes]]) -> None:
    """Write a gzip tar with `(name, data, typeflag)` members plus a checksum sidecar."""
    with gzip.open(path, "wb") as gz, tarfile.open(fileobj=gz, mode="w|") as tar:
        for name, data, typeflag in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.type = typeflag
            tar.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")


@pytest.mark.parametrize(
    ("include", "encrypt", "suffix"),
    [
        (False, False, ".sqlite3.gz"),
        (True, False, ".tar.gz"),
        (False, True, ".sqlite3.gz.enc"),
        (True, True, ".tar.gz.enc"),
    ],
)
async def test_all_four_variants_round_trip(
    tmp_path: Path, include: bool, encrypt: bool, suffix: str
) -> None:
    db_path, secrets_path = await _prepared(tmp_path)
    service = _service(
        tmp_path, include=include, encrypt=encrypt, allow_plaintext=True, secrets_path=secrets_path
    )

    path = await service.create()

    assert path.name.endswith(suffix)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    service.verify(path)
    (listed,) = service.list_backups()
    assert listed.encrypted is encrypt
    assert listed.credentials is (None if encrypt else include)
    if encrypt:
        assert b"SQLite format 3" not in path.read_bytes()
        assert _SECRETS not in path.read_bytes()

    target = tmp_path / "restored"
    target.mkdir()
    target_secrets = target / "cfg" / "secrets.toml"
    restorer = _service(tmp_path, secrets_path=target_secrets, backup_dir=tmp_path / "backups")
    result = await restorer.restore(path, target / "carchive.sqlite3", restore_credentials=include)

    assert _marker(target / "carchive.sqlite3") == 4242
    assert result.credentials_available is include
    assert result.credentials_restored is include
    if include:
        assert target_secrets.read_bytes() == _SECRETS
        assert (target_secrets.parent / "vault.key").read_bytes() == _KEY
        assert stat.S_IMODE(target_secrets.stat().st_mode) == 0o600
        assert stat.S_IMODE((target_secrets.parent / "vault.key").stat().st_mode) == 0o600
    else:
        assert not target_secrets.exists()


async def test_restore_without_the_option_leaves_credentials_alone(tmp_path: Path) -> None:
    db_path, secrets_path = await _prepared(tmp_path)
    path = await _service(tmp_path, include=True, encrypt=True, secrets_path=secrets_path).create()
    (tmp_path / "restored").mkdir()
    target_secrets = tmp_path / "restored" / "cfg" / "secrets.toml"
    restorer = _service(tmp_path, secrets_path=target_secrets)

    result = await restorer.restore(path, tmp_path / "restored" / "carchive.sqlite3")

    assert result.credentials_available is True
    assert result.credentials_restored is False
    assert not target_secrets.exists()


async def test_credentials_without_encryption_are_refused(tmp_path: Path) -> None:
    _, secrets_path = await _prepared(tmp_path)
    service = _service(tmp_path, include=True, secrets_path=secrets_path)

    with pytest.raises(BackupError, match="unencrypted"):
        await service.create()

    assert service.list_backups() == []
    assert not any((tmp_path / "backups").iterdir())


async def test_allow_plaintext_credentials_overrides_with_a_warning(tmp_path: Path) -> None:
    _, secrets_path = await _prepared(tmp_path)
    service = _service(tmp_path, include=True, allow_plaintext=True, secrets_path=secrets_path)

    with capture_logs() as logs:
        path = await service.create()

    assert path.name.endswith(".tar.gz")
    assert any(
        entry["event"] == "backup.plaintext_credentials" and entry["log_level"] == "warning"
        for entry in logs
    )


@pytest.mark.parametrize("problem", ["missing_key", "missing_secrets", "open_mode", "symlink"])
async def test_include_credentials_fails_loudly_on_unusable_credential_files(
    tmp_path: Path, problem: str
) -> None:
    _, secrets_path = await _prepared(tmp_path)
    key_path = secrets_path.parent / "vault.key"
    if problem == "missing_key":
        key_path.unlink()
    elif problem == "missing_secrets":
        secrets_path.unlink()
    elif problem == "open_mode":
        secrets_path.chmod(0o644)
    else:
        key_path.unlink()
        key_path.symlink_to(secrets_path)
    service = _service(tmp_path, include=True, encrypt=True, secrets_path=secrets_path)

    with pytest.raises(BackupError):
        await service.create()

    assert not any(
        p.name.startswith(("carchive-", ".tmp-")) for p in (tmp_path / "backups").iterdir()
    )


async def test_encrypting_without_a_passphrase_fails(tmp_path: Path) -> None:
    await _prepared(tmp_path)
    service = _service(tmp_path, encrypt=True, passphrase=None)

    with pytest.raises(PassphraseUnavailableError):
        await service.create()


async def test_short_passphrase_is_rejected(tmp_path: Path) -> None:
    await _prepared(tmp_path)

    with pytest.raises(BackupError, match="at least"):
        await _service(tmp_path, encrypt=True, passphrase="short").create()


async def test_wrong_or_missing_passphrase_on_an_encrypted_archive(tmp_path: Path) -> None:
    await _prepared(tmp_path)
    path = await _service(tmp_path, encrypt=True).create()

    with pytest.raises(BackupError) as wrong:
        _service(tmp_path, passphrase="a different passphrase").verify(path)
    with pytest.raises(PassphraseUnavailableError):
        _service(tmp_path, passphrase=None).verify(path)

    assert "different passphrase" not in str(wrong.value)
    _service(tmp_path, passphrase=None).verify(path, content=False)


async def test_restore_with_a_wrong_passphrase_changes_nothing(tmp_path: Path) -> None:
    db_path, _ = await _prepared(tmp_path)
    path = await _service(tmp_path, encrypt=True).create()
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA user_version = 7")
    conn.close()

    with pytest.raises(BackupError):
        await _service(tmp_path, passphrase="a different passphrase").restore(path, db_path)

    assert _marker(db_path) == 7
    assert not list(db_path.parent.glob("*before-restore*"))
    assert not list(db_path.parent.glob(".tmp-*"))


async def test_tampered_encrypted_archive_fails_even_with_a_fixed_checksum(tmp_path: Path) -> None:
    await _prepared(tmp_path)
    service = _service(tmp_path, encrypt=True)
    path = await service.create()
    data = bytearray(path.read_bytes())
    data[-5] ^= 0x01
    path.write_bytes(bytes(data))
    path.with_name(path.name + ".sha256").write_text(
        f"{hashlib.sha256(bytes(data)).hexdigest()}  {path.name}\n"
    )

    with pytest.raises(BackupError, match="cannot decrypt"):
        service.verify(path)


async def test_passphrase_never_appears_in_logs_or_errors(tmp_path: Path) -> None:
    _, secrets_path = await _prepared(tmp_path)
    service = _service(tmp_path, include=True, encrypt=True, secrets_path=secrets_path)
    texts: list[str] = []

    with capture_logs() as logs:
        path = await service.create()
        service.verify(path)
        with pytest.raises(BackupError) as info:
            _service(tmp_path, passphrase="a different passphrase").verify(path)
        texts.append(str(info.value))
    texts.extend(repr(entry) for entry in logs)

    assert not any(_PASS in text or "different passphrase" in text for text in texts)


async def test_restore_never_overwrites_credentials_without_permission(tmp_path: Path) -> None:
    db_path, secrets_path = await _prepared(tmp_path)
    path = await _service(tmp_path, include=True, encrypt=True, secrets_path=secrets_path).create()
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA user_version = 7")
    conn.close()
    _write_private(secrets_path, b"[credentials]\n")
    restorer = _service(tmp_path, secrets_path=secrets_path)

    with pytest.raises(BackupError, match="already exists"):
        await restorer.restore(path, db_path, restore_credentials=True)

    assert secrets_path.read_bytes() == b"[credentials]\n"
    assert _marker(db_path) == 7

    result = await restorer.restore(
        path, db_path, restore_credentials=True, overwrite_credentials=True
    )

    assert secrets_path.read_bytes() == _SECRETS
    assert stat.S_IMODE(secrets_path.stat().st_mode) == 0o600
    (aside,) = [p for p in result.previous_credentials if p.name.startswith("secrets.toml")]
    assert aside.read_bytes() == b"[credentials]\n"
    assert _marker(db_path) == 4242


async def test_restoring_credentials_from_an_archive_without_them_fails(tmp_path: Path) -> None:
    db_path, secrets_path = await _prepared(tmp_path)
    path = await _service(tmp_path, secrets_path=secrets_path).create()

    with pytest.raises(BackupError, match="no credentials"):
        await _service(tmp_path, secrets_path=secrets_path).restore(
            path, db_path, restore_credentials=True, overwrite_credentials=True
        )


async def test_existing_plain_archives_stay_readable_with_encryption_configured(
    tmp_path: Path,
) -> None:
    db_path, _ = await _prepared(tmp_path)
    legacy = await _service(tmp_path).create()

    modern = _service(tmp_path, include=True, encrypt=True, passphrase=None)
    modern.verify(legacy)
    result = await modern.restore(legacy, db_path)

    assert result.credentials_available is False
    assert _marker(db_path) == 4242


async def test_prune_handles_every_archive_variant(tmp_path: Path) -> None:
    _, secrets_path = await _prepared(tmp_path)
    variants = [(False, False), (True, True), (False, True), (True, True), (False, False)]
    for day, (include, encrypt) in enumerate(variants):
        await _service(
            tmp_path,
            include=include,
            encrypt=encrypt,
            secrets_path=secrets_path,
            clock=_NOW - timedelta(days=len(variants) - day),
        ).create()
    service = _service(tmp_path, secrets_path=secrets_path)
    service = BackupService(
        service._db_path,
        service._backup_dir,
        None,
        keep_daily=2,
        keep_weekly=1,
        keep_monthly=1,
        options=service._options,
    )

    deleted = service.prune(_NOW)

    remaining = service.list_backups()
    assert len(remaining) + len(deleted) == 5
    assert deleted
    assert all(not p.exists() and not p.with_name(p.name + ".sha256").exists() for p in deleted)
    assert all(b.path.with_name(b.path.name + ".sha256").exists() for b in remaining)


async def test_prune_skips_when_the_newest_encrypted_backup_cannot_be_checked(
    tmp_path: Path,
) -> None:
    await _prepared(tmp_path)
    for day in range(3):
        await _service(tmp_path, encrypt=True, clock=_NOW - timedelta(days=day)).create()
    service = BackupService(
        tmp_path / "data" / "carchive.sqlite3",
        tmp_path / "backups",
        None,
        keep_daily=1,
        keep_weekly=1,
        keep_monthly=1,
    )

    assert service.prune(_NOW) == []
    assert len(service.list_backups()) == 3


def test_list_ignores_lookalike_names(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    for name in (
        "carchive-20261022T030000Z.zip.enc",
        "carchive-20261022T030000Z.tar.gz.enc.bak",
        "carchive-20261022T030000Z.tar.enc",
    ):
        (backup_dir / name).write_bytes(b"x")

    assert _service(tmp_path).list_backups() == []


@pytest.mark.parametrize(
    "members",
    [
        [("../evil", b"x", tarfile.REGTYPE)],
        [("carchive.sqlite3", b"x", tarfile.REGTYPE), ("other", b"x", tarfile.REGTYPE)],
        [("carchive.sqlite3", b"x", tarfile.REGTYPE), ("carchive.sqlite3", b"x", tarfile.REGTYPE)],
        [("carchive.sqlite3", b"", tarfile.SYMTYPE)],
        [("secrets.toml", _SECRETS, tarfile.REGTYPE)],
        [("carchive.sqlite3", b"x", tarfile.REGTYPE), ("secrets.toml", _SECRETS, tarfile.REGTYPE)],
        [
            ("carchive.sqlite3", b"x", tarfile.REGTYPE),
            ("secrets.toml", b"x" * (1024 * 1024 + 1), tarfile.REGTYPE),
            ("vault.key", _KEY, tarfile.REGTYPE),
        ],
        [
            ("carchive.sqlite3", b"x", tarfile.REGTYPE),
            ("secrets.toml", b"not = [toml", tarfile.REGTYPE),
            ("vault.key", _KEY, tarfile.REGTYPE),
        ],
        [
            ("carchive.sqlite3", b"x", tarfile.REGTYPE),
            ("secrets.toml", _SECRETS, tarfile.REGTYPE),
            ("vault.key", b"short", tarfile.REGTYPE),
        ],
    ],
)
def test_hostile_tar_archives_are_rejected(
    tmp_path: Path, members: list[tuple[str, bytes, bytes]]
) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    path = backup_dir / "carchive-20261022T030000Z.tar.gz"
    _archive_with_members(path, members)

    with pytest.raises(BackupError):
        _service(tmp_path).verify(path)

    assert not any(p.name.startswith(".tmp-") for p in backup_dir.iterdir())


def test_unrecognized_gzip_content_is_rejected(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    path = backup_dir / "carchive-20261022T030000Z.sqlite3.gz"
    with gzip.open(path, "wb") as gz:
        gz.write(b"just text" * 100)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")

    with pytest.raises(BackupError, match="unrecognized"):
        _service(tmp_path).verify(path)


def test_passphrase_file_is_read_checked_and_registered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = SecretRegistry()
    monkeypatch.setattr(backup_module, "register_secret", registry.register)
    path = tmp_path / "pass"
    _write_private(path, b"a long passphrase\n")

    assert read_passphrase_file(path) == "a long passphrase"
    assert "***" in registry.redact("value a long passphrase here")


@pytest.mark.parametrize("problem", ["open_mode", "empty", "missing", "symlink", "huge", "binary"])
def test_passphrase_file_problems_are_reported(tmp_path: Path, problem: str) -> None:
    path = tmp_path / "pass"
    if problem == "open_mode":
        _write_private(path, b"a long passphrase", 0o644)
    elif problem == "empty":
        _write_private(path, b"\n")
    elif problem == "symlink":
        _write_private(tmp_path / "real", b"a long passphrase")
        path.symlink_to(tmp_path / "real")
    elif problem == "huge":
        _write_private(path, b"x" * 5000)
    elif problem == "binary":
        _write_private(path, b"\xff\xfe\xfd")

    with pytest.raises(PassphraseUnavailableError) as info:
        read_passphrase_file(path)

    assert "long passphrase" not in str(info.value)


def test_passphrase_file_with_crlf(tmp_path: Path) -> None:
    path = tmp_path / "pass"
    _write_private(path, b"a long passphrase\r\n")

    assert read_passphrase_file(path) == "a long passphrase"
    assert os.stat(path).st_mode & 0o077 == 0
