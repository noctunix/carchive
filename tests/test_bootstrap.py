"""Tests for the live credential lookup used by the collector."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import carchive.bootstrap as bootstrap
from carchive.bootstrap import LiveCredentials
from carchive.config import (
    ConfigError,
    load_secrets,
    replace_password,
    vault_key_path,
    write_credentials,
)
from carchive.core.redact import redact

_OLD = "old-synthetic-portal-secret"
_NEW = "new-synthetic-portal-secret"


@pytest.fixture
def secrets_file(tmp_path: Path) -> Path:
    path = tmp_path / "cfg" / "secrets.toml"
    write_credentials(path, "audi", {"user": "me", "password": _OLD}, overwrite=False)
    return path


@pytest.fixture
def load_count(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []

    def counting(path: Path) -> dict[str, dict[str, str]]:
        calls.append(1)
        return load_secrets(path)

    monkeypatch.setattr(bootstrap, "load_secrets", counting)
    return calls


def test_returns_decrypted_credentials_and_reads_the_file_only_once_while_unchanged(
    secrets_file: Path, load_count: list[int]
) -> None:
    live = LiveCredentials(secrets_file)

    assert live("audi") == {"user": "me", "password": _OLD}
    assert live("audi") == {"user": "me", "password": _OLD}
    assert len(load_count) == 1


def test_picks_up_a_replaced_password_without_a_restart(secrets_file: Path) -> None:
    live = LiveCredentials(secrets_file)
    assert live("audi")["password"] == _OLD

    replace_password(secrets_file, "audi", _NEW)

    assert live("audi") == {"user": "me", "password": _NEW}
    assert redact(f"login failed for {_NEW}") == "login failed for ***"


def test_picks_up_a_new_reference_and_a_removed_one(secrets_file: Path) -> None:
    live = LiveCredentials(secrets_file)
    assert live("audi")["user"] == "me"

    write_credentials(secrets_file, "vw", {"user": "u2", "password": _NEW}, overwrite=False)
    assert live("vw")["user"] == "u2"

    secrets_file.unlink()
    with pytest.raises(KeyError):
        live("audi")


def test_unknown_reference_and_missing_file_raise_key_error(tmp_path: Path) -> None:
    live = LiveCredentials(tmp_path / "absent.toml")

    with pytest.raises(KeyError):
        live("audi")


def test_a_broken_file_fails_loudly_and_never_serves_old_values(secrets_file: Path) -> None:
    live = LiveCredentials(secrets_file)
    assert live("audi")["password"] == _OLD
    secrets_file.write_text("this is [not valid toml")
    secrets_file.chmod(0o600)

    with pytest.raises(ConfigError, match="cannot load portal credentials"):
        live("audi")
    with pytest.raises(ConfigError):
        live("audi")

    secrets_file.unlink()
    write_credentials(secrets_file, "audi", {"user": "me", "password": _NEW}, overwrite=False)
    assert live("audi")["password"] == _NEW


def test_an_insecure_file_fails_loudly_without_leaking_values(secrets_file: Path) -> None:
    live = LiveCredentials(secrets_file)
    assert live("audi")["password"] == _OLD
    os.chmod(secrets_file, 0o644)

    with pytest.raises(ConfigError, match="group/world-accessible") as exc_info:
        live("audi")

    assert _OLD not in str(exc_info.value)


def test_an_undecryptable_file_fails_loudly(secrets_file: Path) -> None:
    live = LiveCredentials(secrets_file)
    assert live("audi")["password"] == _OLD
    replace_password(secrets_file, "audi", _NEW)
    vault_key_path(secrets_file).unlink()

    with pytest.raises(ConfigError, match="vault key") as exc_info:
        live("audi")

    assert _NEW not in str(exc_info.value)


def test_an_unreadable_directory_entry_is_reported_as_a_config_error(
    tmp_path: Path,
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    live = LiveCredentials(locked / "secrets.toml")
    locked.chmod(0o000)
    try:
        with pytest.raises(ConfigError, match="cannot read portal credentials"):
            live("audi")
    finally:
        locked.chmod(0o700)
