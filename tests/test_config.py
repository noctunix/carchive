"""Tests for carchive.config."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

import carchive.config as config_module
from carchive.config import (
    ConfigError,
    InsecureSecretsError,
    SecretsLockTimeoutError,
    Settings,
    is_loopback_host,
    load_operator_hash,
    load_secrets,
    load_settings,
    remove_credentials,
    secrets_file_lock,
    write_credentials,
    write_operator_hash,
)
from carchive.core.redact import redact, register_secret


@pytest.fixture(autouse=True)
def _isolated_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every XDG/Carchive env var at a fresh tmp dir, never the real home."""
    monkeypatch.delenv("CARCHIVE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    for field in (
        "DATA_DIR",
        "BACKUP_DIR",
        "BACKUP_TIME",
        "BACKUP_KEEP_DAILY",
        "BACKUP_KEEP_WEEKLY",
        "BACKUP_KEEP_MONTHLY",
        "SECRETS_FILE",
        "BIND_HOST",
        "TRUSTED_PROXIES",
        "TLS_CERTFILE",
        "TLS_KEYFILE",
        "TLS_SELFSIGNED",
        "CONTAINER",
        "PORT",
        "FETCH_INTERVAL_MIN",
        "REQUEST_INTERVAL_S",
        "LOG_FORMAT",
    ):
        monkeypatch.delenv(f"CARCHIVE_{field}", raising=False)


def test_defaults_use_xdg_dirs(tmp_path: Path) -> None:
    settings = load_settings()

    assert settings.data_dir == tmp_path / "data" / "carchive"
    assert settings.secrets_file == tmp_path / "config" / "carchive" / "secrets.toml"
    assert settings.effective_backup_dir == settings.data_dir / "backups"
    assert settings.bind_host == "127.0.0.1"
    assert settings.port == 8470
    assert settings.fetch_interval_min == 15
    assert settings.log_format == "auto"


def test_missing_toml_file_is_fine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_CONFIG", str(tmp_path / "nonexistent.toml"))

    settings = load_settings()

    assert settings.port == 8470


def test_toml_overrides_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "carchive.toml"
    config_file.write_text('port = 9000\nbind_host = "127.0.0.2"\n')
    monkeypatch.setenv("CARCHIVE_CONFIG", str(config_file))

    settings = load_settings()

    assert settings.port == 9000
    assert settings.bind_host == "127.0.0.2"


def test_env_overrides_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "carchive.toml"
    config_file.write_text("port = 9000\n")
    monkeypatch.setenv("CARCHIVE_CONFIG", str(config_file))
    monkeypatch.setenv("CARCHIVE_PORT", "9100")

    settings = load_settings()

    assert settings.port == 9100


def test_tilde_is_expanded_in_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_DATA_DIR", "~/custom-carchive-data")

    settings = load_settings()

    assert "~" not in str(settings.data_dir)
    assert str(settings.data_dir).startswith(str(Path.home()))


def test_invalid_port_raises_config_error_naming_field_not_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CARCHIVE_PORT", "99999")

    with pytest.raises(ConfigError) as exc_info:
        load_settings()

    message = str(exc_info.value)
    assert "port" in message
    assert "99999" not in message


def test_invalid_fetch_interval_raises_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_FETCH_INTERVAL_MIN", "7")

    with pytest.raises(ConfigError) as exc_info:
        load_settings()

    message = str(exc_info.value)
    assert "fetch_interval_min" in message
    assert "7" not in message.split("field(s)")[-1].split("(config")[0]


def test_trusted_proxies_defaults_to_empty() -> None:
    settings = load_settings()

    assert settings.trusted_proxies == ()


def test_trusted_proxies_accepts_addresses_and_networks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_TRUSTED_PROXIES", '["127.0.0.1", "10.0.0.0/24"]')

    settings = load_settings()

    assert settings.trusted_proxies == ("127.0.0.1", "10.0.0.0/24")


def test_invalid_trusted_proxies_entry_raises_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CARCHIVE_TRUSTED_PROXIES", '["not-an-ip"]')

    with pytest.raises(ConfigError) as exc_info:
        load_settings()

    assert "trusted_proxies" in str(exc_info.value)


def test_backup_dir_none_means_data_dir_backups() -> None:
    settings = load_settings()

    assert settings.backup_dir is None
    assert settings.effective_backup_dir == settings.data_dir / "backups"


def test_backup_defaults() -> None:
    settings = load_settings()

    assert settings.backup_time == "03:30"
    assert settings.backup_keep_daily == 7
    assert settings.backup_keep_weekly == 4
    assert settings.backup_keep_monthly == 6


def test_backup_protection_defaults_are_database_only_and_unencrypted() -> None:
    settings = load_settings()

    assert settings.backup_include_credentials is False
    assert settings.backup_encrypt is False
    assert settings.backup_allow_plaintext_credentials is False
    assert settings.backup_passphrase_file is None


def test_backup_protection_settings_come_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CARCHIVE_BACKUP_INCLUDE_CREDENTIALS", "true")
    monkeypatch.setenv("CARCHIVE_BACKUP_ENCRYPT", "1")
    monkeypatch.setenv("CARCHIVE_BACKUP_PASSPHRASE_FILE", "~/passphrase")

    settings = load_settings()

    assert settings.backup_include_credentials is True
    assert settings.backup_encrypt is True
    assert settings.backup_passphrase_file == Path.home() / "passphrase"


def test_empty_backup_passphrase_file_means_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_BACKUP_PASSPHRASE_FILE", "")

    assert load_settings().backup_passphrase_file is None


def test_invalid_backup_time_raises_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_BACKUP_TIME", "25:99")

    with pytest.raises(ConfigError) as exc_info:
        load_settings()

    assert "backup_time" in str(exc_info.value)


def test_backup_keep_daily_must_be_at_least_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_BACKUP_KEEP_DAILY", "0")

    with pytest.raises(ConfigError) as exc_info:
        load_settings()

    assert "backup_keep_daily" in str(exc_info.value)


# --- secrets -----------------------------------------------------------------


def test_load_secrets_missing_file_returns_empty_dict(tmp_path: Path) -> None:
    assert load_secrets(tmp_path / "secrets.toml") == {}


def test_load_secrets_rejects_group_readable_file(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials.audi]\nuser = "me"\npassword = "pw"\n')
    secrets_file.chmod(0o640)

    with pytest.raises(InsecureSecretsError) as exc_info:
        load_secrets(secrets_file)

    assert "chmod 600" in str(exc_info.value)


def test_load_secrets_accepts_owner_only_file(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials.audi]\nuser = "me"\npassword = "pw"\n')
    secrets_file.chmod(0o600)

    secrets = load_secrets(secrets_file)

    assert secrets == {"audi": {"user": "me", "password": "pw"}}


def test_load_secrets_rejects_non_string_value(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text("[credentials.audi]\nport = 1234\n")
    secrets_file.chmod(0o600)

    with pytest.raises(ConfigError) as exc_info:
        load_secrets(secrets_file)

    message = str(exc_info.value)
    assert "audi" in message
    assert "1234" not in message


def test_load_secrets_rejects_non_table_credential(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials]\naudi = "not-a-table"\n')
    secrets_file.chmod(0o600)

    with pytest.raises(ConfigError):
        load_secrets(secrets_file)


def test_loaded_secrets_are_registered_for_redaction(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('[credentials.audi]\npassword = "unique-password-xyz"\n')
    secrets_file.chmod(0o600)

    load_secrets(secrets_file)

    assert redact("the password is unique-password-xyz") == "the password is ***"


def test_register_secret_is_available_standalone() -> None:
    register_secret("standalone-secret-value")

    assert redact("standalone-secret-value leaked") == "*** leaked"


def test_xdg_env_vars_are_honoured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom_data = tmp_path / "somewhere" / "data"
    monkeypatch.setenv("XDG_DATA_HOME", str(custom_data))

    settings = load_settings()

    assert settings.data_dir == custom_data / "carchive"


def test_env_vars_are_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("carchive_port", "9200")

    settings = load_settings()

    assert settings.port == 9200


def test_tls_is_off_by_default() -> None:
    settings = load_settings()

    assert settings.tls_certfile is None
    assert settings.tls_keyfile is None
    assert not settings.tls_enabled


def test_tls_paths_from_env_expand_the_home_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", "~/tls/cert.pem")
    monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", "~/tls/key.pem")

    settings = load_settings()

    assert settings.tls_certfile == tmp_path / "tls" / "cert.pem"
    assert settings.tls_keyfile == tmp_path / "tls" / "key.pem"
    assert settings.tls_enabled


def test_tls_paths_from_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "carchive.toml"
    config_file.write_text('tls_certfile = "/etc/c.pem"\ntls_keyfile = "/etc/k.pem"\n')
    monkeypatch.setenv("CARCHIVE_CONFIG", str(config_file))

    settings = load_settings()

    assert settings.tls_certfile == Path("/etc/c.pem")
    assert settings.tls_keyfile == Path("/etc/k.pem")


@pytest.mark.parametrize("name", ["CARCHIVE_TLS_CERTFILE", "CARCHIVE_TLS_KEYFILE"])
def test_tls_with_only_one_of_the_two_files_is_a_config_error(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(name, "/some/where.pem")

    with pytest.raises(ConfigError, match="tls_certfile and tls_keyfile must be set together"):
        load_settings()


def test_empty_tls_values_count_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", "")
    monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", " ")

    assert not load_settings().tls_enabled


# --- automatic self-signed certificate -------------------------------------------------

_FILES = {"tls_certfile": Path("/etc/c.pem"), "tls_keyfile": Path("/etc/k.pem")}


@pytest.mark.parametrize(
    ("bind_host", "container", "selfsigned", "files", "active"),
    [
        ("127.0.0.1", False, None, False, False),
        ("::1", False, None, False, False),
        ("localhost", False, None, False, False),
        ("0.0.0.0", False, None, False, True),
        ("192.168.1.20", False, None, False, True),
        ("::", False, None, False, True),
        ("nas.lan.test", False, None, False, True),
        ("0.0.0.0", True, None, False, True),
        ("127.0.0.1", True, None, False, True),
        ("0.0.0.0", True, False, False, False),
        ("0.0.0.0", True, None, True, False),
        ("0.0.0.0", False, None, True, False),
        ("127.0.0.1", False, True, False, True),
        ("0.0.0.0", True, True, False, True),
        ("0.0.0.0", False, True, False, True),
        ("0.0.0.0", False, False, False, False),
        ("127.0.0.1", False, False, False, False),
        ("0.0.0.0", False, False, True, False),
    ],
)
def test_selfsigned_auto_mode_decision_table(
    bind_host: str, container: bool, selfsigned: bool | None, files: bool, active: bool
) -> None:
    settings = Settings(
        bind_host=bind_host,
        container=container,
        tls_selfsigned=selfsigned,
        **(_FILES if files else {}),  # type: ignore[arg-type]
    )

    assert settings.tls_selfsigned_active is active
    assert settings.tls_files_configured is files
    assert settings.tls_enabled is (active or files)


def test_selfsigned_true_together_with_files_is_a_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "true")
    monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", "/etc/c.pem")
    monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", "/etc/k.pem")

    with pytest.raises(ConfigError, match="tls_selfsigned = true cannot be combined"):
        load_settings()


def test_selfsigned_false_together_with_files_is_fine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "false")
    monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", "/etc/c.pem")
    monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", "/etc/k.pem")

    settings = load_settings()

    assert settings.tls_files_configured
    assert not settings.tls_selfsigned_active


@pytest.mark.parametrize(
    ("raw", "expected"), [("true", True), ("1", True), ("false", False), ("0", False)]
)
def test_selfsigned_from_env(raw: str, expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", raw)

    assert load_settings().tls_selfsigned is expected


def test_selfsigned_empty_env_means_automatic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", " ")

    assert load_settings().tls_selfsigned is None


def test_selfsigned_from_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "carchive.toml"
    config_file.write_text("tls_selfsigned = true\n")
    monkeypatch.setenv("CARCHIVE_CONFIG", str(config_file))

    assert load_settings().tls_selfsigned_active


def test_selfsigned_garbage_is_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "sometimes")

    with pytest.raises(ConfigError, match="tls_selfsigned"):
        load_settings()


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("localhost", True),
        ("127.0.0.1", True),
        ("::1", True),
        ("0.0.0.0", False),
        ("x.test", False),
    ],
)
def test_is_loopback_host(host: str, loopback: bool) -> None:
    assert is_loopback_host(host) is loopback


_FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c3ludGhldGljc2FsdA$c3ludGhldGljaGFzaGZvcnRlc3Rz"


def _owner_only(path: Path, content: str) -> Path:
    path.write_text(content)
    path.chmod(0o600)
    return path


def test_operator_hash_missing_file_or_table_is_none(tmp_path: Path) -> None:
    assert load_operator_hash(tmp_path / "secrets.toml") is None
    secrets_file = _owner_only(tmp_path / "secrets.toml", '[credentials.audi]\nuser = "me"\n')
    assert load_operator_hash(secrets_file) is None


def test_write_operator_hash_roundtrip_keeps_credentials_and_mode(tmp_path: Path) -> None:
    secrets_file = tmp_path / "cfg" / "secrets.toml"
    write_credentials(secrets_file, "audi", {"user": "me", "password": "pw"}, overwrite=False)

    write_operator_hash(secrets_file, _FAKE_HASH)

    assert load_operator_hash(secrets_file) == _FAKE_HASH
    assert load_secrets(secrets_file) == {"audi": {"user": "me", "password": "pw"}}
    assert secrets_file.stat().st_mode & 0o777 == 0o600
    assert secrets_file.parent.stat().st_mode & 0o777 == 0o700


def test_credential_writes_preserve_the_operator_hash(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    write_operator_hash(secrets_file, _FAKE_HASH)

    write_credentials(secrets_file, "audi", {"user": "me", "password": "pw"}, overwrite=False)
    assert load_operator_hash(secrets_file) == _FAKE_HASH
    assert remove_credentials(secrets_file, "audi") is True
    assert load_operator_hash(secrets_file) == _FAKE_HASH


def test_write_operator_hash_replaces_previous_hash(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    write_operator_hash(secrets_file, _FAKE_HASH)

    write_operator_hash(secrets_file, _FAKE_HASH + "x")

    assert load_operator_hash(secrets_file) == _FAKE_HASH + "x"


def test_operator_hash_is_registered_for_redaction(tmp_path: Path) -> None:
    write_operator_hash(tmp_path / "secrets.toml", _FAKE_HASH)

    assert redact(f"hash {_FAKE_HASH} leaked") == "hash *** leaked"


def test_operator_hash_rejects_group_readable_file(tmp_path: Path) -> None:
    secrets_file = _owner_only(
        tmp_path / "secrets.toml", f'[operator]\npassword_hash = "{_FAKE_HASH}"\n'
    )
    secrets_file.chmod(0o640)

    with pytest.raises(InsecureSecretsError):
        load_operator_hash(secrets_file)
    with pytest.raises(InsecureSecretsError):
        write_operator_hash(secrets_file, _FAKE_HASH)


@pytest.mark.parametrize(
    "content",
    [
        "this is = = not toml",
        "[operator]\npassword_hash = 12345\n",
        'operator = "not-a-table"\n',
        '[operator]\npassword_hash = ""\n',
        '[operator]\nsurprise = "x"\n',
    ],
)
def test_operator_hash_fails_closed_on_malformed_file(tmp_path: Path, content: str) -> None:
    secrets_file = _owner_only(tmp_path / "secrets.toml", content)

    with pytest.raises(ConfigError) as exc_info:
        load_operator_hash(secrets_file)

    assert "12345" not in str(exc_info.value)


def test_write_operator_hash_refuses_to_overwrite_a_malformed_file(tmp_path: Path) -> None:
    secrets_file = _owner_only(tmp_path / "secrets.toml", "garbage = = =")

    with pytest.raises(ConfigError):
        write_operator_hash(secrets_file, _FAKE_HASH)

    assert secrets_file.read_text() == "garbage = = ="


# --- secrets_file_lock --------------------------------------------------------------


def test_secrets_file_lock_serializes_two_threads(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    events: list[str] = []

    def hold_briefly(name: str, delay: float) -> None:
        with secrets_file_lock(secrets_file, timeout_s=2.0):
            events.append(f"{name}-enter")
            time.sleep(delay)
            events.append(f"{name}-exit")

    first = threading.Thread(target=hold_briefly, args=("first", 0.2))
    second = threading.Thread(target=hold_briefly, args=("second", 0.0))
    first.start()
    time.sleep(0.05)  # give the first thread time to actually acquire the lock first
    second.start()
    first.join()
    second.join()

    assert events == ["first-enter", "first-exit", "second-enter", "second-exit"]


def test_secrets_file_lock_times_out_while_another_thread_holds_it(tmp_path: Path) -> None:
    secrets_file = tmp_path / "secrets.toml"
    holder_ready = threading.Event()
    release_holder = threading.Event()

    def hold_until_released() -> None:
        with secrets_file_lock(secrets_file, timeout_s=2.0):
            holder_ready.set()
            release_holder.wait(timeout=2.0)

    holder = threading.Thread(target=hold_until_released)
    holder.start()
    holder_ready.wait(timeout=2.0)
    try:
        with (
            pytest.raises(SecretsLockTimeoutError, match=r"\.lock"),
            secrets_file_lock(secrets_file, timeout_s=0.1),
        ):
            pass
    finally:
        release_holder.set()
        holder.join()


def test_secrets_file_lock_file_is_owner_only(tmp_path: Path) -> None:
    secrets_file = tmp_path / "cfg" / "secrets.toml"

    with secrets_file_lock(secrets_file):
        lock_path = secrets_file.with_name(secrets_file.name + ".lock")
        assert lock_path.stat().st_mode & 0o777 == 0o600
        assert lock_path.parent.stat().st_mode & 0o777 == 0o700


def test_concurrent_writers_do_not_lose_each_others_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A credential write and an operator-hash write racing each other both land."""
    secrets_file = tmp_path / "secrets.toml"
    original_write = config_module._write_secrets_atomically

    def slow_write(*args: object, **kwargs: object) -> None:
        # Widens the race window between the lock-protected read and the write, so a
        # missing lock would reliably show up as a lost update instead of only rarely.
        time.sleep(0.05)
        original_write(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(config_module, "_write_secrets_atomically", slow_write)

    credential_thread = threading.Thread(
        target=write_credentials,
        args=(secrets_file, "audi", {"user": "me", "password": "pw"}),
        kwargs={"overwrite": False},
    )
    hash_thread = threading.Thread(target=write_operator_hash, args=(secrets_file, _FAKE_HASH))
    credential_thread.start()
    hash_thread.start()
    credential_thread.join()
    hash_thread.join()

    assert load_secrets(secrets_file) == {"audi": {"user": "me", "password": "pw"}}
    assert load_operator_hash(secrets_file) == _FAKE_HASH
