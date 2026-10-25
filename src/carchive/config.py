"""Settings and secrets loading: TOML file + environment overrides, secrets file."""

from __future__ import annotations

import fcntl
import ipaddress
import os
import stat
import tempfile
import time
import tomllib
from collections.abc import Collection, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import tomli_w
from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from carchive.core.redact import register_secret
from carchive.core.vault import KEY_LENGTH, VaultError, generate_key, is_sealed, seal, unseal

_VALID_FETCH_INTERVALS = (5, 10, 15, 20, 30, 60)
_OPERATOR_HASH_KEY = "password_hash"
_VAULT_KEY_NAME = "vault.key"
_SEALED_FIELD = "password"
_SECRETS_LOCK_TIMEOUT_S = 5.0
_SECRETS_LOCK_POLL_S = 0.05


class SecretsLockTimeoutError(RuntimeError):
    """Raised when the secrets file lock is still held by another process after a timeout."""


def is_loopback_host(host: str) -> bool:
    """Return whether `host` is `localhost` or a loopback IP address (no DNS lookup)."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ConfigError(ValueError):
    """Raised for invalid or malformed configuration."""


class InsecureSecretsError(ValueError):
    """Raised when the secrets file is group- or world-accessible."""


def _xdg_dir(env_var: str, fallback: Path) -> Path:
    value = os.environ.get(env_var)
    return Path(value).expanduser() if value else fallback


def config_dir() -> Path:
    """Return the directory holding the config and secrets files.

    Determined by `$CARCHIVE_CONFIG`'s parent directory if set, else
    `$XDG_CONFIG_HOME/carchive`, falling back to `~/.config/carchive`.
    """
    config_file = os.environ.get("CARCHIVE_CONFIG")
    if config_file:
        return Path(config_file).expanduser().parent
    return _xdg_dir("XDG_CONFIG_HOME", Path.home() / ".config") / "carchive"


def config_file_path() -> Path:
    """Return the TOML config file path: `$CARCHIVE_CONFIG` or the default location."""
    config_file = os.environ.get("CARCHIVE_CONFIG")
    if config_file:
        return Path(config_file).expanduser()
    return config_dir() / "carchive.toml"


def default_data_dir() -> Path:
    """Return `$XDG_DATA_HOME/carchive`, falling back to `~/.local/share/carchive`."""
    return _xdg_dir("XDG_DATA_HOME", Path.home() / ".local" / "share") / "carchive"


def _default_secrets_file() -> Path:
    return config_dir() / "secrets.toml"


class Settings(BaseSettings):
    """Carchive's runtime configuration.

    Loaded with increasing precedence: field defaults, the TOML config file,
    then `CARCHIVE_<FIELD>` environment variables (case-insensitive).
    """

    model_config = SettingsConfigDict(env_prefix="carchive_", frozen=True)

    data_dir: Path = Field(default_factory=default_data_dir)
    backup_dir: Path | None = None
    backup_time: str = "03:30"
    backup_keep_daily: int = Field(default=7, ge=1)
    backup_keep_weekly: int = Field(default=4, ge=1)
    backup_keep_monthly: int = Field(default=6, ge=1)
    backup_include_credentials: bool = False
    """Add `secrets.toml` and `vault.key` to every backup (as a tar container)."""
    backup_encrypt: bool = False
    """Encrypt every backup with a passphrase."""
    backup_passphrase_file: Path | None = None
    """Owner-only file holding the backup passphrase, for unattended backups."""
    backup_allow_plaintext_credentials: bool = False
    """Permit `backup_include_credentials` without `backup_encrypt`: the key to the
    credential vault then lies next to the credentials in a readable archive."""
    secrets_file: Path = Field(default_factory=_default_secrets_file)
    bind_host: str = "127.0.0.1"
    port: int = Field(default=8470, ge=1, le=65535)
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "[::1]")
    trusted_proxies: tuple[str, ...] = ()
    """Socket peer addresses or networks (`ipaddress` syntax) allowed to set
    `X-Forwarded-For` for the login throttle's client key. Empty by default: without a
    known reverse proxy in front, no peer is trusted to name a different client."""
    container: bool = False
    """Set by `CARCHIVE_CONTAINER=1` in container images: the process listens on
    `0.0.0.0` so the container runtime can publish it. HTTPS with a self-signed
    certificate is on by default in this mode; only an explicit `tls_selfsigned = false`
    (TLS terminated by a proxy in front) allows the plain-HTTP bind, which `serve` logs
    as a warning. The host allowlist is unaffected."""
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    """PEM certificate chain and private key for serving HTTPS; both or neither."""
    tls_selfsigned: bool | None = None
    """Serve HTTPS with an automatically generated self-signed certificate. `None` means
    automatic: on when `container` is true or `bind_host` is not loopback, and no
    certificate files are configured. `True` forces it on (also on loopback), `False` turns it off.
    Configured certificate files always take precedence and exclude `True`."""
    raw_payload_retention_days: int | None = Field(default=30, ge=0)
    """How long a successfully parsed delivery's raw payload (the ZIP as the portal sent
    it) is kept after the one-time typed-value parse, beyond which `raw_payload` is
    cleared (the typed data points stay). `0` clears it as soon as a delivery parses,
    `None`/unset keeps it forever. Never applies to a delivery still `pending` or `failed`
    parsing, which need their raw payload for a future reparse."""
    fetch_interval_min: int = 15
    request_interval_s: float = Field(default=1.0, ge=0)
    log_format: Literal["auto", "console", "json"] = "auto"

    @field_validator("data_dir", "secrets_file", mode="after")
    @classmethod
    def _expand_path(cls, value: Path) -> Path:
        return value.expanduser()

    @field_validator("tls_certfile", "tls_keyfile", "backup_passphrase_file", mode="before")
    @classmethod
    def _empty_optional_path_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("raw_payload_retention_days", mode="before")
    @classmethod
    def _empty_retention_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("tls_selfsigned", mode="before")
    @classmethod
    def _empty_tls_selfsigned_is_automatic(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator(
        "backup_dir", "tls_certfile", "tls_keyfile", "backup_passphrase_file", mode="after"
    )
    @classmethod
    def _expand_optional_path(cls, value: Path | None) -> Path | None:
        return value.expanduser() if value is not None else None

    @field_validator("fetch_interval_min")
    @classmethod
    def _check_fetch_interval(cls, value: int) -> int:
        if value not in _VALID_FETCH_INTERVALS:
            raise ValueError(f"must be one of {', '.join(map(str, _VALID_FETCH_INTERVALS))}")
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _check_trusted_proxies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for entry in value:
            try:
                ipaddress.ip_address(entry)
            except ValueError:
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    raise ValueError("must be IP addresses or networks") from None
        return value

    @field_validator("backup_time")
    @classmethod
    def _check_backup_time(cls, value: str) -> str:
        try:
            datetime.strptime(value, "%H:%M")
        except ValueError:
            raise ValueError("must be a 24h time in the form HH:MM") from None
        return value

    @model_validator(mode="after")
    def _check_tls_pair(self) -> Settings:
        if (self.tls_certfile is None) != (self.tls_keyfile is None):
            raise ValueError("tls_certfile and tls_keyfile must be set together")
        if self.tls_selfsigned is True and self.tls_certfile is not None:
            raise ValueError(
                "tls_selfsigned = true cannot be combined with tls_certfile/tls_keyfile"
            )
        return self

    @property
    def tls_files_configured(self) -> bool:
        """Whether the operator provided a certificate and key (both are set)."""
        return self.tls_certfile is not None and self.tls_keyfile is not None

    @property
    def tls_selfsigned_active(self) -> bool:
        """Whether `serve` generates and uses a self-signed certificate."""
        if self.tls_files_configured:
            return False
        if self.tls_selfsigned is None:
            return self.container or not is_loopback_host(self.bind_host)
        return self.tls_selfsigned

    @property
    def tls_enabled(self) -> bool:
        """Whether `serve` speaks HTTPS: configured files or the generated certificate."""
        return self.tls_files_configured or self.tls_selfsigned_active

    @property
    def effective_backup_dir(self) -> Path:
        """`backup_dir` if set, else `data_dir / "backups"`."""
        return self.backup_dir if self.backup_dir is not None else self.data_dir / "backups"

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order the settings sources: init arguments, environment, then the TOML file.

        Earlier sources win, so environment variables override the TOML file. Dotenv and
        file-secret sources are deliberately not used.

        Args:
            settings_cls: the settings class being built.
            init_settings: values passed to the constructor.
            env_settings: `CARCHIVE_*` environment variables.
            dotenv_settings: unused.
            file_secret_settings: unused.

        Returns:
            The sources in precedence order.
        """
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings]
        toml_file = config_file_path()
        if toml_file.is_file():
            sources.append(TomlConfigSettingsSource(settings_cls, toml_file=toml_file))
        return tuple(sources)


def load_settings() -> Settings:
    """Load settings from defaults, the TOML config file and the environment.

    Returns:
        The validated `Settings`.

    Raises:
        ConfigError: if any field fails validation. The message names the
            invalid field(s) and the config file consulted, never the
            offending value.
    """
    try:
        return Settings()
    except ValidationError as exc:
        errors = exc.errors()
        fields = sorted({".".join(str(part) for part in e["loc"]) for e in errors if e["loc"]})
        # Cross-field validators carry no field location; their messages never hold values.
        problems = sorted(
            {str(e["msg"]).removeprefix("Value error, ") for e in errors if not e["loc"]}
        )
        details = [f"field(s) {', '.join(fields)}"] if fields else []
        details.extend(problems)
        raise ConfigError(
            f"invalid configuration for {'; '.join(details)} (config file: {config_file_path()})"
        ) from exc


def _read_secrets_document(path: Path) -> dict[str, Any]:
    """Read and parse the secrets file after checking its permissions.

    Args:
        path: path to the secrets file.

    Returns:
        The parsed TOML document, or `{}` if the file does not exist.

    Raises:
        InsecureSecretsError: if the file is group- or world-accessible.
        ConfigError: if the file is not valid TOML. The message carries no file content.
    """
    if not path.is_file():
        return {}

    mode = path.stat().st_mode
    if mode & 0o077:
        raise InsecureSecretsError(f"{path} is group/world-accessible; fix with: chmod 600 {path}")

    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError:
        raise ConfigError(f"invalid secrets file {path}: not valid TOML") from None


def _parse_credentials(data: Mapping[str, Any], path: Path) -> dict[str, dict[str, str]]:
    """Validate the `[credentials]` tables and return them as stored (possibly sealed)."""
    credentials = data.get("credentials", {})
    if not isinstance(credentials, dict):
        raise ConfigError(f"invalid secrets file {path}: 'credentials' must be a table")

    result: dict[str, dict[str, str]] = {}
    for ref, table in credentials.items():
        if not isinstance(table, dict):
            raise ConfigError(f"invalid secrets file {path}: credential {ref!r} must be a table")
        values: dict[str, str] = {}
        for key, value in table.items():
            if not isinstance(value, str):
                raise ConfigError(
                    f"invalid secrets file {path}: credential {ref!r} field {key!r} "
                    "must be a string"
                )
            values[key] = value
        result[str(ref)] = values
    return result


def vault_key_path(secrets_path: Path) -> Path:
    """Return the location of the vault key belonging to a secrets file.

    Args:
        secrets_path: path to the secrets file.

    Returns:
        `vault.key` in the secrets file's directory.
    """
    return secrets_path.parent / _VAULT_KEY_NAME


def _load_vault_key(secrets_path: Path) -> bytes | None:
    """Read the vault key, refusing anything but an owner-only regular file of exact size.

    Args:
        secrets_path: path to the secrets file whose key is wanted.

    Returns:
        The key, or `None` if no key file exists.

    Raises:
        ConfigError: if the key file is a symlink or not a regular file, is
            group/world-accessible, or does not hold exactly `KEY_LENGTH` bytes. The
            message never carries key content.
    """
    key_path = vault_key_path(secrets_path)
    try:
        # NOFOLLOW makes a symlink fail here (also a dangling one) instead of reading
        # through it; NONBLOCK keeps a FIFO from hanging the open.
        fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(
            f"cannot open vault key {key_path}: {exc.strerror}; it must be a regular file"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"vault key {key_path} is not a regular file")
        if info.st_mode & 0o077:
            raise ConfigError(
                f"vault key {key_path} is group/world-accessible; fix with: chmod 600 {key_path}"
            )
        key = os.read(fd, KEY_LENGTH + 1)
    finally:
        os.close(fd)
    if len(key) != KEY_LENGTH:
        raise ConfigError(f"vault key {key_path} must be exactly {KEY_LENGTH} bytes")
    return key


def _create_vault_key(secrets_path: Path) -> bytes:
    """Create the vault key owner-only without ever replacing an existing file.

    Args:
        secrets_path: path to the secrets file whose key is wanted.

    Returns:
        The new key, or the existing one if another process created it first.

    Raises:
        ConfigError: if the key cannot be written, or a key file that appeared meanwhile
            is invalid.
    """
    key_path = vault_key_path(secrets_path)
    key = generate_key()
    fd, tmp_name = tempfile.mkstemp(dir=key_path.parent, prefix=".tmp-vault-", suffix=".key")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        # A hard link fails if the target exists, where a rename would silently replace
        # a key that already protects stored values.
        try:
            os.link(tmp_name, key_path)
        except FileExistsError:
            existing = _load_vault_key(secrets_path)
            if existing is None:
                raise ConfigError(f"vault key {key_path} vanished while being created") from None
            return existing
        except OSError as exc:
            raise ConfigError(f"cannot create vault key {key_path}: {exc.strerror}") from None
    finally:
        Path(tmp_name).unlink(missing_ok=True)
    return key


def _require_vault_key(secrets_path: Path, *, may_create: bool) -> bytes:
    key = _load_vault_key(secrets_path)
    if key is not None:
        return key
    if may_create:
        return _create_vault_key(secrets_path)
    raise ConfigError(
        f"{secrets_path} holds encrypted credentials but the vault key "
        f"{vault_key_path(secrets_path)} is missing; restore it from your backup. If it is "
        "lost, the stored portal passwords are unrecoverable and must be entered again "
        "with `carchive account set-password`"
    )


def _decrypt_credentials(
    stored: Mapping[str, Mapping[str, str]], secrets_path: Path
) -> dict[str, dict[str, str]]:
    """Return `stored` with every sealed password decrypted; all values are registered.

    Only the `password` field is ever sealed; other fields are returned as stored.

    Raises:
        ConfigError: if sealed values exist but the key is missing or invalid, or a value
            fails authentication or is of an unsupported format. The message names the
            reference and field, never a value.
    """
    key: bytes | None = None
    result: dict[str, dict[str, str]] = {}
    for ref, fields in stored.items():
        decrypted: dict[str, str] = {}
        for name, value in fields.items():
            if name == _SEALED_FIELD and is_sealed(value):
                if key is None:
                    key = _require_vault_key(secrets_path, may_create=False)
                try:
                    value = unseal(key, ref, name, value)
                except VaultError as exc:
                    raise ConfigError(
                        f"cannot decrypt credential {ref!r} field {name!r} in {secrets_path}: "
                        f"{exc} (vault key {vault_key_path(secrets_path)})"
                    ) from None
            register_secret(value)
            decrypted[name] = value
        result[ref] = decrypted
    return result


def _seal_credentials(
    credentials: Mapping[str, Mapping[str, str]], secrets_path: Path, *, may_create_key: bool
) -> dict[str, dict[str, str]]:
    """Return `credentials` with every plaintext password sealed; sealed ones stay as they are."""
    key: bytes | None = None
    result: dict[str, dict[str, str]] = {}
    for ref, fields in credentials.items():
        sealed: dict[str, str] = {}
        for name, value in fields.items():
            if name == _SEALED_FIELD and not is_sealed(value):
                if key is None:
                    key = _require_vault_key(secrets_path, may_create=may_create_key)
                value = seal(key, ref, name, value)
            sealed[name] = value
        result[ref] = sealed
    return result


def _sealed_passwords(credentials: Mapping[str, Mapping[str, str]]) -> list[str]:
    return [
        fields[_SEALED_FIELD]
        for fields in credentials.values()
        if _SEALED_FIELD in fields and is_sealed(fields[_SEALED_FIELD])
    ]


def _has_sealed(credentials: Mapping[str, Mapping[str, str]]) -> bool:
    return bool(_sealed_passwords(credentials))


def _parse_operator(data: Mapping[str, Any], path: Path) -> dict[str, str]:
    operator = data.get("operator", {})
    if not isinstance(operator, dict):
        raise ConfigError(f"invalid secrets file {path}: 'operator' must be a table")
    values: dict[str, str] = {}
    for key, value in operator.items():
        if not isinstance(value, str):
            raise ConfigError(
                f"invalid secrets file {path}: operator field {key!r} must be a string"
            )
        values[key] = value
        register_secret(value)
    return values


def load_secrets(path: Path) -> dict[str, dict[str, str]]:
    """Load provider credentials from a `secrets.toml` file.

    Expected format: one `[credentials.<ref>]` table per credential, with string values
    only. A `password` stored as `enc:v2:` is decrypted with the vault key next to the file;
    a plaintext password and all other fields (such as `user`) are taken as they are. Every
    returned value is registered for log/error redaction. The operator's `[operator]` table
    is not part of the result.

    Args:
        path: path to the secrets file.

    Returns:
        A mapping from credential reference to its decrypted fields, or `{}` if the
        file does not exist.

    Raises:
        InsecureSecretsError: if the file is group- or world-accessible.
        ConfigError: if the file content is malformed, encrypted values exist but the
            vault key is missing or invalid, or a value fails authentication. The message
            names the credential reference and field, never the value.
    """
    return _decrypt_credentials(_parse_credentials(_read_secrets_document(path), path), path)


def load_operator_hash(path: Path) -> str | None:
    """Load the operator's password hash from the `[operator]` table of the secrets file.

    Args:
        path: path to the secrets file.

    Returns:
        The stored hash, or `None` if the file or the `password_hash` entry does not exist.

    Raises:
        InsecureSecretsError: if the file is group- or world-accessible.
        ConfigError: if the file cannot be parsed or the `[operator]` table is malformed
            (so an unreadable file is never mistaken for "no password set"). The message
            never contains the hash.
    """
    operator = _parse_operator(_read_secrets_document(path), path)
    unknown = sorted(set(operator) - {_OPERATOR_HASH_KEY})
    if unknown:
        raise ConfigError(f"invalid secrets file {path}: unknown operator field(s) {unknown}")
    password_hash = operator.get(_OPERATOR_HASH_KEY)
    if password_hash is not None and not password_hash:
        raise ConfigError(f"invalid secrets file {path}: operator password_hash is empty")
    return password_hash


def write_operator_hash(path: Path, password_hash: str) -> None:
    """Store the operator's password hash in the secrets file, atomically.

    Sealed passwords are kept as they are; plaintext ones are sealed on the way. Reading the
    current document and rewriting it happen under `secrets_file_lock`, so this never loses
    a concurrent write by another process to the same file (such as a running server's own
    credential or token-refresh writes).

    Args:
        path: the secrets file to update; created owner-only if missing.
        password_hash: the encoded password hash to store.

    Raises:
        SecretsLockTimeoutError: if another process still holds the secrets file lock.
        InsecureSecretsError: if the secrets file exists but is group/world-accessible.
        ConfigError: if the secrets file exists but is malformed, or plaintext passwords
            need sealing and the vault key is missing (while sealed ones exist) or invalid.
    """
    register_secret(password_hash)
    with secrets_file_lock(path):
        data = _read_secrets_document(path)
        stored = _parse_credentials(data, path)
        _parse_operator(data, path)
        _write_secrets_atomically(
            path,
            stored,
            {_OPERATOR_HASH_KEY: password_hash},
            may_create_key=not _has_sealed(stored),
        )


@contextmanager
def secrets_file_lock(path: Path, *, timeout_s: float = _SECRETS_LOCK_TIMEOUT_S) -> Iterator[None]:
    """Serialize one read-modify-write on the secrets file against every other writer.

    Takes an exclusive `fcntl.flock` on `<path>.lock`, blocking (via short polling, since
    `flock` has no native timeout) until it is acquired or `timeout_s` elapses. This is
    deliberately independent of `DataDirLock`: the read-modify-write it protects is a brief
    TOML rewrite, not the long-running work (migrations, a whole `serve` lifetime)
    `DataDirLock` guards, and the file has several short-lived writers (CLI commands, a
    running server's account and session handling) that must serialize against each other
    even while `DataDirLock` itself is free.

    Args:
        path: path to the secrets file whose read-modify-write is serialized. Its parent
            directory is created owner-only if it does not exist yet.
        timeout_s: how long to wait for the lock before giving up.

    Yields:
        Nothing; the caller's read-modify-write runs while this is held.

    Raises:
        SecretsLockTimeoutError: if another process still holds the lock after `timeout_s`.
    """
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not lock_path.exists():
        lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    handle = lock_path.open("a+")
    try:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise SecretsLockTimeoutError(
                        f"{lock_path} is still locked by another process after {timeout_s}s"
                    ) from None
                time.sleep(_SECRETS_LOCK_POLL_S)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _write_secrets_atomically(
    path: Path,
    credentials: Mapping[str, Mapping[str, str]],
    operator: Mapping[str, str],
    *,
    may_create_key: bool,
) -> None:
    """Rewrite the whole secrets file, atomically and owner-only.

    The caller must already hold `secrets_file_lock(path)`, since `credentials` and
    `operator` were computed from an earlier, separate read of the file: without the lock
    covering that whole read-modify-write, a second writer could read the same prior state
    in between and overwrite this call's result with its own merge, silently losing one of
    the two changes.

    Args:
        path: the secrets file to (re)write.
        credentials: every credential reference that should exist afterward, including
            ones already present and untouched by this write. Plaintext passwords are
            sealed here; passwords already sealed are written as they are.
        operator: the `[operator]` table that should exist afterward; empty omits it.
        may_create_key: whether a missing vault key may be generated. Must be `False`
            whenever the file being replaced held sealed values, since a new key would
            make them unreadable.

    Raises:
        ConfigError: if plaintext passwords need sealing and the vault key is missing (and
            may not be created) or invalid.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    document: dict[str, Any] = {
        "credentials": _seal_credentials(credentials, path, may_create_key=may_create_key)
    }
    if operator:
        document["operator"] = dict(operator)
    content = tomli_w.dumps(document)

    # `tempfile.mkstemp` always creates with mode 0600 regardless of the process umask.
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-secrets-", suffix=".toml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


class WriteOutcome(StrEnum):
    """What `write_credentials` actually did."""

    CREATED = "created"
    """No credential existed yet for this reference; it was written."""

    UNCHANGED = "unchanged"
    """A credential already existed with exactly these values; nothing was written."""

    CONFLICT = "conflict"
    """A credential already existed with different values and `overwrite` was False."""

    REPLACED = "replaced"
    """A credential already existed with different values and `overwrite` was True."""


def write_credentials(
    path: Path, ref: str, values: Mapping[str, str], *, overwrite: bool
) -> WriteOutcome:
    """Add or update one credential reference in the secrets file, atomically.

    Reads and decrypts the whole file, changes only `ref`'s entry and rewrites the file.
    Other references keep their stored form; plaintext passwords are sealed on the way, and
    the vault key is created if the file held no sealed passwords before. The read, the
    conflict check and the rewrite all happen under `secrets_file_lock`, so a concurrent
    writer (another process, or a running server) can never overwrite this call's result
    with a merge computed against the same now-stale state.

    Args:
        path: the secrets file to update.
        ref: the credential reference (`credential_ref`) to write.
        values: the field values to store for `ref`.
        overwrite: whether an existing, differing credential for `ref` may be replaced.

    Returns:
        What was actually done.

    Raises:
        SecretsLockTimeoutError: if another process still holds the secrets file lock.
        InsecureSecretsError: if the secrets file exists but is group/world-accessible.
        ConfigError: if the secrets file exists but is malformed, sealed values exist but
            the vault key is missing or invalid, or the password in `values` itself starts
            with the reserved `enc:` prefix.
    """
    if is_sealed(values.get(_SEALED_FIELD, "")):
        raise ConfigError("the password must not start with the reserved prefix 'enc:'")
    with secrets_file_lock(path):
        data = _read_secrets_document(path)
        stored = _parse_credentials(data, path)
        existing = _decrypt_credentials(stored, path)
        operator = _parse_operator(data, path)
        current = existing.get(ref)
        if current is not None:
            if dict(current) == dict(values):
                return WriteOutcome.UNCHANGED
            if not overwrite:
                return WriteOutcome.CONFLICT
            outcome = WriteOutcome.REPLACED
        else:
            outcome = WriteOutcome.CREATED

        merged: dict[str, Mapping[str, str]] = dict(stored)
        merged[ref] = dict(values)
        for value in values.values():
            register_secret(value)
        _write_secrets_atomically(path, merged, operator, may_create_key=not _has_sealed(stored))
    return outcome


def read_credential_fields(path: Path, ref: str) -> dict[str, str] | None:
    """Return the readable fields of one credential reference, without its password.

    Never needs the vault key, so it works after the key was lost.

    Args:
        path: the secrets file to read.
        ref: the credential reference.

    Returns:
        Every stored field of `ref` except `password`, or `None` if the file or the
        reference does not exist.

    Raises:
        InsecureSecretsError: if the secrets file exists but is group/world-accessible.
        ConfigError: if the secrets file is malformed.
    """
    fields = _parse_credentials(_read_secrets_document(path), path).get(ref)
    if fields is None:
        return None
    for value in fields.values():
        register_secret(value)
    return {name: value for name, value in fields.items() if name != _SEALED_FIELD}


def _stranded_refs(
    stored: Mapping[str, Mapping[str, str]], path: Path, replacing: Collection[str]
) -> list[str]:
    """Return references outside `replacing` whose encrypted password a new key would strand."""
    if _load_vault_key(path) is not None:
        return []
    return sorted(
        ref for ref, fields in stored.items() if ref not in replacing and _has_sealed({ref: fields})
    )


def _stranded_error(path: Path, stranded: Sequence[str]) -> ConfigError:
    return ConfigError(
        f"vault key {vault_key_path(path)} is missing and {len(stranded)} other "
        f"reference(s) ({', '.join(stranded)}) still hold encrypted passwords that cannot be "
        "read; a new key is only created once none are left. Run `carchive account "
        "set-password` without a label to replace all of them in one go"
    )


def unreadable_credential_refs(path: Path) -> list[str]:
    """Return the references whose encrypted password cannot be decrypted.

    All of them if the vault key is missing; otherwise those failing authentication with it.

    Args:
        path: the secrets file to inspect.

    Returns:
        The sorted references, empty if every password is readable or none is encrypted.

    Raises:
        InsecureSecretsError: if the secrets file is group/world-accessible.
        ConfigError: if the secrets file is malformed or the vault key file is invalid.
    """
    stored = _parse_credentials(_read_secrets_document(path), path)
    sealed = {
        ref: fields[_SEALED_FIELD]
        for ref, fields in stored.items()
        if _SEALED_FIELD in fields and is_sealed(fields[_SEALED_FIELD])
    }
    if not sealed:
        return []
    key = _load_vault_key(path)
    if key is None:
        return sorted(sealed)
    unreadable: list[str] = []
    for ref, value in sealed.items():
        try:
            unseal(key, ref, _SEALED_FIELD, value)
        except VaultError:
            unreadable.append(ref)
    return sorted(unreadable)


def check_passwords_replaceable(path: Path, refs: Collection[str]) -> None:
    """Fail early if replacing only the passwords of `refs` would leave others unreadable.

    Args:
        path: the secrets file that would be updated.
        refs: the credential references whose passwords are about to be replaced.

    Raises:
        InsecureSecretsError: if the secrets file is group/world-accessible.
        ConfigError: if the file is malformed, the vault key is invalid, or the key is missing
            while other references still hold encrypted passwords (the message lists them).
    """
    stored = _parse_credentials(_read_secrets_document(path), path)
    stranded = _stranded_refs(stored, path, refs)
    if stranded:
        raise _stranded_error(path, stranded)


def replace_passwords(path: Path, passwords: Mapping[str, str]) -> None:
    """Replace the stored passwords of existing credential references in one atomic write.

    The old passwords are neither read nor decrypted, so this also works when the vault key
    is lost. A new key is generated in that case, but only if every encrypted password in
    the file is among the replaced ones; otherwise nothing is written. The read, the
    stranded-reference check and the rewrite all happen under `secrets_file_lock`, so a
    concurrent writer can never overwrite this call's result with a merge computed against
    the same now-stale state.

    Args:
        path: the secrets file to update.
        passwords: new plaintext password per credential reference.

    Raises:
        SecretsLockTimeoutError: if another process still holds the secrets file lock.
        InsecureSecretsError: if the secrets file is group/world-accessible.
        ConfigError: if `passwords` is empty, the file is malformed, a reference has no
            stored credentials, a password starts with the reserved `enc:` prefix, the vault
            key is invalid, or the key is missing while other references still hold
            encrypted passwords (the message lists them).
    """
    if not passwords:
        raise ConfigError("no passwords to replace")
    if any(is_sealed(password) for password in passwords.values()):
        raise ConfigError("the password must not start with the reserved prefix 'enc:'")
    with secrets_file_lock(path):
        data = _read_secrets_document(path)
        stored = _parse_credentials(data, path)
        operator = _parse_operator(data, path)
        for ref in passwords:
            if ref not in stored:
                raise ConfigError(f"no stored credentials for reference {ref!r}")

        stranded = _stranded_refs(stored, path, passwords.keys())
        if stranded:
            raise _stranded_error(path, stranded)
        may_create_key = _load_vault_key(path) is None

        merged: dict[str, Mapping[str, str]] = dict(stored)
        for ref, password in passwords.items():
            register_secret(password)
            merged[ref] = {**stored[ref], _SEALED_FIELD: password}
        _write_secrets_atomically(path, merged, operator, may_create_key=may_create_key)


def replace_password(path: Path, ref: str, password: str) -> None:
    """Replace the stored password of one existing credential reference, atomically.

    See `replace_passwords`.

    Args:
        path: the secrets file to update.
        ref: the credential reference whose password is replaced.
        password: the new password in plaintext.

    Raises:
        SecretsLockTimeoutError: if another process still holds the secrets file lock.
        InsecureSecretsError: if the secrets file is group/world-accessible.
        ConfigError: as for `replace_passwords`.
    """
    replace_passwords(path, {ref: password})


def remove_credentials(path: Path, ref: str) -> bool:
    """Remove one credential reference from the secrets file, atomically.

    Works without the vault key as long as no plaintext password remains to be sealed, so
    accounts can still be removed after the key was lost. The read and the rewrite happen
    under `secrets_file_lock`, so a concurrent writer can never overwrite this call's result
    with a merge computed against the same now-stale state.

    Args:
        path: the secrets file to update.
        ref: the credential reference to remove.

    Returns:
        `True` if `ref` existed and was removed, `False` if the file did not exist or
        had no entry for `ref` (and so was left untouched).

    Raises:
        SecretsLockTimeoutError: if another process still holds the secrets file lock.
        InsecureSecretsError: if the secrets file exists but is group/world-accessible.
        ConfigError: if the secrets file exists but is malformed, or plaintext passwords
            need sealing and the vault key is missing (while sealed ones exist) or invalid.
    """
    with secrets_file_lock(path):
        data = _read_secrets_document(path)
        stored = _parse_credentials(data, path)
        operator = _parse_operator(data, path)
        if ref not in stored:
            return False
        merged = {key: value for key, value in stored.items() if key != ref}
        _write_secrets_atomically(path, merged, operator, may_create_key=not _has_sealed(stored))
    return True


@dataclass(frozen=True)
class VaultStatus:
    """Summary of how the credentials in a secrets file are protected.

    Attributes:
        key_present: whether a valid vault key file exists.
        sealed_values: number of passwords stored encrypted.
        plaintext_values: number of passwords stored as plaintext.
    """

    key_present: bool
    sealed_values: int
    plaintext_values: int


def inspect_vault(path: Path) -> VaultStatus:
    """Report how the credentials in the secrets file are stored, without decrypting them.

    Args:
        path: path to the secrets file.

    Returns:
        The vault status; all zeros and no key if neither file exists.

    Raises:
        InsecureSecretsError: if the secrets file is group- or world-accessible.
        ConfigError: if the secrets file is malformed, the vault key is invalid, or sealed
            values exist but the key is missing.
    """
    stored = _parse_credentials(_read_secrets_document(path), path)
    passwords = [fields[_SEALED_FIELD] for fields in stored.values() if _SEALED_FIELD in fields]
    sealed = sum(1 for value in passwords if is_sealed(value))
    key = _load_vault_key(path)
    if sealed and key is None:
        _require_vault_key(path, may_create=False)
    return VaultStatus(
        key_present=key is not None,
        sealed_values=sealed,
        plaintext_values=len(passwords) - sealed,
    )
