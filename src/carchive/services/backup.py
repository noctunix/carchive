"""Backup service: create, verify, prune and restore local SQLite snapshots.

An archive is a gzip-compressed SQLite snapshot (`.sqlite3.gz`) or, when credentials are
included, a gzip-compressed tar holding the snapshot plus `secrets.toml` and `vault.key`
(`.tar.gz`). Either may be wrapped in the encrypted container of
`carchive.core.backup_crypto` (extra `.enc` suffix). Readers decide by content, not name.

Every step that touches the filesystem is written so a crash in the middle leaves no
half-written artifact behind: temporary files live under the backup directory (never
`/tmp`, so a rename at the end stays on the same filesystem and is atomic) and are removed
on any failure.
"""

from __future__ import annotations

import asyncio
import dataclasses
import gzip
import hashlib
import os
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import tomllib
import unicodedata
import zlib
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import BufferedIOBase, BytesIO
from pathlib import Path
from uuid import UUID, uuid4

import structlog
from argon2 import DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST
from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw

from carchive.config import Settings, vault_key_path
from carchive.core import backup_crypto
from carchive.core.redact import redact, register_secret
from carchive.core.vault import KEY_LENGTH
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.repositories import BackupRepository

logger = structlog.get_logger(__name__)

# Matches exactly the filenames this service creates; anything else in the backup
# directory is left alone by list_backups/prune, even if it looks similar. Both the
# second-only timestamps written before microseconds were added and the current
# microsecond ones are accepted, so archives from before that change stay listed.
_FILENAME_PATTERN = re.compile(r"^carchive-(\d{8}T\d{6}(?:\d{6})?Z)\.(sqlite3|tar)\.gz(\.enc)?$")
_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%S%fZ"
_LEGACY_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"
_LEGACY_TIMESTAMP_LENGTH = len("20000101T000000Z")

# A generous ceiling for a personal vehicle database, well above anything a real backup
# should ever reach; guards against a corrupted or tampered-with gzip header claiming an
# unbounded decompressed size.
_MAX_DECOMPRESSED_BYTES = 20 * 1024**3

_DB_MEMBER = "carchive.sqlite3"
_SECRETS_MEMBER = "secrets.toml"
_KEY_MEMBER = "vault.key"
_MAX_SECRETS_BYTES = 1024 * 1024
_MEMBER_LIMITS = {
    _DB_MEMBER: _MAX_DECOMPRESSED_BYTES,
    _SECRETS_MEMBER: _MAX_SECRETS_BYTES,
    _KEY_MEMBER: KEY_LENGTH,
}
_TAR_BLOCK = 512
# Slack allowed after the tar end marker (record padding) before the archive is rejected.
_TAR_TRAILER_LIMIT = 1024 * 1024
_SQLITE_MAGIC = b"SQLite format 3\x00"

MIN_PASSPHRASE_CHARS = 16
_MAX_PASSPHRASE_FILE_BYTES = 4096

PassphraseProvider = Callable[[], str]
"""Returns the backup passphrase, or raises `PassphraseUnavailableError`."""


class BackupError(RuntimeError):
    """Raised when creating, verifying or restoring a backup fails."""


class PassphraseUnavailableError(BackupError):
    """Raised when a backup needs a passphrase and none can be obtained."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_timestamp(raw: str) -> datetime:
    """Parse a timestamp matched by `_FILENAME_PATTERN`, legacy or current format."""
    fmt = _LEGACY_TIMESTAMP_FORMAT if len(raw) == _LEGACY_TIMESTAMP_LENGTH else _TIMESTAMP_FORMAT
    return datetime.strptime(raw, fmt).replace(tzinfo=UTC)


def _checksum_path(backup_path: Path) -> Path:
    return backup_path.with_name(backup_path.name + ".sha256")


def _sha256_of(path: Path) -> str:
    """Return the hex SHA-256 digest of `path`'s contents, read in bounded chunks."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _integrity_check(sqlite_path: Path) -> None:
    """Run `PRAGMA integrity_check` on a standalone SQLite file.

    Raises:
        BackupError: if the file is not a valid SQLite database, or the check result is
            anything other than the single row `ok`.
    """
    try:
        conn = sqlite3.connect(str(sqlite_path))
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"not a valid SQLite database: {exc}") from exc
    if rows != [("ok",)]:
        details = "; ".join(str(row[0]) for row in rows[:5])
        raise BackupError(f"integrity check failed: {details}")


def _vacuum_into(db_path: Path, dest_path: Path) -> None:
    """Write a consistent snapshot of `db_path` into the already-created `dest_path`.

    Runs against a plain `sqlite3` connection, separate from the application's async
    engine, so it works correctly even while that engine holds open WAL connections.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("VACUUM INTO ?", (str(dest_path),))
    finally:
        conn.close()


def _gzip_file(src: Path, dest: Path) -> None:
    """Compress `src` into the already-created `dest`, fsyncing before returning."""
    with dest.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb") as gz, src.open("rb") as source:
            for chunk in iter(lambda: source.read(1 << 20), b""):
                gz.write(chunk)
        raw.flush()
        os.fsync(raw.fileno())


def _decompress(src: Path, dest: Path) -> None:
    """Decompress gzip archive `src` into the already-created `dest`.

    Raises:
        BackupError: if the decompressed size exceeds `_MAX_DECOMPRESSED_BYTES`.
        gzip.BadGzipFile: if `src` is not a valid gzip stream.
        EOFError: if `src` is truncated.
    """
    written = 0
    with gzip.open(src, "rb") as gz, dest.open("wb") as out:
        while True:
            chunk = gz.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > _MAX_DECOMPRESSED_BYTES:
                raise BackupError(f"{src.name} exceeds the decompression size limit")
            out.write(chunk)


def _derive_key(passphrase: str, header: backup_crypto.Header) -> bytes:
    """Derive the block key from `passphrase` with the Argon2id parameters in `header`.

    Raises:
        BackupError: if the key derivation fails (e.g. the memory cannot be allocated).
    """
    try:
        return hash_secret_raw(
            unicodedata.normalize("NFC", passphrase).encode("utf-8"),
            header.salt,
            time_cost=header.time_cost,
            memory_cost=header.memory_cost,
            parallelism=header.parallelism,
            hash_len=backup_crypto.KEY_LENGTH,
            type=Type.ID,
        )
    except HashingError:
        raise BackupError("key derivation failed") from None


def encrypt_file(src: Path, dest: Path, passphrase: str) -> None:
    """Encrypt `src` into the already-created `dest`, fsyncing before returning.

    Args:
        src: the plaintext file.
        dest: the file to write the encrypted container to.
        passphrase: the passphrase the key is derived from.

    Raises:
        BackupError: if the key derivation fails.
        OSError: if reading or writing fails.
    """
    header = backup_crypto.parse_header(
        backup_crypto.build_header(
            os.urandom(backup_crypto.SALT_LENGTH),
            DEFAULT_TIME_COST,
            DEFAULT_MEMORY_COST,
            DEFAULT_PARALLELISM,
            os.urandom(backup_crypto.NONCE_PREFIX_LENGTH),
        )
    )
    encryptor = backup_crypto.BlockEncryptor(_derive_key(passphrase, header), header)
    with src.open("rb") as source, dest.open("wb") as out:
        out.write(header.raw)
        size = backup_crypto.BLOCK_SIZE
        block = source.read(size)
        while True:
            following = source.read(size) if len(block) == size else b""
            last = not following
            out.write(encryptor.encrypt(block, last=last))
            if last:
                break
            block = following
        out.flush()
        os.fsync(out.fileno())


def decrypt_file(src: Path, dest: Path, passphrase: str) -> None:
    """Decrypt the container `src` into the already-created `dest`.

    Args:
        src: the encrypted container.
        dest: the file to write the plaintext to; its content is meaningless after a
            failure.
        passphrase: the passphrase the key is derived from.

    Raises:
        BackupError: if `src` is not a supported container, the passphrase is wrong, or
            the data is damaged, truncated, reordered or extended. The message never
            says which of the latter, nor anything about the content.
        OSError: if reading or writing fails.
    """
    try:
        with src.open("rb") as source:
            header = backup_crypto.parse_header(source.read(backup_crypto.HEADER_LENGTH))
            decryptor = backup_crypto.BlockDecryptor(_derive_key(passphrase, header), header)
            with dest.open("wb") as out:
                block = source.read(backup_crypto.ENCRYPTED_BLOCK_SIZE)
                if not block:
                    raise backup_crypto.DecryptionError("no data blocks")
                while True:
                    full = len(block) == backup_crypto.ENCRYPTED_BLOCK_SIZE
                    following = source.read(backup_crypto.ENCRYPTED_BLOCK_SIZE) if full else b""
                    last = not following
                    out.write(decryptor.decrypt(block, last=last))
                    if last:
                        break
                    block = following
    except (backup_crypto.BackupFormatError, backup_crypto.DecryptionError) as exc:
        raise BackupError(f"cannot decrypt {src.name}: {exc}") from None


def _mkstemp_in(directory: Path, suffix: str) -> Path:
    """Create an empty, owner-only temp file in `directory` and return its path.

    `tempfile.mkstemp` always creates with mode 0600 regardless of the process umask, so
    the file is never briefly world- or group-readable even if the caller forgot to
    restrict its umask.
    """
    fd, name = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=suffix)
    os.close(fd)
    return Path(name)


def _read_private_file(path: Path, limit: int, label: str) -> bytes:
    """Read a small owner-only regular file without following symlinks.

    Args:
        path: the file to read.
        limit: the largest acceptable size in bytes.
        label: what the file is, for error messages.

    Returns:
        The file content.

    Raises:
        BackupError: if the file is missing, not a regular file, group/world-accessible
            or larger than `limit`. Messages never carry content.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise BackupError(f"{label} {path} does not exist") from None
    except OSError as exc:
        raise BackupError(f"cannot open {label} {path}: {exc.strerror}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BackupError(f"{label} {path} is not a regular file")
        if info.st_mode & 0o077:
            raise BackupError(
                f"{label} {path} is group/world-accessible; fix with: chmod 600 {path}"
            )
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise BackupError(f"{label} {path} is larger than {limit} bytes")
    return data


def read_passphrase_file(path: Path) -> str:
    """Read the backup passphrase from an owner-only file and register it for redaction.

    Args:
        path: the passphrase file; one trailing newline is ignored.

    Returns:
        The passphrase.

    Raises:
        PassphraseUnavailableError: if the file is missing, empty, not UTF-8, not an
            owner-only regular file or implausibly large.
    """
    try:
        raw = _read_private_file(path, _MAX_PASSPHRASE_FILE_BYTES, "passphrase file")
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PassphraseUnavailableError(f"passphrase file {path} is not valid UTF-8") from None
    except BackupError as exc:
        raise PassphraseUnavailableError(str(exc)) from None
    passphrase = text.removesuffix("\n").removesuffix("\r")
    if not passphrase:
        raise PassphraseUnavailableError(f"passphrase file {path} is empty")
    register_secret(passphrase)
    return passphrase


def _require_passphrase(provider: PassphraseProvider | None) -> str:
    if provider is None:
        raise PassphraseUnavailableError(
            "a passphrase is required but none is configured (set backup_passphrase_file)"
        )
    passphrase = provider()
    register_secret(passphrase)
    return passphrase


def _tar_gzip(snapshot: Path, extra: dict[str, bytes], dest: Path) -> None:
    """Write a gzip-compressed tar with the snapshot and `extra` members into `dest`.

    Member names are the fixed constants of this module; the tar carries no owner names,
    paths or timestamps beyond the write time.
    """
    now = int(datetime.now(UTC).timestamp())

    def info(name: str, size: int) -> tarfile.TarInfo:
        member = tarfile.TarInfo(name)
        member.size = size
        member.mode = 0o600
        member.mtime = now
        return member

    with dest.open("wb") as raw:
        with (
            gzip.GzipFile(fileobj=raw, mode="wb") as gz,
            tarfile.open(fileobj=gz, mode="w|", format=tarfile.GNU_FORMAT) as tar,
            snapshot.open("rb") as source,
        ):
            tar.addfile(info(_DB_MEMBER, snapshot.stat().st_size), source)
            for name, data in extra.items():
                tar.addfile(info(name, len(data)), BytesIO(data))
        raw.flush()
        os.fsync(raw.fileno())


def _tar_member_header(block: bytes) -> tuple[str, int] | None:
    """Parse one 512-byte tar header, returning `(name, size)` or `None` at the end marker.

    Only plain regular files with short ASCII names are accepted, so extended-header and
    long-name records (which tarfile would read into memory unbounded) never occur.

    Raises:
        BackupError: if the header is damaged or describes anything but a regular file.
    """
    if not any(block):
        return None
    try:
        recorded = int(block[148:156].split(b"\0")[0].strip() or b"x", 8)
    except ValueError:
        raise BackupError("corrupt tar header") from None
    if recorded != sum(block[:148]) + 8 * 0x20 + sum(block[156:]):
        raise BackupError("corrupt tar header")
    if block[156:157] not in (b"0", b"\0") or block[345:500].strip(b"\0"):
        raise BackupError("unexpected entry type in archive")
    try:
        name = block[:100].split(b"\0")[0].decode("ascii")
        size_field = block[124:136]
        if size_field[0] & 0x80:
            size = int.from_bytes(bytes([size_field[0] & 0x7F]) + size_field[1:], "big")
        else:
            size = int(size_field.split(b"\0")[0].strip() or b"0", 8)
    except (UnicodeDecodeError, ValueError):
        raise BackupError("corrupt tar header") from None
    return name, size


def _read_exact(stream: BufferedIOBase, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise BackupError("archive is truncated")
    return data


def _unpack_tar(stream: BufferedIOBase, db_dest: Path) -> dict[str, bytes]:
    """Read a tar produced by `_tar_gzip`: the snapshot goes to `db_dest`, the rest is returned.

    Raises:
        BackupError: if a member has an unexpected name, type or size, appears twice, or
            the database member is missing, or only one of the credential members is
            present, or the credentials are malformed.
    """
    seen: set[str] = set()
    extra: dict[str, bytes] = {}
    while (header := _tar_member_header(_read_exact(stream, _TAR_BLOCK))) is not None:
        name, size = header
        limit = _MEMBER_LIMITS.get(name)
        if limit is None or name in seen or size > limit:
            raise BackupError("unexpected member in archive")
        seen.add(name)
        remaining = size
        if name == _DB_MEMBER:
            with db_dest.open("wb") as out:
                while remaining:
                    chunk = _read_exact(stream, min(remaining, 1 << 20))
                    out.write(chunk)
                    remaining -= len(chunk)
        else:
            extra[name] = _read_exact(stream, size)
        _read_exact(stream, -size % _TAR_BLOCK)
    trailing = 0
    while chunk := stream.read(1 << 20):
        trailing += len(chunk)
        if trailing > _TAR_TRAILER_LIMIT:
            raise BackupError("unexpected data after the end of the archive")
    if _DB_MEMBER not in seen:
        raise BackupError("archive has no database")
    if set(extra) not in (set(), {_SECRETS_MEMBER, _KEY_MEMBER}):
        raise BackupError("archive holds an incomplete set of credentials")
    if _KEY_MEMBER in extra and len(extra[_KEY_MEMBER]) != KEY_LENGTH:
        raise BackupError("archive holds a malformed vault key")
    if _SECRETS_MEMBER in extra:
        try:
            tomllib.loads(extra[_SECRETS_MEMBER].decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            raise BackupError("archive holds a malformed secrets file") from None
    return extra


@contextmanager
def _workdir(parent: Path) -> Iterator[Path]:
    """Yield a fresh owner-only directory under `parent`, removed on exit."""
    path = Path(tempfile.mkdtemp(dir=parent, prefix=".tmp-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@dataclass(frozen=True, slots=True)
class _Unpacked:
    """A backup archive taken apart: the plain database file and any credential members."""

    db_path: Path
    credentials: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class RestoreResult:
    """The outcome of `BackupService.restore`.

    Attributes:
        previous_db: where the previous database was moved to, or `None` if there was none.
        credentials_available: whether the archive held `secrets.toml` and `vault.key`.
        credentials_restored: whether they were written back.
        previous_credentials: where replaced credential files were moved to.
    """

    previous_db: Path | None
    credentials_available: bool
    credentials_restored: bool
    previous_credentials: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class BackupOptions:
    """What a backup contains and how it is protected.

    Attributes:
        include_credentials: add `secrets.toml` and `vault.key` to new backups.
        encrypt: encrypt new backups.
        allow_plaintext_credentials: permit `include_credentials` without `encrypt`.
        secrets_path: the secrets file; `vault.key` is taken from its directory. Needed to
            include credentials and to restore them.
        passphrase: returns the passphrase when one is needed (encrypting, or reading an
            encrypted archive); `None` if none can be provided.
    """

    include_credentials: bool = False
    encrypt: bool = False
    allow_plaintext_credentials: bool = False
    secrets_path: Path | None = None
    passphrase: PassphraseProvider | None = None


def options_from_settings(
    settings: Settings, *, passphrase: PassphraseProvider | None = None
) -> BackupOptions:
    """Derive `BackupOptions` from the configuration.

    Args:
        settings: the loaded settings.
        passphrase: where the passphrase comes from; defaults to reading
            `backup_passphrase_file` on demand, or none if that is unset.

    Returns:
        The options.
    """
    if passphrase is None and settings.backup_passphrase_file is not None:
        passphrase_file = settings.backup_passphrase_file

        def passphrase() -> str:
            return read_passphrase_file(passphrase_file)

    return BackupOptions(
        include_credentials=settings.backup_include_credentials,
        encrypt=settings.backup_encrypt,
        allow_plaintext_credentials=settings.backup_allow_plaintext_credentials,
        secrets_path=settings.secrets_file,
        passphrase=passphrase,
    )


@dataclass(frozen=True, slots=True)
class BackupFile:
    """One backup archive found on disk, as named and timestamped by this service.

    Attributes:
        path: the archive file.
        created_at: the creation time encoded in the file name.
        size_bytes: the file size.
        encrypted: whether the file starts with the encrypted container magic.
        credentials: whether the archive holds `secrets.toml` and `vault.key`, as far as the
            file name tells; `None` (unknown) for encrypted archives, whose name is not
            authenticated.
    """

    path: Path
    created_at: datetime
    size_bytes: int
    encrypted: bool = False
    credentials: bool | None = False


class BackupService:
    """Creates, verifies, prunes and restores gzip-compressed SQLite snapshots.

    Args:
        db_path: the live database file to back up or to restore into.
        backup_dir: the directory holding backup archives and their checksum sidecars.
            Created with mode 0700 if it does not exist yet.
        db: the application's database, used to record the outcome of `create()` in the
            `backups` table; `None` to skip recording (verification and pruning never
            touch this table).
        clock: returns the current UTC time; overridable for tests.
        keep_daily: number of most recent distinct days to keep one backup from.
        keep_weekly: number of most recent distinct ISO weeks to keep one backup from.
        keep_monthly: number of most recent distinct months to keep one backup from.
        options: what new backups contain and how they are protected; also supplies the
            passphrase and secrets location for reading and restoring.
    """

    def __init__(
        self,
        db_path: Path,
        backup_dir: Path,
        db: Database | None,
        *,
        clock: Callable[[], datetime] = _utcnow,
        keep_daily: int = 7,
        keep_weekly: int = 4,
        keep_monthly: int = 6,
        options: BackupOptions | None = None,
    ) -> None:
        self._options = options or BackupOptions()
        self._db_path = db_path
        self._backup_dir = backup_dir
        self._db = db
        self._clock = clock
        self._keep_daily = keep_daily
        self._keep_weekly = keep_weekly
        self._keep_monthly = keep_monthly
        self._backups = BackupRepository()

    @classmethod
    @asynccontextmanager
    async def connect(
        cls,
        db_path: Path,
        backup_dir: Path,
        *,
        clock: Callable[[], datetime] = _utcnow,
        keep_daily: int = 7,
        keep_weekly: int = 4,
        keep_monthly: int = 6,
        options: BackupOptions | None = None,
    ) -> AsyncIterator[BackupService]:
        """Open a `Database` on `db_path` and yield a `BackupService` using it.

        For callers (the CLI) that are not already holding a connected `Database` but
        need `create()` to record its outcome.

        Args:
            db_path: the live database file to back up.
            backup_dir: the directory holding backup archives and their checksums.
            clock: returns the current UTC time; overridable for tests.
            keep_daily: number of most recent distinct days to keep one backup from.
            keep_weekly: number of most recent distinct ISO weeks to keep one backup from.
            keep_monthly: number of most recent distinct months to keep one backup from.
            options: what new backups contain and how they are protected.

        Yields:
            A `BackupService` backed by the opened database, closed on exit.
        """
        database = Database()
        await database.connect(db_path)
        try:
            yield cls(
                db_path,
                backup_dir,
                database,
                clock=clock,
                keep_daily=keep_daily,
                keep_weekly=keep_weekly,
                keep_monthly=keep_monthly,
                options=options,
            )
        finally:
            await database.close()

    def derive(
        self,
        *,
        include_credentials: bool = False,
        encrypt: bool = False,
        allow_plaintext_credentials: bool = False,
        passphrase: PassphraseProvider | None = None,
    ) -> BackupService:
        """Return a service on the same data with other protection options.

        Plaintext credentials are refused on the derived service unless the caller
        explicitly opts in again here, so the configuration's own setting cannot leak
        into an interactive request that never asked for it.

        Args:
            include_credentials: add `secrets.toml` and `vault.key` to new backups.
            encrypt: encrypt new backups.
            allow_plaintext_credentials: permit `include_credentials` without `encrypt`.
            passphrase: where the passphrase comes from; `None` keeps the configured source.

        Returns:
            A new service sharing the database, directory, clock and retention settings.
        """
        options = dataclasses.replace(
            self._options,
            include_credentials=include_credentials,
            encrypt=encrypt,
            allow_plaintext_credentials=allow_plaintext_credentials,
            passphrase=passphrase if passphrase is not None else self._options.passphrase,
        )
        return BackupService(
            self._db_path,
            self._backup_dir,
            self._db,
            clock=self._clock,
            keep_daily=self._keep_daily,
            keep_weekly=self._keep_weekly,
            keep_monthly=self._keep_monthly,
            options=options,
        )

    async def create(self) -> Path:
        """Create a new verified backup of the live database.

        Writes a consistent snapshot with `VACUUM INTO`, checks its integrity, compresses
        it (together with the credential files if configured), optionally encrypts it,
        checksums it, then atomically publishes it under the backup directory. Records
        the outcome (success or failure) in the `backups` table if this service was
        constructed with a `db`.

        Returns:
            The path to the new backup archive.

        Raises:
            PassphraseUnavailableError: if encryption is requested and no passphrase can
                be obtained.
            BackupError: if a backup with the same generated file name already exists,
                credentials would be stored unencrypted without explicit permission, the
                passphrase is too short, a credential file is missing or insecure, or any
                step fails. No temporary file nor a half-written final file is left behind.
        """
        options = self._options
        if not self._backup_dir.is_dir():
            self._backup_dir.mkdir(parents=True)
        self._backup_dir.chmod(0o700)

        created_at = self._clock()
        stem = f"carchive-{created_at.strftime(_TIMESTAMP_FORMAT)}"
        extension = ".tar.gz" if options.include_credentials else ".sqlite3.gz"
        final_path = self._backup_dir / (stem + extension + (".enc" if options.encrypt else ""))
        checksum_path = _checksum_path(final_path)

        if final_path.exists() or checksum_path.exists():
            # Practically unreachable now that the file name carries microseconds: it
            # would need two backups started in the exact same microsecond, which only
            # happens in tests with a frozen clock. Failing loudly beats silently
            # overwriting a previous backup.
            error = BackupError(f"a backup named {final_path.name} already exists")
            await self._record(
                created_at, final_path, 0, "", verified=False, error=redact(str(error))
            )
            raise error

        try:
            passphrase = await asyncio.to_thread(self._prepare_protection)
        except BackupError as exc:
            await self._record(
                created_at, final_path, 0, "", verified=False, error=redact(str(exc))
            )
            raise

        temps: list[Path] = []
        try:
            extra = (
                await asyncio.to_thread(self._read_credentials)
                if options.include_credentials
                else {}
            )
            tmp_sqlite = _mkstemp_in(self._backup_dir, ".sqlite3")
            temps.append(tmp_sqlite)
            # VACUUM INTO refuses to write into a file that already has content, but an
            # empty pre-created file (needed to get owner-only permissions up front) is
            # accepted and its mode is preserved.
            tmp_sqlite.unlink()
            await asyncio.to_thread(_vacuum_into, self._db_path, tmp_sqlite)
            os.chmod(tmp_sqlite, 0o600)
            await asyncio.to_thread(_integrity_check, tmp_sqlite)

            tmp_archive = _mkstemp_in(self._backup_dir, extension)
            temps.append(tmp_archive)
            if options.include_credentials:
                await asyncio.to_thread(_tar_gzip, tmp_sqlite, extra, tmp_archive)
            else:
                await asyncio.to_thread(_gzip_file, tmp_sqlite, tmp_archive)
            if passphrase is not None:
                tmp_encrypted = _mkstemp_in(self._backup_dir, extension + ".enc")
                temps.append(tmp_encrypted)
                await asyncio.to_thread(encrypt_file, tmp_archive, tmp_encrypted, passphrase)
                tmp_archive = tmp_encrypted
            sha256 = await asyncio.to_thread(_sha256_of, tmp_archive)
            size_bytes = tmp_archive.stat().st_size

            os.replace(tmp_archive, final_path)
            try:
                checksum_path.write_text(f"{sha256}  {final_path.name}\n")
                checksum_path.chmod(0o600)
            except OSError:
                final_path.unlink(missing_ok=True)
                raise
        except Exception as exc:
            message = redact(str(exc))
            await self._record(created_at, final_path, 0, "", verified=False, error=message)
            raise BackupError(f"backup creation failed: {message}") from exc
        finally:
            for temp in temps:
                temp.unlink(missing_ok=True)

        await self._record(created_at, final_path, size_bytes, sha256, verified=True, error=None)
        return final_path

    def _prepare_protection(self) -> str | None:
        """Enforce the credential/encryption rule and fetch the passphrase if encrypting."""
        options = self._options
        if options.include_credentials and not options.encrypt:
            if not options.allow_plaintext_credentials:
                raise BackupError(
                    "refusing to store credentials in an unencrypted backup: vault.key would "
                    "sit next to secrets.toml in the same readable archive; enable encryption "
                    "or explicitly allow plaintext credentials"
                )
            logger.warning("backup.plaintext_credentials")
        if not options.encrypt:
            return None
        passphrase = _require_passphrase(options.passphrase)
        if len(passphrase) < MIN_PASSPHRASE_CHARS:
            raise BackupError(f"the passphrase must be at least {MIN_PASSPHRASE_CHARS} characters")
        return passphrase

    def _read_credentials(self) -> dict[str, bytes]:
        secrets_path = self._options.secrets_path
        if secrets_path is None:
            raise BackupError("no secrets file configured to include in the backup")
        return {
            _SECRETS_MEMBER: _read_private_file(secrets_path, _MAX_SECRETS_BYTES, "secrets file"),
            _KEY_MEMBER: _read_private_file(vault_key_path(secrets_path), KEY_LENGTH, "vault key"),
        }

    async def _record(
        self,
        created_at: datetime,
        path: Path,
        size_bytes: int,
        sha256: str,
        *,
        verified: bool,
        error: str | None,
    ) -> None:
        if self._db is None:
            return
        async with self._db.write() as conn:
            await self._backups.add(
                conn,
                id=_new_backup_id(),
                created_at=created_at,
                path=str(path),
                size_bytes=size_bytes,
                sha256=sha256,
                verified=verified,
                error=error,
            )

    def _check_checksum(self, path: Path) -> None:
        checksum_path = _checksum_path(path)
        if not checksum_path.is_file():
            raise BackupError(f"missing checksum file for {path.name}")
        if not path.is_file():
            raise BackupError(f"backup file {path.name} does not exist")

        try:
            expected = checksum_path.read_text().split()[0]
        except (OSError, IndexError) as exc:
            raise BackupError(f"malformed checksum file for {path.name}") from exc

        if _sha256_of(path) != expected:
            raise BackupError(f"checksum mismatch for {path.name}")

    def _unpack(self, path: Path, workdir: Path) -> _Unpacked:
        """Take `path` apart inside `workdir`, decrypting it first if it is encrypted.

        Raises:
            PassphraseUnavailableError: if the archive is encrypted and no passphrase
                can be obtained.
            BackupError: if the archive is damaged, oversized or not recognized.
        """
        inner = path
        try:
            with path.open("rb") as handle:
                encrypted = backup_crypto.is_encrypted_prefix(handle.read(len(backup_crypto.MAGIC)))
            if encrypted:
                passphrase = _require_passphrase(self._options.passphrase)
                inner = _mkstemp_in(workdir, ".inner")
                decrypt_file(path, inner, passphrase)
            with gzip.open(inner, "rb") as gz:
                head = gz.read(_TAR_BLOCK)
            db_path = _mkstemp_in(workdir, ".sqlite3")
            if head.startswith(_SQLITE_MAGIC):
                _decompress(inner, db_path)
                return _Unpacked(db_path, {})
            if head[257:262] != b"ustar":
                raise BackupError(f"unrecognized backup archive {path.name}")
            with gzip.open(inner, "rb") as gz:
                return _Unpacked(db_path, _unpack_tar(gz, db_path))
        except (OSError, EOFError, zlib.error) as exc:
            raise BackupError(f"corrupt backup archive {path.name}: {exc}") from exc

    def verify(self, path: Path, *, content: bool = True) -> None:
        """Verify a backup archive's checksum, container integrity and SQLite integrity.

        Blocking: reads and decrypts/decompresses the whole archive and runs a SQLite
        integrity check on a throwaway copy. Callers inside an event loop should wrap this
        in `asyncio.to_thread`.

        Args:
            path: the backup archive to verify.
            content: if `False`, only the checksum is checked, which needs no passphrase
                for an encrypted archive.

        Raises:
            PassphraseUnavailableError: if `content` is set, the archive is encrypted and
                no passphrase can be obtained.
            BackupError: if the checksum file is missing or does not match, if the
                archive (after decryption) is not a valid container or decompresses too
                large, or if the database fails its integrity check.
        """
        self._check_checksum(path)
        if not content:
            return
        with _workdir(path.parent) as workdir:
            _integrity_check(self._unpack(path, workdir).db_path)

    def list_backups(self) -> list[BackupFile]:
        """Return every backup archive in the backup directory, newest first.

        Only files whose name exactly matches this service's naming pattern are
        considered; anything else in the directory (including checksum sidecars and
        foreign files) is ignored.
        """
        files: list[BackupFile] = []
        if not self._backup_dir.is_dir():
            return files
        for entry in self._backup_dir.iterdir():
            match = _FILENAME_PATTERN.fullmatch(entry.name)
            if match is None or not entry.is_file():
                continue
            created_at = _parse_timestamp(match.group(1))
            try:
                with entry.open("rb") as handle:
                    encrypted = backup_crypto.is_encrypted_prefix(
                        handle.read(len(backup_crypto.MAGIC))
                    )
            except OSError:
                encrypted = match.group(3) is not None
            credentials = None if encrypted else match.group(2) == "tar"
            files.append(
                BackupFile(entry, created_at, entry.stat().st_size, encrypted, credentials)
            )
        files.sort(key=lambda backup_file: backup_file.created_at, reverse=True)
        return files

    def prune(self, now: datetime) -> list[Path]:
        """Delete backups outside the grandfather-father-son retention window.

        Keeps the newest backup per distinct day for `keep_daily` days, per distinct ISO
        week for `keep_weekly` weeks, and per distinct month for `keep_monthly` months;
        the union of those is kept, everything else (and its checksum sidecar) is
        deleted. Does nothing if the newest backup does not pass `verify()`, since
        pruning around a corrupted latest backup could leave no good backup at all.

        Args:
            now: unused for the retention math itself (grouping is by each backup's own
                timestamp), kept for callers that want to log/report against it.

        Returns:
            The paths of the backups that were deleted, newest first.
        """
        backups = self.list_backups()
        if not backups:
            return []

        newest = backups[0]
        try:
            self.verify(newest.path)
        except BackupError as exc:
            logger.warning(
                "backup.prune_skipped_unverified_newest",
                path=str(newest.path),
                error=redact(str(exc)),
            )
            return []

        keep: set[Path] = set()
        keep |= _keep_newest_per_period(backups, self._keep_daily, lambda dt: dt.date())
        keep |= _keep_newest_per_period(backups, self._keep_weekly, lambda dt: dt.isocalendar()[:2])
        keep |= _keep_newest_per_period(backups, self._keep_monthly, lambda dt: (dt.year, dt.month))

        deleted: list[Path] = []
        for backup in backups:
            if backup.path in keep:
                continue
            backup.path.unlink(missing_ok=True)
            _checksum_path(backup.path).unlink(missing_ok=True)
            deleted.append(backup.path)
        return deleted

    async def restore(
        self,
        path: Path,
        db_path: Path,
        *,
        restore_credentials: bool = False,
        overwrite_credentials: bool = False,
    ) -> RestoreResult:
        """Restore `path` over `db_path`, keeping the previous database aside.

        The caller must hold a `DataDirLock` on `db_path`'s directory for the whole call;
        this method does not take one itself, since the CLI needs the lock held across
        both the restore and, in callers that choose to, surrounding diagnostics.

        Credentials in the archive are restored only on request, and an existing
        `secrets.toml` or `vault.key` is only replaced with `overwrite_credentials`, in
        which case it is kept aside like the database.

        Args:
            path: the backup archive to restore.
            db_path: the live database file to replace.
            restore_credentials: also restore `secrets.toml` and `vault.key`.
            overwrite_credentials: replace credential files that already exist.

        Returns:
            What was restored and which previous files were moved aside.

        Raises:
            PassphraseUnavailableError: if the archive is encrypted and no passphrase can
                be obtained.
            BackupError: if `path` fails verification or the database fails its integrity
                check, credentials are requested but absent from the archive, or would
                overwrite existing files without permission. In these cases nothing has
                been changed.
        """
        await asyncio.to_thread(self._check_checksum, path)

        secrets_path = self._options.secrets_path
        targets = (
            (secrets_path, _SECRETS_MEMBER),
            (vault_key_path(secrets_path) if secrets_path else None, _KEY_MEMBER),
        )
        restore_dir = db_path.parent
        with _workdir(restore_dir) as workdir:
            unpacked = await asyncio.to_thread(self._unpack, path, workdir)
            await asyncio.to_thread(_integrity_check, unpacked.db_path)

            available = bool(unpacked.credentials)
            staged: list[tuple[Path, Path]] = []
            if restore_credentials:
                if not available:
                    raise BackupError("the backup holds no credentials to restore")
                for target, member in targets:
                    if target is None:
                        raise BackupError("no secrets file configured to restore credentials to")
                    if os.path.lexists(target) and not overwrite_credentials:
                        raise BackupError(
                            f"{target} already exists; pass the overwrite option to replace it"
                        )
                    staged.append((target, self._stage(target, unpacked.credentials[member])))

            timestamp = self._clock().strftime(_TIMESTAMP_FORMAT)
            try:
                moved_db = self._swap_database(unpacked.db_path, db_path, timestamp)
                moved_credentials = self._place_credentials(staged, timestamp)
            finally:
                for _, tmp in staged:
                    tmp.unlink(missing_ok=True)

        await upgrade_to_head(db_path)
        return RestoreResult(
            previous_db=moved_db,
            credentials_available=available,
            credentials_restored=bool(staged),
            previous_credentials=moved_credentials,
        )

    @staticmethod
    def _stage(target: Path, data: bytes) -> Path:
        """Write `data` owner-only next to `target` and return the temporary path."""
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = _mkstemp_in(target.parent, ".restore")
        try:
            with tmp.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return tmp

    @staticmethod
    def _swap_database(plain_db: Path, db_path: Path, timestamp: str) -> Path | None:
        candidates = (
            db_path,
            db_path.with_name(db_path.name + "-wal"),
            db_path.with_name(db_path.name + "-shm"),
        )
        moved_db_path: Path | None = None
        for candidate in candidates:
            if not candidate.exists():
                continue
            aside = candidate.with_name(f"{candidate.name}.before-restore-{timestamp}")
            os.replace(candidate, aside)
            if candidate == db_path:
                moved_db_path = aside
        os.chmod(plain_db, 0o600)
        os.replace(plain_db, db_path)
        return moved_db_path

    @staticmethod
    def _place_credentials(staged: list[tuple[Path, Path]], timestamp: str) -> tuple[Path, ...]:
        moved: list[Path] = []
        try:
            for target, tmp in staged:
                if os.path.lexists(target):
                    aside = target.with_name(f"{target.name}.before-restore-{timestamp}")
                    os.replace(target, aside)
                    moved.append(aside)
                os.replace(tmp, target)
        except OSError as exc:
            raise BackupError(
                f"the database was restored but the credentials could not be: {exc.strerror}"
            ) from exc
        return tuple(moved)

    async def latest_verified_age(self, now: datetime) -> timedelta | None:
        """Return how long ago the most recently created, successfully verified backup ran.

        Reads the `backups` table; requires this service to have been constructed with
        a `db`.

        Args:
            now: the current time to measure the age against.

        Returns:
            The age of the latest verified backup, or `None` if there is no `db` or no
            verified backup has ever been recorded.
        """
        if self._db is None:
            return None
        async with self._db.read() as conn:
            record = await self._backups.latest_verified(conn)
        if record is None:
            return None
        return now - record.created_at

    @staticmethod
    def due(now: datetime, last_backup_at: datetime | None, backup_time: str) -> bool:
        """Return whether a daily backup is due.

        Due once the local wall-clock time has passed `backup_time` today and no
        successful backup has happened since that moment today.

        Args:
            now: the current time (any timezone; converted to local time).
            last_backup_at: the time of the most recent successful backup, or `None`.
            backup_time: the configured local time of day, as `"HH:MM"`.

        Returns:
            `True` if a backup should run now.
        """
        hour, minute = (int(part) for part in backup_time.split(":"))
        local_now = now.astimezone()
        threshold_today = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if local_now < threshold_today:
            return False
        if last_backup_at is None:
            return True
        return last_backup_at.astimezone() < threshold_today


def _keep_newest_per_period[PeriodKey](
    backups: Sequence[BackupFile], limit: int, period_key: Callable[[datetime], PeriodKey]
) -> set[Path]:
    """Return the newest backup's path for each of the `limit` most recent distinct periods.

    `backups` must already be sorted newest first.
    """
    kept: set[Path] = set()
    seen_periods: set[PeriodKey] = set()
    for backup in backups:
        period = period_key(backup.created_at)
        if period in seen_periods:
            continue
        if len(seen_periods) >= limit:
            break
        seen_periods.add(period)
        kept.add(backup.path)
    return kept


def _new_backup_id() -> UUID:
    return uuid4()
