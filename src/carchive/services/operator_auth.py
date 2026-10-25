"""Login backend for the single operator: password, sessions, brute-force throttle.

The Argon2id hash lives in the owner-only secrets file and sessions live in the database as
SHA-256 hashes of random tokens. Nothing here knows about HTTP; the web layer composes these
pieces.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
import secrets
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import (
    Argon2Error,
    InvalidHashError,
    UnsupportedParametersError,
    VerifyMismatchError,
)

from carchive.config import (
    ConfigError,
    InsecureSecretsError,
    load_operator_hash,
    write_operator_hash,
)
from carchive.core.redact import redact, register_secret
from carchive.storage.db import Database
from carchive.storage.migrate import current_revision
from carchive.storage.repositories import OperatorSessionRepository

logger = structlog.get_logger(__name__)

MIN_PASSWORD_LENGTH = 16
MAX_PASSWORD_LENGTH = 256

SESSION_IDLE_TIMEOUT = timedelta(hours=12)
SESSION_ABSOLUTE_LIFETIME = timedelta(days=14)
# `last_seen_at` is written at most this often, so a busy page does not turn every request into
# a database write.
SESSION_TOUCH_INTERVAL = timedelta(minutes=1)

# `secrets.token_urlsafe(32)` yields 43 characters; anything far beyond is not ours.
_MAX_SESSION_TOKEN_LENGTH = 128

THROTTLE_GLOBAL_KEY = "*"
_THROTTLE_THRESHOLD = 5
_THROTTLE_GLOBAL_FACTOR = 10
_THROTTLE_BASE_LOCK_S = 30.0
_THROTTLE_MAX_LOCK_S = 900.0
_THROTTLE_MAX_KEYS = 1024
# A key with no failure for this long starts over, so old typos do not count forever.
_THROTTLE_FORGET_AFTER_S = 3600.0


class OperatorAuthError(RuntimeError):
    """Raised when stored login state is unusable; the message is safe to show."""


class PasswordPolicyError(ValueError):
    """Raised when a new password violates the policy; the message is safe to show."""


class PasswordAlreadySetError(RuntimeError):
    """Raised when the first password is requested but one already exists."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class SessionToken:
    """A freshly created session.

    Attributes:
        token: the raw session token; shown once, only its hash is stored.
        expires_at: the absolute end of the session, independent of activity (the idle
            timeout can end it sooner).
    """

    token: str = field(repr=False)
    expires_at: datetime


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class OperatorAuth:
    """Password and session handling for the one operator account.

    Args:
        db: a connected database holding `operator_sessions`.
        secrets_path: the owner-only secrets file holding the password hash.
        clock: returns the current UTC time; overridable for tests.
    """

    def __init__(
        self,
        db: Database,
        secrets_path: Path,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._db = db
        self._secrets_path = secrets_path
        self._clock = clock
        self._sessions = OperatorSessionRepository()
        self._hasher = PasswordHasher()
        self._dummy_hash: str | None = None
        # Serializes writes of the password hash so a rehash after login cannot undo a
        # concurrent password change.
        self._hash_lock = asyncio.Lock()

    @classmethod
    @asynccontextmanager
    async def connect(
        cls,
        db_path: Path,
        secrets_path: Path,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ) -> AsyncIterator[OperatorAuth]:
        """Open a `Database` on `db_path` and yield an `OperatorAuth` using it.

        For callers (the CLI) that do not already hold a connected `Database`. The database
        must already be migrated.

        Args:
            db_path: the migrated database file.
            secrets_path: the owner-only secrets file holding the password hash.
            clock: returns the current UTC time; overridable for tests.

        Yields:
            An `OperatorAuth` backed by the opened database, closed on exit.

        Raises:
            OperatorAuthError: if the database has not been migrated.
        """
        if await current_revision(db_path) is None:
            raise OperatorAuthError("database is not migrated; run 'carchive db upgrade'")
        db = Database()
        await db.connect(db_path)
        try:
            yield cls(db, secrets_path, clock=clock)
        finally:
            await db.close()

    def password_is_set(self) -> bool:
        """Return whether an operator password hash exists.

        Returns:
            `True` if a hash is stored, `False` only if the secrets file or its hash entry
            does not exist.

        Raises:
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file cannot be parsed or is malformed; an unreadable
                file is never reported as "no password".
        """
        return load_operator_hash(self._secrets_path) is not None

    async def set_password(self, new_password: str, *, only_if_unset: bool = False) -> None:
        """Set or replace the operator password, ending every session.

        With `only_if_unset` the check and the write happen under one lock, so of several
        concurrent first-time attempts exactly one succeeds. The lock is per process; the
        data directory lock keeps a second process from running next to the server.

        Args:
            new_password: the new password.
            only_if_unset: refuse to replace an existing password.

        Raises:
            PasswordPolicyError: if the password violates the policy.
            PasswordAlreadySetError: if `only_if_unset` is set and a password exists.
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file is malformed.
            OSError: if the secrets file cannot be written.
        """
        self._check_policy(new_password)
        new_hash = await asyncio.to_thread(self._hasher.hash, new_password)
        register_secret(new_password)
        async with self._hash_lock:
            if only_if_unset and await asyncio.to_thread(self.password_is_set):
                raise PasswordAlreadySetError("a password is already set")
            await asyncio.to_thread(write_operator_hash, self._secrets_path, new_hash)
        await self.revoke_all_sessions()

    @staticmethod
    def _check_policy(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise PasswordPolicyError(
                f"password must be at least {MIN_PASSWORD_LENGTH} characters long"
            )
        if len(password) > MAX_PASSWORD_LENGTH:
            raise PasswordPolicyError(
                f"password must be at most {MAX_PASSWORD_LENGTH} characters long"
            )
        if password.isspace():
            raise PasswordPolicyError("password must not consist only of whitespace")

    async def verify_password(self, password: str) -> bool:
        """Check a login password; upgrades the stored hash if its parameters are outdated.

        With no password set a dummy hash is verified, so the response time does not reveal
        that state. Overlong input is rejected without hashing.

        Args:
            password: the password to check.

        Returns:
            `True` if it matches, `False` for a wrong password, no password set or input
            longer than the policy maximum.

        Raises:
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file is malformed.
            OperatorAuthError: if the stored hash is not a usable Argon2 hash.
        """
        if len(password) > MAX_PASSWORD_LENGTH:
            return False
        stored = load_operator_hash(self._secrets_path)
        if stored is None:
            await asyncio.to_thread(self._verify_dummy, password)
            return False
        try:
            await asyncio.to_thread(self._hasher.verify, stored, password)
        except VerifyMismatchError:
            return False
        except (Argon2Error, InvalidHashError, UnsupportedParametersError):
            raise OperatorAuthError("the stored password hash is unusable") from None
        if self._hasher.check_needs_rehash(stored):
            await self._rehash(stored, password)
        return True

    def _verify_dummy(self, password: str) -> None:
        if self._dummy_hash is None:
            self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))
        with suppress(VerifyMismatchError):
            self._hasher.verify(self._dummy_hash, password)

    async def _rehash(self, old_hash: str, password: str) -> None:
        new_hash = await asyncio.to_thread(self._hasher.hash, password)
        async with self._hash_lock:
            try:
                # Only replace the hash we verified against, never a newer password.
                if load_operator_hash(self._secrets_path) == old_hash:
                    await asyncio.to_thread(write_operator_hash, self._secrets_path, new_hash)
            except (OSError, ConfigError, InsecureSecretsError) as exc:
                logger.warning("operator_auth.rehash_failed", error=redact(str(exc)))

    async def create_session(self) -> SessionToken:
        """Create a session and drop expired ones.

        Returns:
            The raw token (shown once) and the session's absolute expiry.
        """
        token = secrets.token_urlsafe(32)
        now = self._clock()
        expires_at = now + SESSION_ABSOLUTE_LIFETIME
        async with self._db.write() as conn:
            await self._sessions.delete_expired(
                conn, expired_before=now, idle_before=now - SESSION_IDLE_TIMEOUT
            )
            await self._sessions.add(
                conn,
                id=uuid4(),
                token_hash=_hash_token(token),
                created_at=now,
                last_seen_at=now,
                expires_at=expires_at,
            )
        return SessionToken(token=token, expires_at=expires_at)

    async def validate_session(self, token: str) -> bool:
        """Check a session token and extend its idle window.

        Expired sessions are deleted on sight.

        Args:
            token: the raw session token, e.g. from a cookie.

        Returns:
            `True` if the session exists and is neither idle-expired nor past its absolute
            lifetime.
        """
        if not token or len(token) > _MAX_SESSION_TOKEN_LENGTH:
            return False
        token_hash = _hash_token(token)
        now = self._clock()
        async with self._db.read() as conn:
            record = await self._sessions.get_by_token_hash(conn, token_hash)
        if record is None or not hmac.compare_digest(record.token_hash, token_hash):
            return False
        if now >= record.expires_at or now - record.last_seen_at >= SESSION_IDLE_TIMEOUT:
            async with self._db.write() as conn:
                await self._sessions.delete_by_token_hash(conn, token_hash)
            return False
        if now - record.last_seen_at >= SESSION_TOUCH_INTERVAL:
            async with self._db.write() as conn:
                await self._sessions.touch(conn, record.id, now)
        return True

    async def revoke_session(self, token: str) -> None:
        """End one session; an unknown token is ignored.

        Args:
            token: the raw session token.
        """
        if not token or len(token) > _MAX_SESSION_TOKEN_LENGTH:
            return
        async with self._db.write() as conn:
            await self._sessions.delete_by_token_hash(conn, _hash_token(token))

    async def revoke_all_sessions(self) -> None:
        """End every session."""
        async with self._db.write() as conn:
            await self._sessions.delete_all(conn)

    async def purge_expired_sessions(self) -> int:
        """Delete sessions that are idle-expired or past their absolute lifetime.

        Returns:
            The number of sessions deleted.
        """
        now = self._clock()
        async with self._db.write() as conn:
            return await self._sessions.delete_expired(
                conn, expired_before=now, idle_before=now - SESSION_IDLE_TIMEOUT
            )


@dataclass(slots=True)
class _ThrottleEntry:
    failures: int
    last_failure: float
    locked_until: float


class LoginThrottle:
    """In-memory brute-force throttle with exponentially growing lockouts.

    After 5 failures for a key it locks that key for 30 s; every further failure doubles the
    lockout up to 900 s. A success resets the key, and a key without failures for an hour
    starts over. The special key `"*"` has ten times the threshold and is meant as a global
    counter against attempts spread over many clients.

    The throttle does not pick keys: the caller decides what identifies a client (for example
    its address), and should check and record both that key and `"*"` for every login attempt.
    State is not persisted and holds at most 1024 keys; when full, the key with the oldest
    activity is dropped (never `"*"`).

    Args:
        clock: returns monotonic seconds; overridable for tests.
    """

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock if clock is not None else time.monotonic
        self._entries: OrderedDict[str, _ThrottleEntry] = OrderedDict()

    @staticmethod
    def _threshold(key: str) -> int:
        if key == THROTTLE_GLOBAL_KEY:
            return _THROTTLE_THRESHOLD * _THROTTLE_GLOBAL_FACTOR
        return _THROTTLE_THRESHOLD

    def _live_entry(self, key: str, now: float) -> _ThrottleEntry | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.locked_until <= now and now - entry.last_failure >= _THROTTLE_FORGET_AFTER_S:
            del self._entries[key]
            return None
        return entry

    def retry_after(self, key: str) -> int | None:
        """Return how long a key stays locked.

        Args:
            key: the client key, or `"*"`.

        Returns:
            Remaining lockout in whole seconds (at least 1), or `None` if the key is not locked.
        """
        now = self._clock()
        entry = self._live_entry(key, now)
        if entry is None or entry.locked_until <= now:
            return None
        return max(1, math.ceil(entry.locked_until - now))

    def record_failure(self, key: str) -> None:
        """Count a failed attempt and lock the key once it reaches its threshold.

        Args:
            key: the client key, or `"*"`.
        """
        now = self._clock()
        entry = self._live_entry(key, now)
        if entry is None:
            entry = _ThrottleEntry(failures=0, last_failure=now, locked_until=0.0)
            self._entries[key] = entry
        entry.failures += 1
        entry.last_failure = now
        over = entry.failures - self._threshold(key)
        if over >= 0:
            # Capped exponent keeps the arithmetic bounded however long an attack lasts.
            lock = min(_THROTTLE_BASE_LOCK_S * 2 ** min(over, 16), _THROTTLE_MAX_LOCK_S)
            entry.locked_until = now + lock
        self._entries.move_to_end(key)
        self._evict()

    def record_success(self, key: str) -> None:
        """Forget a key's failures.

        Args:
            key: the client key, or `"*"`.
        """
        self._entries.pop(key, None)

    def _evict(self) -> None:
        while len(self._entries) > _THROTTLE_MAX_KEYS:
            oldest = next(k for k in self._entries if k != THROTTLE_GLOBAL_KEY)
            del self._entries[oldest]
