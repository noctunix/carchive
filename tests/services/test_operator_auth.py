"""Tests for `carchive.services.operator_auth`."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy import text

from carchive.config import (
    ConfigError,
    InsecureSecretsError,
    load_operator_hash,
    load_secrets,
    write_credentials,
    write_operator_hash,
)
from carchive.core.redact import redact
from carchive.services.operator_auth import (
    LoginThrottle,
    OperatorAuth,
    OperatorAuthError,
    PasswordAlreadySetError,
    PasswordPolicyError,
)
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head

_START = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
_PASSWORD = "synthetic-test-passphrase"


@dataclass
class _Clock:
    now: datetime = _START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def secrets_path(tmp_path: Path) -> Path:
    return tmp_path / "config" / "secrets.toml"


@pytest.fixture
def auth(db: Database, secrets_path: Path, clock: _Clock) -> OperatorAuth:
    return OperatorAuth(db, secrets_path, clock=clock)


async def _session_rows(db: Database) -> list[tuple[str, datetime | str]]:
    async with db.read() as conn:
        rows = await conn.execute(text("SELECT token_hash, last_seen_at FROM operator_sessions"))
        return [(row[0], row[1]) for row in rows]


class TestPassword:
    async def test_not_set_initially_and_verify_is_false(self, auth: OperatorAuth) -> None:
        assert auth.password_is_set() is False
        assert await auth.verify_password(_PASSWORD) is False

    async def test_set_then_verify_roundtrip(self, auth: OperatorAuth, secrets_path: Path) -> None:
        await auth.set_password(_PASSWORD)

        assert auth.password_is_set() is True
        assert await auth.verify_password(_PASSWORD) is True
        assert await auth.verify_password(_PASSWORD + "x") is False
        assert await auth.verify_password("") is False
        stored = load_operator_hash(secrets_path)
        assert stored is not None and stored.startswith("$argon2id$")
        assert _PASSWORD not in secrets_path.read_text()

    async def test_secrets_file_stays_owner_only_and_keeps_accounts(
        self, auth: OperatorAuth, secrets_path: Path
    ) -> None:
        write_credentials(secrets_path, "audi", {"user": "me", "password": "pw"}, overwrite=False)

        await auth.set_password(_PASSWORD)

        assert secrets_path.stat().st_mode & 0o777 == 0o600
        assert load_secrets(secrets_path) == {"audi": {"user": "me", "password": "pw"}}

    @pytest.mark.parametrize(
        ("password", "fragment"),
        [
            ("short", "at least 16"),
            ("x" * 15, "at least 16"),
            ("x" * 257, "at most 256"),
            (" " * 20, "whitespace"),
            ("\t\n" * 10, "whitespace"),
        ],
    )
    async def test_policy_violations(
        self, auth: OperatorAuth, secrets_path: Path, password: str, fragment: str
    ) -> None:
        with pytest.raises(PasswordPolicyError, match=fragment):
            await auth.set_password(password)

        assert not secrets_path.exists()

    async def test_policy_boundaries_and_no_composition_rules(self, auth: OperatorAuth) -> None:
        await auth.set_password("a" * 16)
        assert await auth.verify_password("a" * 16) is True
        await auth.set_password("b" * 256)
        assert await auth.verify_password("b" * 256) is True

    async def test_overlong_input_is_rejected_without_hashing(
        self, auth: OperatorAuth, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await auth.set_password(_PASSWORD)

        class _NoHashing:
            def verify(self, *_args: object) -> None:
                raise AssertionError("must not hash overlong input")

        monkeypatch.setattr(auth, "_hasher", _NoHashing())
        assert await auth.verify_password("x" * 257) is False

    async def test_outdated_hash_is_upgraded_after_successful_login(
        self, auth: OperatorAuth, secrets_path: Path
    ) -> None:
        await auth.set_password("placeholder-password")  # creates the file
        weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(_PASSWORD)
        write_operator_hash(secrets_path, weak)

        assert await auth.verify_password(_PASSWORD) is True

        upgraded = load_operator_hash(secrets_path)
        assert upgraded is not None and upgraded != weak
        assert not PasswordHasher().check_needs_rehash(upgraded)
        assert await auth.verify_password(_PASSWORD) is True

    async def test_wrong_password_does_not_rehash(
        self, auth: OperatorAuth, secrets_path: Path
    ) -> None:
        weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(_PASSWORD)
        write_operator_hash(secrets_path, weak)

        assert await auth.verify_password("another-passphrase") is False

        assert load_operator_hash(secrets_path) == weak

    async def test_corrupt_secrets_file_fails_closed(
        self, auth: OperatorAuth, secrets_path: Path
    ) -> None:
        secrets_path.parent.mkdir(parents=True)
        secrets_path.write_text("not = = toml")
        secrets_path.chmod(0o600)

        with pytest.raises(ConfigError):
            auth.password_is_set()
        with pytest.raises(ConfigError):
            await auth.verify_password(_PASSWORD)
        with pytest.raises(ConfigError):
            await auth.set_password(_PASSWORD)
        assert secrets_path.read_text() == "not = = toml"

    async def test_group_readable_secrets_file_fails_closed(
        self, auth: OperatorAuth, secrets_path: Path
    ) -> None:
        await auth.set_password(_PASSWORD)
        secrets_path.chmod(0o640)

        with pytest.raises(InsecureSecretsError):
            auth.password_is_set()
        with pytest.raises(InsecureSecretsError):
            await auth.verify_password(_PASSWORD)

    async def test_unusable_hash_raises_without_leaking_it(
        self, auth: OperatorAuth, secrets_path: Path
    ) -> None:
        secrets_path.parent.mkdir(parents=True)
        secrets_path.write_text('[operator]\npassword_hash = "plain-not-a-hash"\n')
        secrets_path.chmod(0o600)

        with pytest.raises(OperatorAuthError) as exc_info:
            await auth.verify_password(_PASSWORD)

        assert "plain-not-a-hash" not in str(exc_info.value)

    async def test_hash_is_redacted_from_text(self, auth: OperatorAuth, secrets_path: Path) -> None:
        await auth.set_password(_PASSWORD)
        stored = load_operator_hash(secrets_path)
        assert stored is not None

        assert stored not in redact(f"hash={stored}")
        assert _PASSWORD not in redact(f"password={_PASSWORD}")


class TestSessions:
    async def test_create_and_validate(self, auth: OperatorAuth, clock: _Clock) -> None:
        session = await auth.create_session()

        assert len(session.token) >= 43
        assert session.token not in repr(session)
        assert session.expires_at == _START + timedelta(days=14)
        assert await auth.validate_session(session.token) is True
        assert await auth.validate_session(session.token + "x") is False
        assert await auth.validate_session("") is False
        assert await auth.validate_session("x" * 500) is False

    async def test_tokens_are_unique(self, auth: OperatorAuth) -> None:
        first = await auth.create_session()
        second = await auth.create_session()

        assert first.token != second.token

    async def test_only_the_hash_is_stored(self, auth: OperatorAuth, db: Database) -> None:
        session = await auth.create_session()

        rows = await _session_rows(db)

        assert len(rows) == 1
        assert rows[0][0] == hashlib.sha256(session.token.encode()).hexdigest()
        assert session.token not in rows[0][0]

    async def test_idle_timeout_slides_with_activity(
        self, auth: OperatorAuth, clock: _Clock
    ) -> None:
        session = await auth.create_session()

        for _ in range(4):
            clock.advance(hours=11)
            assert await auth.validate_session(session.token) is True

        clock.advance(hours=12)
        assert await auth.validate_session(session.token) is False
        clock.advance(minutes=1)
        assert await auth.validate_session(session.token) is False

    async def test_idle_expired_session_is_deleted(
        self, auth: OperatorAuth, clock: _Clock, db: Database
    ) -> None:
        session = await auth.create_session()
        clock.advance(hours=12)

        assert await auth.validate_session(session.token) is False

        assert await _session_rows(db) == []

    async def test_absolute_lifetime_ends_an_active_session(
        self, auth: OperatorAuth, clock: _Clock
    ) -> None:
        session = await auth.create_session()
        for _ in range(30):
            clock.advance(hours=11)
            assert await auth.validate_session(session.token) is True

        clock.now = _START + timedelta(days=14) - timedelta(minutes=1)
        assert await auth.validate_session(session.token) is True
        clock.now = _START + timedelta(days=14)
        assert await auth.validate_session(session.token) is False

    async def test_last_seen_is_written_at_most_once_per_minute(
        self, auth: OperatorAuth, clock: _Clock, db: Database
    ) -> None:
        session = await auth.create_session()
        written = (await _session_rows(db))[0][1]

        clock.advance(seconds=59)
        assert await auth.validate_session(session.token) is True
        assert (await _session_rows(db))[0][1] == written

        clock.advance(seconds=1)
        assert await auth.validate_session(session.token) is True
        assert (await _session_rows(db))[0][1] != written

    async def test_revoke_one(self, auth: OperatorAuth) -> None:
        keep = await auth.create_session()
        drop = await auth.create_session()

        await auth.revoke_session(drop.token)
        await auth.revoke_session(drop.token)
        await auth.revoke_session("unknown")
        await auth.revoke_session("")

        assert await auth.validate_session(drop.token) is False
        assert await auth.validate_session(keep.token) is True

    async def test_revoke_all(self, auth: OperatorAuth) -> None:
        sessions = [await auth.create_session() for _ in range(3)]

        await auth.revoke_all_sessions()

        for session in sessions:
            assert await auth.validate_session(session.token) is False

    async def test_password_change_revokes_all_sessions(self, auth: OperatorAuth) -> None:
        await auth.set_password(_PASSWORD)
        session = await auth.create_session()

        await auth.set_password(_PASSWORD + "-new")

        assert await auth.validate_session(session.token) is False

    async def test_purge_removes_only_expired(
        self, auth: OperatorAuth, clock: _Clock, db: Database
    ) -> None:
        old = await auth.create_session()
        clock.advance(hours=11)
        fresh = await auth.create_session()
        clock.advance(hours=2)

        assert await auth.purge_expired_sessions() == 1
        assert await auth.purge_expired_sessions() == 0
        assert len(await _session_rows(db)) == 1
        assert await auth.validate_session(old.token) is False
        assert await auth.validate_session(fresh.token) is True

    async def test_create_session_drops_expired_sessions(
        self, auth: OperatorAuth, clock: _Clock, db: Database
    ) -> None:
        await auth.create_session()
        clock.advance(hours=13)

        await auth.create_session()

        assert len(await _session_rows(db)) == 1


class TestInitialPassword:
    async def test_only_if_unset_sets_the_first_password(self, auth: OperatorAuth) -> None:
        await auth.set_password(_PASSWORD, only_if_unset=True)

        assert auth.password_is_set()
        assert await auth.verify_password(_PASSWORD) is True

    async def test_only_if_unset_refuses_to_replace(self, auth: OperatorAuth) -> None:
        await auth.set_password(_PASSWORD)

        with pytest.raises(PasswordAlreadySetError):
            await auth.set_password("another-long-password", only_if_unset=True)

        assert await auth.verify_password(_PASSWORD) is True

    async def test_concurrent_first_attempts_have_exactly_one_winner(
        self, auth: OperatorAuth
    ) -> None:
        passwords = [f"first-candidate-password-{i}" for i in range(5)]

        results = await asyncio.gather(
            *(auth.set_password(p, only_if_unset=True) for p in passwords),
            return_exceptions=True,
        )

        failures = [r for r in results if isinstance(r, PasswordAlreadySetError)]
        assert len(failures) == len(passwords) - 1
        assert sum(1 for r in results if r is None) == 1
        winners = [p for p in passwords if await auth.verify_password(p)]
        assert len(winners) == 1

    async def test_policy_violation_does_not_set_anything(self, auth: OperatorAuth) -> None:
        with pytest.raises(PasswordPolicyError):
            await auth.set_password("short", only_if_unset=True)

        assert not auth.password_is_set()

    async def test_corrupt_secrets_file_is_not_reported_as_unset(
        self, auth: OperatorAuth, secrets_path: Path
    ) -> None:
        secrets_path.parent.mkdir(parents=True)
        secrets_path.write_text("= = =")
        secrets_path.chmod(0o600)

        with pytest.raises(ConfigError):
            await auth.set_password(_PASSWORD, only_if_unset=True)

        assert secrets_path.read_text() == "= = ="


class _FakeMonotonic:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class TestLoginThrottle:
    def test_unknown_key_is_not_locked(self) -> None:
        assert LoginThrottle().retry_after("a") is None

    def test_locks_at_the_threshold_and_doubles_up_to_the_cap(self) -> None:
        clock = _FakeMonotonic()
        throttle = LoginThrottle(clock)
        for _ in range(4):
            throttle.record_failure("a")
            assert throttle.retry_after("a") is None

        expected = [30, 60, 120, 240, 480, 900, 900]
        for seconds in expected:
            throttle.record_failure("a")
            assert throttle.retry_after("a") == seconds
            clock.now += seconds

        assert throttle.retry_after("a") is None

    def test_lock_counts_down_and_other_keys_are_unaffected(self) -> None:
        clock = _FakeMonotonic()
        throttle = LoginThrottle(clock)
        for _ in range(5):
            throttle.record_failure("a")

        clock.now += 10.5
        assert throttle.retry_after("a") == 20
        assert throttle.retry_after("b") is None
        clock.now += 20
        assert throttle.retry_after("a") is None

    def test_success_resets_the_key(self) -> None:
        throttle = LoginThrottle(_FakeMonotonic())
        for _ in range(5):
            throttle.record_failure("a")

        throttle.record_success("a")

        assert throttle.retry_after("a") is None
        for _ in range(4):
            throttle.record_failure("a")
        assert throttle.retry_after("a") is None

    def test_old_failures_are_forgotten(self) -> None:
        clock = _FakeMonotonic()
        throttle = LoginThrottle(clock)
        for _ in range(4):
            throttle.record_failure("a")

        clock.now += 3601
        throttle.record_failure("a")

        assert throttle.retry_after("a") is None

    def test_global_key_has_ten_times_the_threshold(self) -> None:
        throttle = LoginThrottle(_FakeMonotonic())
        for _ in range(49):
            throttle.record_failure("*")
        assert throttle.retry_after("*") is None

        throttle.record_failure("*")

        assert throttle.retry_after("*") == 30

    def test_size_is_bounded_and_global_key_survives(self) -> None:
        throttle = LoginThrottle(_FakeMonotonic())
        for _ in range(50):
            throttle.record_failure("*")
        for index in range(3000):
            throttle.record_failure(f"client-{index}")

        assert len(throttle._entries) == 1024
        assert throttle.retry_after("*") == 30
        assert "client-0" not in throttle._entries
        assert "client-2999" in throttle._entries
