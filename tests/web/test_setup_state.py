"""Tests for `carchive.web.setup_state.SetupTokenStore`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from carchive.web.setup_state import SetupTokenStore


def test_create_then_consume_returns_the_account_id() -> None:
    store = SetupTokenStore()
    account_id = uuid4()

    token = store.create(account_id)

    assert store.consume(token) == account_id


def test_consume_is_single_use() -> None:
    store = SetupTokenStore()
    token = store.create(uuid4())

    store.consume(token)

    assert store.consume(token) is None


def test_consume_unknown_token_returns_none() -> None:
    store = SetupTokenStore()

    assert store.consume("does-not-exist") is None


def test_consume_after_ttl_expiry_returns_none() -> None:
    now = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    clock_value = [now]
    store = SetupTokenStore(clock=lambda: clock_value[0])

    token = store.create(uuid4())
    clock_value[0] = now + timedelta(minutes=11)

    assert store.consume(token) is None


def test_expired_tokens_are_purged_and_the_store_is_bounded() -> None:
    now = [datetime(2026, 10, 23, 6, 0, tzinfo=UTC)]
    store = SetupTokenStore(clock=lambda: now[0])
    first = store.create(uuid4())
    now[0] += timedelta(minutes=11)
    tokens = [store.create(uuid4()) for _ in range(150)]
    assert store.consume(first) is None
    assert len(store._pending) == 100
    assert store.consume(tokens[-1]) is not None
    assert store.consume(tokens[0]) is None
