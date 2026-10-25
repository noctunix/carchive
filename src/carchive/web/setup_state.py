"""Short-lived, single-use state for the account setup wizard's step 2 -> step 3 handoff.

Holds nothing longer-lived than the few minutes a user takes to pick vehicles: an account
id, never a password or any other credential. Kept in process memory only, never a cookie
or a hidden form field holding anything secret; the hidden field only ever carries the
opaque token below.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

_TOKEN_TTL = timedelta(minutes=10)
_MAX_PENDING = 100


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class _PendingSelection:
    account_id: UUID
    expires_at: datetime


class SetupTokenStore:
    """Maps a one-time setup token to the account created in the wizard's step 2.

    Args:
        clock: returns the current UTC time; overridable for tests.
    """

    def __init__(self, *, clock: Callable[[], datetime] = _utcnow) -> None:
        self._pending: dict[str, _PendingSelection] = {}
        self._clock = clock

    def create(self, account_id: UUID) -> str:
        """Create a new token for `account_id`, valid for 10 minutes and usable once.

        Returns:
            The opaque token to embed in the step-3 form's hidden field.
        """
        now = self._clock()
        # Abandoned wizards would otherwise accumulate forever.
        self._pending = {t: e for t, e in self._pending.items() if e.expires_at >= now}
        if len(self._pending) >= _MAX_PENDING:
            oldest = min(self._pending, key=lambda t: self._pending[t].expires_at)
            del self._pending[oldest]
        token = secrets.token_urlsafe(32)
        self._pending[token] = _PendingSelection(account_id, now + _TOKEN_TTL)
        return token

    def consume(self, token: str) -> UUID | None:
        """Return and invalidate the account id behind `token`.

        Args:
            token: the token from the step-3 form's hidden field.

        Returns:
            The account id, or `None` if `token` is unknown, already used, or expired.
        """
        entry = self._pending.pop(token, None)
        if entry is None or entry.expires_at < self._clock():
            return None
        return entry.account_id
