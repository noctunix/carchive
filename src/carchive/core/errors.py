"""Provider error hierarchy.

These carry only text the caller already redacted or otherwise chose to pass in; they never
extract values from a response body themselves.
"""

from __future__ import annotations


class ProviderError(Exception):
    """Base class for errors raised by a provider implementation."""


class AuthenticationError(ProviderError):
    """Login failed (bad credentials, rejected consent, expired session, …)."""


class NeedsAttentionError(ProviderError):
    """The provider needs a human before it can continue.

    Raised for conditions no amount of retrying resolves on its own, such as a changed login
    page layout, an outstanding consent screen, or an identifier the portal rejects outright.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)

    def __str__(self) -> str:
        return f"needs attention: {self.reason}"


class RateLimitedError(ProviderError):
    """The provider asked to slow down, optionally with a suggested wait time."""

    def __init__(self, retry_after_s: float | None = None) -> None:
        self.retry_after_s = retry_after_s
        super().__init__(str(retry_after_s))

    def __str__(self) -> str:
        if self.retry_after_s is None:
            return "rate limited"
        return f"rate limited, retry after {self.retry_after_s:g}s"


class TransientError(ProviderError):
    """A temporary failure (network error, 5xx) that a later retry may resolve."""
