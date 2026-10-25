"""Tests for `carchive.core.errors`."""

from __future__ import annotations

from carchive.core.errors import (
    AuthenticationError,
    NeedsAttentionError,
    ProviderError,
    RateLimitedError,
    TransientError,
)


def test_subclasses_are_provider_errors() -> None:
    assert issubclass(AuthenticationError, ProviderError)
    assert issubclass(NeedsAttentionError, ProviderError)
    assert issubclass(RateLimitedError, ProviderError)
    assert issubclass(TransientError, ProviderError)


def test_needs_attention_error_str_includes_reason() -> None:
    error = NeedsAttentionError("login page layout changed")
    assert error.reason == "login page layout changed"
    assert "login page layout changed" in str(error)


def test_rate_limited_error_str_with_retry_after() -> None:
    error = RateLimitedError(retry_after_s=30.0)
    assert error.retry_after_s == 30.0
    assert "30" in str(error)


def test_rate_limited_error_str_without_retry_after() -> None:
    error = RateLimitedError()
    assert error.retry_after_s is None
    assert "rate limited" in str(error)
