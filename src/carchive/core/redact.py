"""VIN masking and secret redaction for logs and error messages."""

from __future__ import annotations

import re

# Lookarounds instead of \b: portal file names embed the VIN between
# underscores ("20261022164821_<VIN>_no_content_found.zip"), and "_" is a word
# character, so \b would let exactly those through.
VIN_PATTERN = re.compile(r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])")

_MIN_SECRET_LENGTH = 4

# The catalog upload route's CSRF token travels in the request's query string
# (`web.security.SecurityMiddleware.streaming_paths`), which an access logger such as
# uvicorn's logs as part of the request line. It is a fresh per-session random value,
# never a registered secret, so it needs its own pattern rather than `SecretRegistry`.
_CSRF_TOKEN_QUERY_PARAM = re.compile(r"(csrf_token=)[^&\s\"'>]+", re.IGNORECASE)


def redact_csrf_token(text: str) -> str:
    """Mask a `csrf_token=<value>` query parameter wherever it appears in `text`.

    Args:
        text: the text to scrub, e.g. a log line that may embed a request's path and
            query string.

    Returns:
        `text` with every `csrf_token=<value>` occurrence's value replaced by `***`.
    """
    if not text:
        return text
    return _CSRF_TOKEN_QUERY_PARAM.sub(r"\1***", text)


def mask_vin(vin: str) -> str:
    """Mask a VIN, keeping only its first and last three characters.

    Args:
        vin: the VIN (or VIN-like string) to mask.

    Returns:
        `vin` unchanged if it has 6 characters or fewer, else
        `"<first 3>…<last 3>"`.
    """
    if len(vin) <= 6:
        return vin
    return f"{vin[:3]}…{vin[-3:]}"


class SecretRegistry:
    """Tracks secret values so they can be scrubbed from arbitrary text."""

    def __init__(self) -> None:
        self._secrets: set[str] = set()

    def register(self, value: str) -> None:
        """Register a value to be redacted by `redact`.

        Args:
            value: the secret value. Values shorter than 4 characters are
                ignored, since masking them would do little and risks
                matching unrelated text.
        """
        if len(value) >= _MIN_SECRET_LENGTH:
            self._secrets.add(value)

    def redact(self, text: str) -> str:
        """Replace registered secrets and VIN-like tokens in `text`.

        Registered secrets are replaced with `***`, longest first so that
        one secret being a substring of another does not leave a remainder
        exposed. Every VIN-like token is masked with `mask_vin`.

        Args:
            text: the text to scrub.

        Returns:
            The scrubbed text.
        """
        if not text:
            return text
        result = text
        for secret in sorted(self._secrets, key=len, reverse=True):
            if secret in result:
                result = result.replace(secret, "***")
        return VIN_PATTERN.sub(lambda match: mask_vin(match.group(0)), result)

    def clear(self) -> None:
        """Remove all registered secrets."""
        self._secrets.clear()


_default_registry = SecretRegistry()


def register_secret(value: str) -> None:
    """Register `value` with the module-level default registry."""
    _default_registry.register(value)


def redact(text: str) -> str:
    """Scrub `text` using the module-level default registry."""
    return _default_registry.redact(text)
