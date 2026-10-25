"""Shared test fixtures."""

from __future__ import annotations

import pytest

from carchive.core import redact as redact_module


@pytest.fixture(autouse=True)
def _clear_secret_registry() -> None:
    """Reset the module-level secret registry so tests don't leak secrets into each other."""
    redact_module._default_registry.clear()
