"""Tests for carchive.core.redact."""

from __future__ import annotations

import json
import logging

import pytest
import structlog

from carchive.core.redact import (
    SecretRegistry,
    mask_vin,
    redact,
    redact_csrf_token,
    register_secret,
)
from carchive.logging_setup import configure_logging


def test_mask_vin_keeps_first_and_last_three() -> None:
    assert mask_vin("WAUZZZF12AA123477") == "WAU…477"


def test_mask_vin_leaves_short_strings_unchanged() -> None:
    assert mask_vin("WAU477") == "WAU477"
    assert mask_vin("ab") == "ab"


def test_registry_redacts_longest_secret_first() -> None:
    registry = SecretRegistry()
    registry.register("secretvalue")
    registry.register("secret")

    assert registry.redact("prefix secretvalue suffix") == "prefix *** suffix"


def test_registry_ignores_short_values() -> None:
    registry = SecretRegistry()
    registry.register("abc")

    assert registry.redact("abc stays") == "abc stays"


def test_registry_masks_vin_like_tokens() -> None:
    registry = SecretRegistry()

    assert registry.redact("vehicle WAUZZZF12AA123477 seen") == "vehicle WAU…477 seen"


def test_module_level_redact_uses_default_registry() -> None:
    register_secret("topsecretpassword")

    assert redact("login with topsecretpassword") == "login with ***"


def test_canary_secret_and_vin_never_appear_in_log_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "sup3r-secret-token"
    vin = "WAUZZZF12AA123477"
    register_secret(secret)

    configure_logging(verbose=False, fmt="json")

    structlog.get_logger("carchive.test").info("structlog event", password=secret, vin=vin)

    try:
        raise RuntimeError(f"failed with token {secret} for vehicle {vin}")
    except RuntimeError:
        logging.getLogger("carchive.stdlib").exception("stdlib event %s %s", secret, vin)

    output = capsys.readouterr().err
    assert secret not in output
    assert vin not in output
    for line in output.splitlines():
        if not line:
            continue
        json.loads(line)


def test_vin_between_underscores_in_a_file_name_is_masked() -> None:
    registry = SecretRegistry()
    text = "acknowledged placeholder 20261022164821_WAUZZZ4G1XN000001_no_content_found.zip"
    assert registry.redact(text) == (
        "acknowledged placeholder 20261022164821_WAU…001_no_content_found.zip"
    )
    assert registry.redact("/vehicles/WAUZZZ4G1XN000001/list") == "/vehicles/WAU…001/list"


def test_redact_csrf_token_masks_the_value_in_a_query_string() -> None:
    text = '"POST /settings/catalog/import?csrf_token=AbC-123_xyz HTTP/1.1" 200'
    assert redact_csrf_token(text) == '"POST /settings/catalog/import?csrf_token=*** HTTP/1.1" 200'


def test_redact_csrf_token_masks_every_occurrence() -> None:
    text = "first csrf_token=aaa then csrf_token=bbb"
    assert redact_csrf_token(text) == "first csrf_token=*** then csrf_token=***"


def test_redact_csrf_token_stops_at_the_next_query_separator() -> None:
    text = "/path?csrf_token=abc123&other=1"
    assert redact_csrf_token(text) == "/path?csrf_token=***&other=1"


def test_redact_csrf_token_is_case_insensitive() -> None:
    assert redact_csrf_token("CSRF_TOKEN=secretvalue") == "CSRF_TOKEN=***"


def test_redact_csrf_token_leaves_text_without_it_unchanged() -> None:
    assert redact_csrf_token("/settings") == "/settings"


def test_redact_csrf_token_handles_empty_string() -> None:
    assert redact_csrf_token("") == ""


def test_canary_csrf_token_never_appears_in_log_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    token = "rAnd0m-csrf-token_value123"
    path = f"/settings/catalog/import?csrf_token={token}"

    configure_logging(verbose=False, fmt="json")

    structlog.get_logger("carchive.test").info("structlog event", path=path)
    logging.getLogger("uvicorn.access").info('%s - "POST %s HTTP/1.1" 200', "127.0.0.1:12345", path)

    output = capsys.readouterr().err
    assert token not in output
    assert "csrf_token=***" in output
    for line in output.splitlines():
        if not line:
            continue
        json.loads(line)
