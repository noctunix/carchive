"""The `datetime` template filter renders local, localized timestamps."""

from __future__ import annotations

import gettext
from datetime import UTC, datetime

import pytest

from carchive.web.i18n import current_language
from carchive.web.templating import build_templates


@pytest.fixture
def datetime_filter(monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.setenv("TZ", "Europe/Berlin")
    import time

    time.tzset()
    translations = {"en": gettext.NullTranslations(), "de": gettext.NullTranslations()}
    yield build_templates(translations).env.filters["datetime"]
    monkeypatch.delenv("TZ")
    time.tzset()


def test_datetime_is_local_and_localized(datetime_filter: object) -> None:
    value = datetime(2026, 10, 23, 4, 57, 43, tzinfo=UTC)
    token = current_language.set("de")
    try:
        assert datetime_filter(value) == "23.10.2026, 06:57:43"  # type: ignore[operator]
    finally:
        current_language.reset(token)
    token = current_language.set("en")
    try:
        assert datetime_filter(value) == "Oct 23, 2026, 6:57:43 AM"  # type: ignore[operator]
    finally:
        current_language.reset(token)
    assert datetime_filter("not a datetime") == "not a datetime"  # type: ignore[operator]
