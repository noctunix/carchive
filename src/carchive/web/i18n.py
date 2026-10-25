"""i18n: German translation compiled in memory from a source `.po` file.

No compiled `.mo` file is committed; `babel.messages.pofile.read_po` parses the German
`.po` catalog at startup and `babel.messages.mofile.write_mo` compiles it into memory for
`gettext.GNUTranslations`, which `jinja2.ext.i18n` expects. English is the template source
language and needs no catalog.
"""

from __future__ import annotations

import gettext
from collections.abc import Awaitable, Callable, MutableMapping
from contextvars import ContextVar
from http.cookies import SimpleCookie
from io import BytesIO
from pathlib import Path
from typing import Any

from babel.messages.mofile import write_mo
from babel.messages.pofile import read_po

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

SUPPORTED_LANGUAGES = ("en", "de")
DEFAULT_LANGUAGE = "en"
LANG_COOKIE_NAME = "lang"

_LOCALE_DIR = Path(__file__).parent / "locale"

# Set by `LanguageMiddleware` for the current request's task context, read by the gettext
# callables installed in `web.templating.build_templates`.
current_language: ContextVar[str] = ContextVar("current_language", default=DEFAULT_LANGUAGE)


def load_translations() -> dict[str, gettext.NullTranslations]:
    """Load every supported language's translations.

    Returns:
        A mapping from language code to a `gettext`-compatible translations object:
        `gettext.NullTranslations` (pass-through) for English, a compiled
        `gettext.GNUTranslations` for German.

    Raises:
        OSError: if the German `.po` file is missing.
        ValueError: if it is malformed.
    """
    translations: dict[str, gettext.NullTranslations] = {"en": gettext.NullTranslations()}
    po_path = _LOCALE_DIR / "de" / "LC_MESSAGES" / "messages.po"
    with po_path.open("rb") as po_file:
        catalog = read_po(po_file, locale="de")
    buffer = BytesIO()
    write_mo(buffer, catalog)
    buffer.seek(0)
    translations["de"] = gettext.GNUTranslations(buffer)
    return translations


def negotiate_language(cookie_value: str | None, accept_language: str | None) -> str:
    """Pick the active UI language: the `lang` cookie, then `Accept-Language`, then English.

    Args:
        cookie_value: the `lang` cookie's value, if any.
        accept_language: the request's `Accept-Language` header, if any.

    Returns:
        One of `SUPPORTED_LANGUAGES`.
    """
    if cookie_value in SUPPORTED_LANGUAGES:
        return cookie_value
    if accept_language:
        for part in accept_language.split(","):
            tag = part.split(";")[0].strip().lower()
            primary = tag.split("-")[0]
            if primary in SUPPORTED_LANGUAGES:
                return primary
    return DEFAULT_LANGUAGE


def _header_value(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _cookie_value(headers: list[tuple[bytes, bytes]], name: str) -> str | None:
    cookie_header = _header_value(headers, b"cookie")
    if not cookie_header:
        return None
    jar: SimpleCookie = SimpleCookie()
    try:
        jar.load(cookie_header)
    except ValueError:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


class LanguageMiddleware:
    """Sets `current_language` for the running request from the `lang` cookie or headers."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Set `current_language` for the request's task context, then call the app."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        language = negotiate_language(
            _cookie_value(headers, LANG_COOKIE_NAME), _header_value(headers, b"accept-language")
        )
        token = current_language.set(language)
        try:
            await self._app(scope, receive, send)
        finally:
            current_language.reset(token)
