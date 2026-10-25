"""The Jinja2 environment every route renders through, wired for per-request i18n."""

from __future__ import annotations

import gettext
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from babel.dates import format_datetime
from babel.numbers import format_decimal
from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import DictLoader, Environment, select_autoescape

from carchive.web.i18n import DEFAULT_LANGUAGE, current_language

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# English source text per canonical signal; German translations live in the `.po` catalog
# like every other template string. The raw `signal` name is shown too (small, detail page
# only), since it is also the provider's own catalog key a user might search for.
_SIGNAL_LABEL_MESSAGES: dict[str, str] = {
    "vehicle.odometer": "Odometer",
    "battery.soc": "State of charge (SoC)",
    "fuel.level": "Fuel level",
    "range.primary": "Range",
    "climate.outdoor_temperature": "Outdoor temperature",
    "battery.temperature": "Battery temperature",
    "charging.state": "Charging state",
    "charging.power": "Charging power",
    "plug.connection_state": "Plug",
}

# Proper nouns, not translated; a brand not in this table (a future provider) falls back to
# capitalizing its raw, lowercase id rather than showing it unchanged.
_BRAND_LABELS: dict[str, str] = {
    "audi": "Audi",
    "volkswagen": "Volkswagen",
    "vw": "Volkswagen",
    "skoda": "Škoda",
    "seat": "SEAT",
    "cupra": "CUPRA",
}

_BABEL_LOCALES: dict[str, str] = {"en": "en_US", "de": "de_DE"}

# Signals shown with two decimal digits instead of the usual one, when their value is not
# already a whole number.
_TWO_DECIMAL_SIGNALS = frozenset({"charging.power"})


def _read_templates() -> dict[str, str]:
    return {
        path.relative_to(_TEMPLATES_DIR).as_posix(): path.read_text(encoding="utf-8")
        for path in _TEMPLATES_DIR.rglob("*.html")
    }


def build_templates(translations: dict[str, gettext.NullTranslations]) -> Jinja2Templates:
    """Build the Jinja2 environment used to render every page.

    Args:
        translations: gettext-compatible translations per supported language, as returned
            by `web.i18n.load_translations`.

    Returns:
        A `Jinja2Templates` whose `{% trans %}`/`_()` calls resolve against the language
        active for the request currently being rendered (`web.i18n.current_language`), and
        whose templates automatically receive `csrf_token`, `language` and `authenticated` in
        their context.
    """
    env = Environment(
        # Every template is read once, here, at process start. Route handlers are plain
        # Python imported once too, so a reinstall onto a *running* server (new files on
        # disk, same process) must not reach the templates either: a template loaded lazily
        # after the reinstall would expect context keys its stale route never sets and fail
        # with "is undefined". Old templates with old routes until the next restart is the
        # predictable behavior.
        loader=DictLoader(_read_templates()),
        auto_reload=False,
        autoescape=select_autoescape(["html"]),
        extensions=["jinja2.ext.i18n"],
    )

    def gettext_(message: str) -> str:
        return translations[current_language.get()].gettext(message)

    def ngettext_(singular: str, plural: str, n: int) -> str:
        return translations[current_language.get()].ngettext(singular, plural, n)

    # jinja2.ext.i18n attaches `install_gettext_callables` to the Environment instance at
    # extension-init time (`Environment.extend`), so it is not in Environment's own type
    # stubs; the `_()` global the extension installs resolves through it automatically.
    cast(Any, env).install_gettext_callables(gettext_, ngettext_, newstyle=True)

    def age_filter(seconds: float | None) -> str:
        """Render an age in seconds as a localized "n h ago"/"n d ago" string.

        Below 48 hours the age is shown in whole hours, at or beyond that in whole days,
        so a "measured 3 h ago" never flips to "0 d ago" right after midnight-like
        rounding would suggest.
        """
        if seconds is None:
            return gettext_("unknown")
        hours = max(0, int(seconds // 3600))
        if hours < 48:
            return gettext_("%(hours)s h ago") % {"hours": hours}
        days = max(0, int(seconds // 86400))
        return gettext_("%(days)s d ago") % {"days": days}

    def duration_filter(seconds: float | None) -> str:
        """Render a duration in seconds as a plain "n h"/"n d" string, with no "ago"/"vor".

        For notice sentences that already supply their own preposition ("is 3 d old",
        "in 2 h"); the hour/day abbreviation is the same in English and German, so unlike
        `age_filter` this needs no translation.
        """
        if seconds is None:
            return gettext_("unknown")
        hours = max(0, int(seconds // 3600))
        if hours < 48:
            return f"{hours} h"
        days = max(0, int(seconds // 86400))
        return f"{days} d"

    def freshness_label_filter(level: str) -> str:
        """Translate a `core.timeutil.Freshness` value into its visible text marker."""
        labels = {
            "fresh": gettext_("fresh"),
            "aging": gettext_("aging"),
            "stale": gettext_("stale"),
            "unknown": gettext_("unknown"),
        }
        return labels.get(level, level)

    def signal_label_filter(signal: str) -> str:
        """Translate a canonical signal name into its display label.

        Returns `signal` unchanged if it is not one of the known canonical signals (an
        unmapped provider key shown raw elsewhere should look the same here).
        """
        message = _SIGNAL_LABEL_MESSAGES.get(signal)
        return gettext_(message) if message is not None else signal

    def brand_label_filter(brand: str) -> str:
        """Return `brand`'s display name, or its capitalized id if it is not known."""
        return _BRAND_LABELS.get(brand.lower(), brand.capitalize())

    def format_number_filter(value: object, signal: str | None = None) -> object:
        """Render a numeric signal value in the active language's locale.

        A whole number is shown with no decimals; otherwise with at most one decimal digit
        (two for `signal`s in `_TWO_DECIMAL_SIGNALS`, e.g. charging power), rounded rather
        than padded. Anything that is not a plain `int`/`float` (an enum value, `None`) is
        returned unchanged, since locale formatting only makes sense for measurements.
        """
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return value
        locale = _BABEL_LOCALES.get(current_language.get(), "en_US")
        if float(value).is_integer():
            pattern = "#,##0"
        else:
            max_decimals = 2 if signal in _TWO_DECIMAL_SIGNALS else 1
            pattern = "#,##0." + "#" * max_decimals
        return format_decimal(value, format=pattern, locale=locale)

    def datetime_filter(value: object) -> object:
        """Render an aware datetime in the server's local time zone and the active locale.

        Anything that is not a `datetime` is returned unchanged.
        """
        if not isinstance(value, datetime):
            return value
        locale = _BABEL_LOCALES.get(current_language.get(), "en_US")
        return format_datetime(value.astimezone(), format="medium", locale=locale)

    def filesize_filter(value: object) -> object:
        """Render a byte count as a short, human-readable size (B/kB/MB/...).

        Anything that is not a plain `int` is returned unchanged.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            return value
        size = float(value)
        for unit in ("B", "kB", "MB", "GB", "TB"):
            if size < 1000 or unit == "TB":
                return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1000
        return f"{value} B"  # unreachable, satisfies static analysis of the loop above

    env.filters["datetime"] = datetime_filter
    env.filters["age"] = age_filter
    env.filters["duration"] = duration_filter
    env.filters["freshness_label"] = freshness_label_filter
    env.filters["signal_label"] = signal_label_filter
    env.filters["brand_label"] = brand_label_filter
    env.filters["format_number"] = format_number_filter
    env.filters["filesize"] = filesize_filter

    def _request_context(request: Request) -> dict[str, Any]:
        state = request.scope.get("state", {})
        return {
            "csrf_token": state.get("csrf_token", ""),
            "language": current_language.get(DEFAULT_LANGUAGE),
            "authenticated": bool(state.get("authenticated", False)),
            "app_version": getattr(request.app.state, "app_version", ""),
        }

    return Jinja2Templates(env=env, context_processors=[_request_context])
