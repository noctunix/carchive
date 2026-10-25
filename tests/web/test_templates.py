"""Static checks over every template: no inline scripts, no inline styles."""

from __future__ import annotations

import re
from pathlib import Path

_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "src" / "carchive" / "web" / "templates"

_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
_INLINE_STYLE_ATTR = re.compile(r"\bstyle\s*=", re.IGNORECASE)


def test_no_inline_scripts_without_src() -> None:
    for template in sorted(_TEMPLATES_DIR.glob("*.html")):
        text = template.read_text(encoding="utf-8")
        matches = _INLINE_SCRIPT.findall(text)
        assert not matches, f"{template.name} has an inline <script> without src: {matches}"


def test_no_inline_style_attributes() -> None:
    for template in sorted(_TEMPLATES_DIR.glob("*.html")):
        text = template.read_text(encoding="utf-8")
        assert not _INLINE_STYLE_ATTR.search(text), f"{template.name} has an inline style= attr"
