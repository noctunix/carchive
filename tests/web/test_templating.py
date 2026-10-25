"""The template environment is a snapshot taken at process start."""

from __future__ import annotations

import gettext
from pathlib import Path

import pytest

from carchive.web import templating


def test_templates_are_not_reread_from_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "page.html").write_text("old", encoding="utf-8")
    monkeypatch.setattr(templating, "_TEMPLATES_DIR", tmp_path)
    translations = {"en": gettext.NullTranslations(), "de": gettext.NullTranslations()}
    env = templating.build_templates(translations).env

    (tmp_path / "page.html").write_text("new", encoding="utf-8")
    (tmp_path / "added.html").write_text("added", encoding="utf-8")

    assert env.get_template("page.html").render() == "old"
    assert "added.html" not in env.list_templates()
