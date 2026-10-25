"""Tests for `providers.vwgroup.archive.extract_json`."""

from __future__ import annotations

import io
import zipfile

import pytest

from carchive.core.errors import ProviderError
from carchive.providers.vwgroup import archive


def _zip_with(files: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_extracts_the_single_json_member() -> None:
    data = _zip_with({"dataset.json": '{"vin": "x"}'})
    assert archive.extract_json(data) == b'{"vin": "x"}'


def test_rejects_an_archive_without_a_json_member() -> None:
    data = _zip_with({"readme.txt": "no json here"})
    with pytest.raises(ProviderError, match="no JSON"):
        archive.extract_json(data)


def test_rejects_too_many_members() -> None:
    data = _zip_with({f"f{i}.txt": "" for i in range(archive.MAX_ARCHIVE_MEMBERS + 1)})
    with pytest.raises(ProviderError, match="too many members"):
        archive.extract_json(data)


def test_rejects_oversized_json_member(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_JSON_BYTES", 10)
    data = _zip_with({"d.json": '{"Data": ["0123456789"]}'})
    with pytest.raises(ProviderError, match="size limit"):
        archive.extract_json(data)


@pytest.mark.parametrize(
    "member_name",
    [
        "../escape.json",
        "a/../../escape.json",
        "/etc/passwd.json",
        "a\\..\\escape.json",
    ],
)
def test_rejects_path_traversing_member_names(member_name: str) -> None:
    data = _zip_with({member_name: "{}"})
    with pytest.raises(ProviderError, match="unsafe member name"):
        archive.extract_json(data)


def test_rejects_non_utf8_json_member() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("d.json", b"\xff\xfe")
    with pytest.raises(ProviderError, match="UTF-8"):
        archive.extract_json(buf.getvalue())


def test_rejects_a_broken_zip() -> None:
    with pytest.raises(ProviderError, match="not a valid ZIP"):
        archive.extract_json(b"not a zip at all")


def test_picks_the_first_json_member_when_several_present() -> None:
    data = _zip_with({"a.json": '{"a": 1}', "b.json": '{"b": 2}'})
    assert archive.extract_json(data) == b'{"a": 1}'
