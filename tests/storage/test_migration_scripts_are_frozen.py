"""Guards against migration scripts drifting along with `storage.schema`."""

from __future__ import annotations

import ast
from pathlib import Path

_VERSIONS_DIR = (
    Path(__file__).parent.parent.parent / "src" / "carchive" / "storage" / "migrations" / "versions"
)


_FORBIDDEN_MODULE = "carchive.storage.schema"


def _imports_storage_schema(source: str) -> bool:
    """Return whether `source` imports `carchive.storage.schema`, in any import style."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            targets = [f"{node.module}.{alias.name}" for alias in node.names] + [node.module]
        else:
            continue
        if any(t == _FORBIDDEN_MODULE or t.startswith(f"{_FORBIDDEN_MODULE}.") for t in targets):
            return True
    return False


def test_no_migration_script_imports_storage_schema() -> None:
    """A migration is a frozen snapshot; importing `schema` would let it track live changes."""
    offenders = [
        path.name
        for path in sorted(_VERSIONS_DIR.glob("*.py"))
        if _imports_storage_schema(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"migration scripts importing carchive.storage.schema: {offenders}"


def test_detector_catches_every_import_style() -> None:
    assert _imports_storage_schema("import carchive.storage.schema\n")
    assert _imports_storage_schema("from carchive.storage.schema import metadata\n")
    assert _imports_storage_schema("from carchive.storage import schema\n")
    assert _imports_storage_schema("from carchive.storage import db, schema\n")


def test_detector_does_not_flag_unrelated_storage_imports() -> None:
    assert _imports_storage_schema("from carchive.storage import db\n") is False
    assert _imports_storage_schema("from carchive.storage.types import UTCDateTime\n") is False


def test_detector_ignores_mentions_in_comments_and_docstrings() -> None:
    source = '"""Does not import carchive.storage.schema, see the module docstring."""\n'
    assert _imports_storage_schema(source) is False
