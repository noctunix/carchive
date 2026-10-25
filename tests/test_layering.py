"""Architecture test: enforces the layer dependency rule.

`core` imports nothing from the package except `core`; `config` imports only `core` (and
itself); `providers` and `storage` import only `core` (and themselves); `services` imports
`core`, `providers`, `storage`, `config` (and itself); `web` and `cli` import `services`,
`core` and `config` (and themselves); `cli` may also import `logging_setup`, `web` and
`bootstrap`. `logging_setup` may import `core` for redaction. `bootstrap` is the
composition root and may import any layer, but only `cli` may import `bootstrap` itself.
Nothing outside `providers/vwgroup` may mention VW-group-specific portal identifiers.

One narrow exception: `cli` may import `storage.migrate` directly, so `db upgrade`/`db
status` can drive Alembic without a `services` module that would only wrap two functions.
No other `storage` module is reachable from `cli`.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).parent.parent / "src" / "carchive"

_ALLOWED: dict[str, set[str]] = {
    "core": {"core"},
    "config": {"core", "config"},
    "providers": {"core", "providers"},
    "storage": {"core", "storage"},
    "services": {"core", "providers", "storage", "services", "config"},
    "web": {"core", "services", "web", "config"},
    "cli": {"core", "services", "web", "cli", "logging_setup", "root", "config", "bootstrap"},
    "logging_setup": {"logging_setup", "core"},
    "bootstrap": {"core", "providers", "storage", "services", "config", "bootstrap", "root"},
    "root": {"root"},
    "__main__": {"cli", "root", "__main__"},
}

_FORBIDDEN_STRINGS = ("drivesomethinggreater", "vwgroup.io")
_PROVIDER_EXCEPTION = Path("providers") / "vwgroup"

# Module-level exceptions to _ALLOWED: (source layer, exact dotted target) pairs that are
# permitted even though the target's layer is otherwise off-limits for that source layer.
_NARROW_EXCEPTIONS: set[tuple[str, str]] = {
    ("cli", "storage.migrate"),
}


def _module_name(py_file: Path, package_root: Path, package: str) -> tuple[str, bool]:
    """Return the dotted module name of `py_file` and whether it is a package (`__init__.py`)."""
    rel = py_file.relative_to(package_root).with_suffix("")
    is_package = rel.name == "__init__"
    parts = [package, *rel.parts[:-1]] if is_package else [package, *rel.parts]
    return ".".join(parts), is_package


def _resolve_import(module_name: str, is_package: bool, level: int, from_module: str | None) -> str:
    """Resolve an `ast.ImportFrom` target to a dotted module name.

    `level` is 0 for an absolute import (then `from_module` is the full target) and >=1 for
    a relative import, counted the way Python's import system counts dots in `from . import x`.
    """
    if level == 0:
        return from_module or ""
    base_parts = module_name.split(".") if is_package else module_name.split(".")[:-1]
    up = level - 1
    if up:
        base_parts = base_parts[: len(base_parts) - up] if up <= len(base_parts) else []
    base = ".".join(base_parts)
    if from_module:
        return f"{base}.{from_module}" if base else from_module
    return base


def _layer(module: str, package: str) -> str | None:
    """Return the layer name for a dotted module belonging to `package`, or None if external."""
    parts = module.split(".")
    if parts[0] != package:
        return None
    if len(parts) == 1:
        return "root"
    return parts[1]


def _imported_targets(tree: ast.Module, module_name: str, is_package: bool) -> list[str]:
    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            targets.append(_resolve_import(module_name, is_package, node.level, node.module))
    return targets


def check_layering(package_root: Path, package: str) -> list[str]:
    """Check every `.py` file under `package_root` against the layer dependency rule.

    Args:
        package_root: directory holding the package's own files (e.g. `src/carchive`).
        package: the package's dotted name as it appears in its own imports (e.g. "carchive").

    Returns:
        One human-readable violation message per disallowed import, empty if the tree is clean.
    """
    violations = []
    for py_file in sorted(package_root.rglob("*.py")):
        module_name, is_package = _module_name(py_file, package_root, package)
        source_layer = _layer(module_name, package)
        if source_layer is None:
            continue
        allowed = _ALLOWED.get(source_layer)
        if allowed is None:
            violations.append(
                f"{py_file.relative_to(package_root)}: layer {source_layer!r} is not in the "
                f"architecture (expected one of {sorted(_ALLOWED)})"
            )
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for target in _imported_targets(tree, module_name, is_package):
            target_layer = _layer(target, package)
            if target_layer is None or target_layer == source_layer:
                continue
            if target_layer not in allowed:
                target_suffix = ".".join(target.split(".")[1:])
                if (source_layer, target_suffix) in _NARROW_EXCEPTIONS:
                    continue
                violations.append(
                    f"{py_file.relative_to(package_root)} (layer {source_layer!r}) imports "
                    f"{target!r} (layer {target_layer!r}), which is not allowed"
                )
    return violations


def find_vwgroup_leaks(package_root: Path) -> list[str]:
    """Find files outside `providers/vwgroup` that mention VW-group-specific identifiers."""
    leaks = []
    for py_file in sorted(package_root.rglob("*.py")):
        rel = py_file.relative_to(package_root)
        if _PROVIDER_EXCEPTION in rel.parents or rel.parent == _PROVIDER_EXCEPTION:
            continue
        text = py_file.read_text(encoding="utf-8")
        for needle in _FORBIDDEN_STRINGS:
            if needle in text:
                leaks.append(f"{rel} contains {needle!r}, which belongs only in providers/vwgroup")
    return leaks


def test_carchive_layering_is_clean() -> None:
    violations = check_layering(SRC_ROOT, "carchive")
    assert not violations, "layering violations:\n" + "\n".join(violations)


def test_no_vwgroup_specifics_outside_provider() -> None:
    leaks = find_vwgroup_leaks(SRC_ROOT)
    assert not leaks, "VW-group specifics leaked outside providers/vwgroup:\n" + "\n".join(leaks)


def test_checker_detects_a_bad_import_graph(tmp_path: Path) -> None:
    package_root = tmp_path / "badpkg"
    (package_root / "core").mkdir(parents=True)
    (package_root / "web").mkdir(parents=True)
    (package_root / "core" / "__init__.py").write_text("")
    (package_root / "core" / "models.py").write_text("import badpkg.web\n")
    (package_root / "web" / "__init__.py").write_text("")

    violations = check_layering(package_root, "badpkg")

    assert len(violations) == 1
    assert "core" in violations[0] and "web" in violations[0]


def test_only_cli_may_import_bootstrap(tmp_path: Path) -> None:
    package_root = tmp_path / "badpkg"
    (package_root / "cli").mkdir(parents=True)
    (package_root / "web").mkdir(parents=True)
    (package_root / "bootstrap").mkdir(parents=True)
    (package_root / "cli" / "__init__.py").write_text("")
    (package_root / "cli" / "ok.py").write_text("from badpkg.bootstrap import build_services\n")
    (package_root / "web" / "__init__.py").write_text("")
    (package_root / "web" / "bad.py").write_text("from badpkg.bootstrap import build_services\n")
    (package_root / "bootstrap" / "__init__.py").write_text("")

    violations = check_layering(package_root, "badpkg")

    assert len(violations) == 1
    assert "bad.py" in violations[0]


def test_cli_may_import_storage_migrate_but_nothing_else_in_storage(tmp_path: Path) -> None:
    package_root = tmp_path / "badpkg"
    (package_root / "cli").mkdir(parents=True)
    (package_root / "storage").mkdir(parents=True)
    (package_root / "cli" / "__init__.py").write_text("")
    (package_root / "cli" / "ok.py").write_text("from badpkg.storage.migrate import upgrade\n")
    (package_root / "cli" / "bad.py").write_text("from badpkg.storage.schema import metadata\n")
    (package_root / "storage" / "__init__.py").write_text("")
    (package_root / "storage" / "migrate.py").write_text("")
    (package_root / "storage" / "schema.py").write_text("")

    violations = check_layering(package_root, "badpkg")

    assert len(violations) == 1
    assert "bad.py" in violations[0]
