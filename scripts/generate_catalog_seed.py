#!/usr/bin/env python3
"""Regenerate the bundled VW-group Data Dictionary seed from a local extraction.

One-off maintenance script, not shipped with the package. Run it again only when a new
Data Dictionary version needs to be bundled, against a fresh local extraction.

Usage:
    uv run python scripts/generate_catalog_seed.py <source.json> <catalog-version>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from carchive.services.catalog import (  # noqa: E402 - path setup must come first
    _clean_description,
    _clean_name,
    _clean_optional_cell,
)

_OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "carchive"
    / "providers"
    / "vwgroup"
    / "data"
    / "catalog_v6.json"
)


def _convert(source: dict[str, dict[str, str]]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for raw in source.values():
        kind = raw["kind"]
        clusters: list[str] | None = None
        if kind == "continuous":
            raw_clusters = raw.get("cluster", "")
            clusters = [part.strip() for part in raw_clusters.split(",") if part.strip()]
        entries.append(
            {
                "key": raw["key"].strip(),
                "name": _clean_name(raw.get("name")),
                "description": _clean_description(raw.get("desc")),
                "unit": _clean_optional_cell(raw.get("unit")),
                "data_type": _clean_optional_cell(raw.get("type")),
                "clusters": clusters,
                "kind": kind,
            }
        )
    entries.sort(key=lambda e: (str(e["kind"]), str(e["key"])))
    return entries


def main() -> int:
    """Convert `sys.argv[1]` into the bundled catalog seed, under `sys.argv[2]`'s version."""
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    source_path = Path(sys.argv[1])
    catalog_version = sys.argv[2]

    source = json.loads(source_path.read_text(encoding="utf-8"))
    entries = _convert(source)

    output = {"catalog_version": catalog_version, "entries": entries}
    _OUTPUT_PATH.write_text(
        json.dumps(output, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(entries)} entries to {_OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
