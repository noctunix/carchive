"""Imports the manufacturer's Data Dictionary PDFs into `catalog_entries`.

Table extraction uses `pdfplumber` (MIT); table geometry detection is its own built-in line
finder, not something modeled here. The dictionaries' table shape (`Key | Data Point Name |
Description | Measurement Unit | Tech. Data Type | Data Cluster`, the last column absent for
the historical dictionary) was documented from the manufacturer's PDFs themselves, not
derived from any third-party source.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pdfplumber
import structlog
from pdfplumber.pdf import PDF

from carchive.storage.db import Database
from carchive.storage.records import CatalogEntryInput, CatalogEntryRecord

# Re-exported (the explicit `as` tells mypy strict this is deliberate, not an unused
# import) so `cli`, which may not import `storage` directly, can still type `list_versions`'s
# result.
from carchive.storage.records import CatalogVersionSummary as CatalogVersionSummary
from carchive.storage.repositories import CatalogEntryRepository

logger = structlog.get_logger(__name__)

_MAX_PDF_BYTES = 50 * 1024 * 1024
_MAX_PDF_PAGES = 3000
_TITLE_SCAN_PAGES = 2

_CONTINUOUS_MARK = "continuous data"
_HISTORICAL_MARK = "historical data"

# The dictionary content bundled with this version of Carchive: extracted once (see
# `scripts/generate_catalog_seed.py`) from the manufacturer's own PDFs, under the licence
# basis the owner confirmed for distributing the descriptive content, not just the bare
# key list.
_BUNDLED_PROVIDER_ID = "vwgroup-euda"
_BUNDLED_CATALOG_PATH = (
    Path(__file__).resolve().parent.parent / "providers" / "vwgroup" / "data" / "catalog_v6.json"
)

# A unit/type cell showing only a placeholder dash means "not given", not a literal value;
# both plain "-" and the dictionary's own "'-" spelling occur.
_PLACEHOLDER_CELLS = frozenset({"", "-", "'-"})

_VERSION_IN_FILENAME = re.compile(r"V(\d+(?:\.\d+)*)", re.IGNORECASE)
_DATE_PREFIX = re.compile(r"^(\d{8})")

_WHITESPACE = re.compile(r"\s+")


class CatalogError(ValueError):
    """Raised for an unreadable, oversized, or unrecognizable dictionary PDF."""


@dataclass(frozen=True, slots=True)
class CatalogImportResult:
    """Outcome of `CatalogService.import_pdf`."""

    kind: str
    new: int
    updated: int
    duplicate_keys_in_file: int


def default_catalog_version(filename: str) -> str:
    """Derive a catalog version from a dictionary PDF's filename.

    Args:
        filename: the file's name (not a full path), e.g.
            `20260724_DataDictionary_Long Version_V6.0_Continuous_Data.pdf`.

    Returns:
        The dotted version after a `V` (e.g. `"6.0"`) if the filename contains one, else
        the leading `YYYYMMDD` date prefix.

    Raises:
        CatalogError: if neither pattern is found; the caller must then pass the catalog
            version explicitly.
    """
    version_match = _VERSION_IN_FILENAME.search(filename)
    if version_match:
        return version_match.group(1)
    date_match = _DATE_PREFIX.match(filename)
    if date_match:
        return date_match.group(1)
    raise CatalogError(
        f"cannot derive a catalog version from filename {filename!r}; pass it explicitly"
    )


def _clean_name(raw: str | None) -> str:
    """Remove every whitespace character, including one that broke a name mid-word."""
    return "".join((raw or "").split())


def _clean_description(raw: str | None) -> str | None:
    normalized = _WHITESPACE.sub(" ", raw or "").strip()
    return normalized or None


def _clean_optional_cell(raw: str | None) -> str | None:
    stripped = (raw or "").strip()
    return stripped if stripped not in _PLACEHOLDER_CELLS else None


def _is_uuid(candidate: str | None) -> bool:
    if candidate is None:
        return False
    try:
        uuid.UUID(candidate.strip())
    except ValueError:
        return False
    return True


def _detect_kind(pdf: PDF) -> str:
    """Determine continuous/historical from the title shown on the first few pages.

    Raises:
        CatalogError: if neither "Continuous Data" nor "Historical Data" appears.
    """
    text = " ".join(page.extract_text().lower() for page in pdf.pages[:_TITLE_SCAN_PAGES])
    if _HISTORICAL_MARK in text:
        return "historical"
    if _CONTINUOUS_MARK in text:
        return "continuous"
    raise CatalogError(
        "could not determine whether this is a continuous or historical data dictionary"
    )


def _parse_row(row: Sequence[str | None], kind: str) -> CatalogEntryInput | None:
    """Turn one table row into a `CatalogEntryInput`, or `None` if it is not a data row."""
    if not row or not _is_uuid(row[0]):
        return None
    clusters: list[str] | None = None
    if kind == "continuous":
        raw_clusters = row[5] if len(row) > 5 else None
        if raw_clusters:
            clusters = [part.strip() for part in raw_clusters.split(",") if part.strip()]
    assert row[0] is not None  # narrowed by `_is_uuid` above
    return CatalogEntryInput(
        key=row[0].strip(),
        name=_clean_name(row[1] if len(row) > 1 else None),
        description=_clean_description(row[2] if len(row) > 2 else None),
        unit=_clean_optional_cell(row[3] if len(row) > 3 else None),
        data_type=_clean_optional_cell(row[4] if len(row) > 4 else None),
        clusters=clusters,
    )


def _parse_rows(pdf: PDF, kind: str) -> tuple[list[CatalogEntryInput], int]:
    """Extract every valid data row across every page of `pdf`.

    Returns:
        The parsed entries, last occurrence of a repeated key winning, and how many
        duplicate keys were collapsed in the process.
    """
    by_key: dict[str, CatalogEntryInput] = {}
    duplicates = 0
    for page in pdf.pages:
        for table in page.extract_tables():
            for row in table:
                entry = _parse_row(row, kind)
                if entry is None:
                    continue
                if entry.key in by_key:
                    duplicates += 1
                by_key[entry.key] = entry
    return list(by_key.values()), duplicates


def _parse_pdf(path: Path) -> tuple[str, list[CatalogEntryInput], int]:
    """Blocking parse of `path`; run via `asyncio.to_thread` by `CatalogService.import_pdf`.

    Raises:
        CatalogError: if the PDF has more pages than `_MAX_PDF_PAGES`, or its kind cannot
            be determined.
    """
    with pdfplumber.open(path) as pdf:
        if len(pdf.pages) > _MAX_PDF_PAGES:
            raise CatalogError(f"{path.name} has more than {_MAX_PDF_PAGES} pages")
        kind = _detect_kind(pdf)
        entries, duplicates = _parse_rows(pdf, kind)
    return kind, entries, duplicates


def _load_bundled_entries() -> tuple[str, dict[str, list[CatalogEntryInput]]]:
    """Read the dictionary content bundled with this Carchive version.

    Returns:
        The bundled catalog version, and its entries grouped by kind
        (`continuous`/`historical`).
    """
    raw = json.loads(_BUNDLED_CATALOG_PATH.read_text(encoding="utf-8"))
    by_kind: dict[str, list[CatalogEntryInput]] = {}
    for entry in raw["entries"]:
        by_kind.setdefault(entry["kind"], []).append(
            CatalogEntryInput(
                key=entry["key"],
                name=entry["name"],
                description=entry["description"],
                unit=entry["unit"],
                data_type=entry["data_type"],
                clusters=entry["clusters"],
            )
        )
    return raw["catalog_version"], by_kind


class CatalogService:
    """Imports Data Dictionary PDFs and looks up the imported catalog entries.

    Args:
        db: the database to write imported entries into and read them back from.
    """

    def __init__(self, db: Database) -> None:
        self._db = db
        self._catalog = CatalogEntryRepository()

    async def import_pdf(
        self, path: Path, provider_id: str, catalog_version: str
    ) -> CatalogImportResult:
        """Parse `path` and upsert its entries into `catalog_entries`.

        Args:
            path: the dictionary PDF to import; must already be a regular, readable file.
            provider_id: the provider this dictionary belongs to.
            catalog_version: the version to store every parsed entry under.

        Returns:
            The detected kind, how many entries were new/updated, and how many duplicate
            keys the file itself contained.

        Raises:
            CatalogError: if the file exceeds the size or page limit, or its kind
                (continuous/historical) cannot be determined from its first pages.
        """
        size = path.stat().st_size
        if size > _MAX_PDF_BYTES:
            raise CatalogError(f"{path.name} exceeds the {_MAX_PDF_BYTES} byte limit")

        kind, entries, duplicates = await asyncio.to_thread(_parse_pdf, path)
        logger.info(
            "catalog.import.parsed",
            provider_id=provider_id,
            catalog_version=catalog_version,
            kind=kind,
            entries=len(entries),
            duplicate_keys_in_file=duplicates,
        )

        async with self._db.write() as conn:
            counts = await self._catalog.upsert_many(
                conn,
                provider_id=provider_id,
                catalog_version=catalog_version,
                kind=kind,
                entries=entries,
            )

        return CatalogImportResult(
            kind=kind,
            new=counts.new,
            updated=counts.updated,
            duplicate_keys_in_file=duplicates,
        )

    async def lookup(self, provider_id: str, keys: Sequence[str]) -> dict[str, CatalogEntryRecord]:
        """Return the newest catalog entry per key in `keys`, for keys that were imported."""
        async with self._db.read() as conn:
            return await self._catalog.latest_for_keys(conn, provider_id, keys)

    async def list_versions(self) -> list[CatalogVersionSummary]:
        """List every imported catalog version, with its kind and entry count."""
        async with self._db.read() as conn:
            return await self._catalog.list_versions(conn)

    async def seed_bundled(self) -> None:
        """Insert the dictionary content bundled with this Carchive version, once.

        No-ops once `(_BUNDLED_PROVIDER_ID, <bundled version>)` already has entries,
        whether from a previous seeding or someone's own import under that exact version
        string - never overwrites a real import. Intended to run once per `serve` start;
        cheap to call repeatedly since it exits after the first, read-only check.
        """
        catalog_version, by_kind = _load_bundled_entries()
        async with self._db.read() as conn:
            versions = await self._catalog.list_versions(conn)
        if any(
            v.provider_id == _BUNDLED_PROVIDER_ID and v.catalog_version == catalog_version
            for v in versions
        ):
            return

        async with self._db.write() as conn:
            for kind, entries in by_kind.items():
                await self._catalog.upsert_many(
                    conn,
                    provider_id=_BUNDLED_PROVIDER_ID,
                    catalog_version=catalog_version,
                    kind=kind,
                    entries=entries,
                )
        logger.info(
            "catalog.bundled_seeded",
            provider_id=_BUNDLED_PROVIDER_ID,
            catalog_version=catalog_version,
            entries=sum(len(e) for e in by_kind.values()),
        )
