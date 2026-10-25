"""Tests for `carchive.services.catalog`."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest

from carchive.services.catalog import CatalogError, CatalogService, default_catalog_version
from carchive.storage.db import Database
from carchive.storage.migrate import upgrade_to_head
from carchive.storage.records import CatalogEntryInput
from tests.services.pdf_fixtures import (
    CONTINUOUS_HEADER,
    HISTORICAL_HEADER,
    build_dictionary_pdf,
)


def _key(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


@pytest.fixture
async def db(tmp_path: Path) -> AsyncGenerator[Database]:
    db_path = tmp_path / "carchive.sqlite3"
    await upgrade_to_head(db_path)
    database = Database()
    await database.connect(db_path)
    yield database
    await database.close()


class TestDefaultCatalogVersion:
    def test_extracts_dotted_version_from_filename(self) -> None:
        name = "20260724_DataDictionary_Long Version_V6.0_Continuous_Data.pdf"
        assert default_catalog_version(name) == "6.0"

    def test_falls_back_to_date_prefix(self) -> None:
        assert default_catalog_version("20260724_some_other_naming.pdf") == "20260724"

    def test_raises_when_neither_pattern_matches(self) -> None:
        with pytest.raises(CatalogError):
            default_catalog_version("dictionary.pdf")


class TestImportPdf:
    async def test_parses_rows_across_several_pages(self, db: Database, tmp_path: Path) -> None:
        rows = [
            [_key(f"field{i}"), f"field_{i}", f"desc of field {i}", "%", "float", "Cluster A"]
            for i in range(80)
        ]
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path, title="List of Continuous Data", header=CONTINUOUS_HEADER, rows=rows
        )

        result = await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

        assert result.kind == "continuous"
        assert result.new == 80
        assert result.updated == 0
        assert result.duplicate_keys_in_file == 0

        found = await CatalogService(db).lookup("vwgroup-euda", [_key("field0"), _key("field79")])
        assert found[_key("field0")].name == "field_0"
        assert found[_key("field79")].name == "field_79"
        assert found[_key("field0")].clusters == ["Cluster A"]

    async def test_cleans_a_name_broken_by_an_embedded_space(
        self, db: Database, tmp_path: Path
    ) -> None:
        key = _key("wrapped")
        rows = [[key, "timers.[*].activation_stat e", "desc", "-", "'-", "Cluster A"]]
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path, title="List of Continuous Data", header=CONTINUOUS_HEADER, rows=rows
        )

        await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

        found = await CatalogService(db).lookup("vwgroup-euda", [key])
        assert found[key].name == "timers.[*].activation_state"
        assert found[key].unit is None
        assert found[key].data_type is None

    async def test_parses_a_cluster_list(self, db: Database, tmp_path: Path) -> None:
        key = _key("multi-cluster")
        rows = [[key, "field", "desc", "%", "float", "Cluster A, Cluster B"]]
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path, title="List of Continuous Data", header=CONTINUOUS_HEADER, rows=rows
        )

        await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

        found = await CatalogService(db).lookup("vwgroup-euda", [key])
        assert found[key].clusters == ["Cluster A", "Cluster B"]

    async def test_historical_dictionary_has_no_clusters(
        self, db: Database, tmp_path: Path
    ) -> None:
        key = _key("hist")
        rows = [[key, "powerCurve.[*].soc", "desc", "%", "float"]]
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path, title="List of Historical Data", header=HISTORICAL_HEADER, rows=rows
        )

        result = await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

        assert result.kind == "historical"
        found = await CatalogService(db).lookup("vwgroup-euda", [key])
        assert found[key].clusters is None

    async def test_counts_duplicate_keys_and_keeps_the_last_one(
        self, db: Database, tmp_path: Path
    ) -> None:
        key = _key("dup")
        rows = [
            [key, "first-name", "desc", "%", "float", "Cluster A"],
            [key, "second-name", "desc", "%", "float", "Cluster A"],
        ]
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path, title="List of Continuous Data", header=CONTINUOUS_HEADER, rows=rows
        )

        result = await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

        assert result.new == 1
        assert result.duplicate_keys_in_file == 1
        found = await CatalogService(db).lookup("vwgroup-euda", [key])
        assert found[key].name == "second-name"

    async def test_updating_an_existing_version_reports_updated_not_new(
        self, db: Database, tmp_path: Path
    ) -> None:
        key = _key("field")
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path,
            title="List of Continuous Data",
            header=CONTINUOUS_HEADER,
            rows=[[key, "a", "desc", "%", "float", "Cluster A"]],
        )
        await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

        path2 = tmp_path / "dict2.pdf"
        build_dictionary_pdf(
            path2,
            title="List of Continuous Data",
            header=CONTINUOUS_HEADER,
            rows=[[key, "b", "desc", "%", "float", "Cluster A"]],
        )
        result = await CatalogService(db).import_pdf(path2, "vwgroup-euda", "6.0")

        assert result.new == 0
        assert result.updated == 1

    async def test_rejects_a_pdf_with_no_recognizable_kind(
        self, db: Database, tmp_path: Path
    ) -> None:
        key = _key("field")
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path,
            title="Some Other Document",
            header=CONTINUOUS_HEADER,
            rows=[[key, "a", "desc", "%", "float", "Cluster A"]],
        )

        with pytest.raises(CatalogError):
            await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

    async def test_rejects_a_file_larger_than_the_size_limit(
        self, db: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import carchive.services.catalog as catalog_module

        monkeypatch.setattr(catalog_module, "_MAX_PDF_BYTES", 10)
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path,
            title="List of Continuous Data",
            header=CONTINUOUS_HEADER,
            rows=[[_key("f"), "a", "desc", "%", "float", "Cluster A"]],
        )

        with pytest.raises(CatalogError):
            await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

    async def test_rejects_a_pdf_with_too_many_pages(
        self, db: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import carchive.services.catalog as catalog_module

        monkeypatch.setattr(catalog_module, "_MAX_PDF_PAGES", 1)
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path,
            title="List of Continuous Data",
            header=CONTINUOUS_HEADER,
            rows=[[_key("f"), "a", "desc", "%", "float", "Cluster A"]],
        )

        with pytest.raises(CatalogError):
            await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")


class TestLookupAndListVersions:
    async def test_lookup_omits_keys_never_imported(self, db: Database) -> None:
        found = await CatalogService(db).lookup("vwgroup-euda", ["does-not-exist"])
        assert found == {}

    async def test_list_versions_reports_kind_and_count(self, db: Database, tmp_path: Path) -> None:
        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path,
            title="List of Continuous Data",
            header=CONTINUOUS_HEADER,
            rows=[[_key("a"), "a", "desc", "%", "float", "Cluster A"]],
        )
        await CatalogService(db).import_pdf(path, "vwgroup-euda", "6.0")

        versions = await CatalogService(db).list_versions()

        assert len(versions) == 1
        assert versions[0].catalog_version == "6.0"
        assert versions[0].kind == "continuous"
        assert versions[0].entry_count == 1


class TestSeedBundled:
    async def test_inserts_the_bundled_entries(
        self, db: Database, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import carchive.services.catalog as catalog_module

        monkeypatch.setattr(
            catalog_module,
            "_load_bundled_entries",
            lambda: (
                "6.0",
                {
                    "continuous": [
                        CatalogEntryInput(
                            key=_key("bundled-a"),
                            name="a",
                            description="desc",
                            unit="%",
                            data_type="float",
                            clusters=["Cluster A"],
                        )
                    ],
                    "historical": [
                        CatalogEntryInput(
                            key=_key("bundled-b"),
                            name="b",
                            description=None,
                            unit=None,
                            data_type=None,
                            clusters=None,
                        )
                    ],
                },
            ),
        )

        await CatalogService(db).seed_bundled()

        versions = await CatalogService(db).list_versions()
        by_kind = {v.kind: v for v in versions}
        assert by_kind["continuous"].catalog_version == "6.0"
        assert by_kind["continuous"].entry_count == 1
        assert by_kind["historical"].entry_count == 1

    async def test_does_not_reimport_once_the_bundled_version_is_present(
        self, db: Database, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import carchive.services.catalog as catalog_module

        calls = 0
        entries = {
            "continuous": [
                CatalogEntryInput(
                    key=_key("bundled-c"),
                    name="a",
                    description=None,
                    unit=None,
                    data_type=None,
                    clusters=["Cluster A"],
                )
            ]
        }

        def load() -> tuple[str, dict[str, list[CatalogEntryInput]]]:
            nonlocal calls
            calls += 1
            return "6.0", entries

        monkeypatch.setattr(catalog_module, "_load_bundled_entries", load)

        service = CatalogService(db)
        await service.seed_bundled()
        await service.seed_bundled()

        assert calls == 2  # loaded each time, but only upserted once
        versions = await service.list_versions()
        assert len(versions) == 1
        assert versions[0].entry_count == 1

    async def test_does_not_overwrite_a_real_import_under_the_same_version(
        self, db: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import carchive.services.catalog as catalog_module

        path = tmp_path / "dict.pdf"
        build_dictionary_pdf(
            path,
            title="List of Continuous Data",
            header=CONTINUOUS_HEADER,
            rows=[[_key("real-import"), "real", "desc", "%", "float", "Cluster A"]],
        )
        service = CatalogService(db)
        await service.import_pdf(path, "vwgroup-euda", "6.0")

        monkeypatch.setattr(
            catalog_module,
            "_load_bundled_entries",
            lambda: (
                "6.0",
                {
                    "continuous": [
                        CatalogEntryInput(
                            key=_key("bundled-d"),
                            name="bundled",
                            description=None,
                            unit=None,
                            data_type=None,
                            clusters=None,
                        )
                    ]
                },
            ),
        )

        await service.seed_bundled()

        versions = await service.list_versions()
        assert len(versions) == 1
        assert versions[0].entry_count == 1
        found = await service.lookup("vwgroup-euda", [_key("real-import")])
        assert found[_key("real-import")].name == "real"
