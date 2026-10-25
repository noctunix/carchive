"""Tests for captures_view.py against databases built by the sampler itself."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import captures_view as view
import eu_data_act_sampler as sampler


def _record(ts: str, field: str, value: str) -> dict[str, str]:
    return {"key": "k", "dataFieldName": field, "timestampUtc": ts, "value": value}


def _db(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name / "captures.sqlite3"
    conn = sampler._open_database(path)
    first = {"Data": [_record("2026-10-22T10:00:00Z", "mileage.value", "1000")]}
    second = {
        "Data": [
            _record("2026-10-22T11:00:00.123456789Z", "battery.soc", "80"),
            _record("2026-10-22T11:00:00Z", "mileage.value", "1010"),
        ]
    }
    sampler._store_capture(
        conn, sampler.DatasetInfo("20261022100000_V.zip", None), "partial", json.dumps(first)
    )
    sampler._store_placeholder(
        conn, sampler.DatasetInfo("20261022103000_V_no_content_found.zip", None), "partial", b"x"
    )
    sampler._store_capture(
        conn, sampler.DatasetInfo("20261022110000_V.zip", None), "partial", json.dumps(second)
    )
    sampler._store_capture(
        conn, sampler.DatasetInfo("20261022111500_V.zip", None), "all", '{"other": 1}'
    )
    conn.close()
    return path


def test_recent_files_lists_content_and_placeholders_newest_first(tmp_path: Path) -> None:
    rows = view.recent_files([("a6", _db(tmp_path, "a6"))], 10)
    assert [(r.created_at, r.has_content, r.records) for r in rows] == [
        ("2026-10-22T11:15:00Z", True, None),
        ("2026-10-22T11:00:00Z", True, 2),
        ("2026-10-22T10:30:00Z", False, 0),
        ("2026-10-22T10:00:00Z", True, 1),
    ]
    assert "unknown layout" in view.format_files(rows)
    assert len(view.recent_files([("a6", tmp_path / "a6" / "captures.sqlite3")], 2)) == 2


def test_recent_records_sorts_by_record_time_and_filters(tmp_path: Path) -> None:
    sources = [("a6", _db(tmp_path, "a6"))]
    records, unknown = view.recent_records(sources, 10)
    assert [(r.timestamp[:22], r.field, r.value) for r in records] == [
        ("2026-10-22T11:00:00.12", "battery.soc", "80"),
        ("2026-10-22T11:00:00Z", "mileage.value", "1010"),
        ("2026-10-22T10:00:00Z", "mileage.value", "1000"),
    ]
    assert unknown == 1
    only_mileage, _ = view.recent_records(sources, 1, "MILEAGE")
    assert [r.value for r in only_mileage] == ["1010"]


def test_missing_database_is_neither_an_error_nor_created(tmp_path: Path) -> None:
    missing = tmp_path / "nobody" / "captures.sqlite3"
    assert view.recent_files([("nobody", missing)], 5) == []
    assert view.recent_records([("nobody", missing)], 5) == ([], 0)
    assert not missing.exists()


def test_field_summary_collapses_indices_and_finds_the_newest(tmp_path: Path) -> None:
    path = tmp_path / "a6" / "captures.sqlite3"
    conn = sampler._open_database(path)
    doc = {
        "Data": [
            _record("2026-10-20T08:00:00Z", "powerCurve.0.timeCurve.1.soc", "40"),
            _record("2026-10-21T08:00:00Z", "powerCurve.1.timeCurve.0.soc", "60"),
            _record("2026-10-21T09:00:00Z", "mileage", "5"),
        ]
    }
    sampler._store_capture(
        conn, sampler.DatasetInfo("20261022100000_V.zip", None), "all", json.dumps(doc)
    )
    conn.close()
    summary, unknown = view.field_summary([("a6", path)])
    assert [(f.name, f.records, f.newest) for f in summary] == [
        ("mileage", 1, "2026-10-21T09:00:00Z"),
        ("powerCurve.[*].timeCurve.[*].soc", 2, "2026-10-21T08:00:00Z"),
    ]
    assert unknown == 0
    only, _ = view.field_summary([("a6", path)], "timecurve.[*].soc")
    assert [f.name for f in only] == ["powerCurve.[*].timeCurve.[*].soc"]
    records, _ = view.recent_records([("a6", path)], 5, "powerCurve.[*].timeCurve.[*].soc")
    assert [r.value for r in records] == ["60", "40"]


def test_generic_field_name_handles_every_index_spelling() -> None:
    expected = "powerCurve.[*].timeCurve.[*].soc"
    assert view.generic_field_name("powerCurve.3.timeCurve.17.soc") == expected
    assert view.generic_field_name("powerCurve.[3].timeCurve.[17].soc") == expected
    assert view.generic_field_name("powerCurve[3].timeCurve[17].soc") == expected
    assert view.generic_field_name("mileage") == "mileage"


def _status_db(tmp_path: Path) -> Path:
    path = tmp_path / "a6" / "captures.sqlite3"
    conn = sampler._open_database(path)
    vin = "WAUZZZ4G1XN000001"
    for name in (f"20261022092341_{vin}_no_content_found.zip", f"20261022093937_{vin}.zip"):
        if "no_content" in name:
            sampler._store_placeholder(conn, sampler.DatasetInfo(name, None), "partial", b"x")
        else:
            sampler._store_capture(conn, sampler.DatasetInfo(name, None), "partial", "{}")
    for stamp in ("20261022100000", "20261022101500"):
        sampler._store_placeholder(
            conn,
            sampler.DatasetInfo(f"{stamp}_{vin}_no_content_found.zip", None),
            "partial",
            b"x",
        )
    started = datetime(2026, 10, 22, 10, 30, tzinfo=UTC)
    stats = sampler.FetchStats(30, 29, 1, 0, 0)
    sampler._record_run(conn, started, vin, "partial", "ok", stats)
    sampler._record_run(conn, started, vin, "all", "unavailable", message=f"no {vin} request")
    conn.close()
    return path


def test_portal_status_reports_last_run_content_and_empty_streak(tmp_path: Path) -> None:
    status = view.portal_status([("a6", _status_db(tmp_path)), ("kamiq", tmp_path / "none")])
    assert status.accounts_without_runs == ["kamiq"]
    assert status.newest_run == datetime(2026, 10, 22, 10, 30, tzinfo=UTC)
    partial = next(r for r in status.requests if r.dataset_type == "partial")
    assert partial.last_run.outcome == "ok"
    assert partial.last_content_created == "2026-10-22T09:39:37Z"
    assert partial.empty_since_content == 2
    assert partial.first_empty_since_content == "2026-10-22T10:00:00Z"
    unavailable = next(r for r in status.requests if r.dataset_type == "all")
    assert unavailable.last_run.message == "no WAU…001 request"


def test_format_status_flags_a_missing_schedule(tmp_path: Path) -> None:
    status = view.portal_status([("a6", _status_db(tmp_path))])
    on_time = view.format_status(status, datetime(2026, 10, 22, 10, 40, tzinfo=UTC), 15)
    assert on_time.splitlines()[0].endswith("(10 min ago) - ok")
    assert "WAU…001" in on_time and "WAUZZZ4G1XN000001" not in on_time
    assert "empty files:  2 in a row since 2026-10-22T10:00:00Z" in on_time
    late = view.format_status(
        status, datetime(2026, 10, 22, 10, 30, tzinfo=UTC) + timedelta(hours=1), 15
    )
    assert "WARNING: no run for longer than 30 min" in late
    assert view.format_status(view.portal_status([]), datetime.now(UTC), 15).startswith(
        "schedule: no runs recorded yet"
    )
