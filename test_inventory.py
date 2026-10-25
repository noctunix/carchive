"""Tests for inventory.py.

All fixtures here are synthetic. The canary test below exists precisely to
catch a future change that accidentally starts echoing real values into the
report.

Run with: pytest test_inventory.py
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import inventory as inv

CANARY_VIN = "WAUZZZ4G1XN000001"
CANARY_EMAIL = "owner@example.com"
CANARY_LAT = 12.34567
CANARY_LON = 76.54321
CANARY_ODOMETER = 123457
CANARY_TIMESTAMP = "2026-10-20T10:15:00Z"
CANARY_TEXT = "CANARY-free-text-xyz"
CANARY_NICKNAME = "MyCanaryCar"
CANARY_DIGIT_SEQUENCES = ["123457", "34567", "54321", "2026-10-20"]


def _canary_document() -> dict[str, object]:
    return {
        "vehicle": {
            CANARY_VIN: {"owner": CANARY_EMAIL},
            "vin": CANARY_VIN,
            "nickName": CANARY_NICKNAME,
            "odometerKm": CANARY_ODOMETER,
        },
        "trips": [
            {
                "startedAt": CANARY_TIMESTAMP,
                "position": {"lat": CANARY_LAT, "lon": CANARY_LON},
                "note": CANARY_TEXT,
            }
        ],
    }


def _assert_no_canary_leak(report: str) -> None:
    for canary in (
        CANARY_VIN,
        CANARY_EMAIL,
        str(CANARY_LAT),
        str(CANARY_LON),
        str(CANARY_ODOMETER),
        CANARY_TIMESTAMP,
        CANARY_TEXT,
        CANARY_NICKNAME,
    ):
        assert canary not in report
    for digits in CANARY_DIGIT_SEQUENCES:
        assert digits not in report


def test_canary_values_never_appear_in_report_for_on_disk_json(tmp_path: Path) -> None:
    doc_path = tmp_path / "export.json"
    doc_path.write_text(json.dumps(_canary_document()), encoding="utf-8")

    report, failed = inv.generate_report([doc_path])

    assert not failed
    _assert_no_canary_leak(report)


def test_canary_values_never_appear_in_report_for_zip_member(tmp_path: Path) -> None:
    zip_path = tmp_path / "export.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("delivery.json", json.dumps(_canary_document()))

    report, failed = inv.generate_report([zip_path])

    assert not failed
    _assert_no_canary_leak(report)


# --------------------------------------------------------------------------
# Path normalization
# --------------------------------------------------------------------------


def test_normalize_key_redacts_dynamic_or_sensitive_keys() -> None:
    assert inv.normalize_key("WAUZZZ4G1XN000001") == "<vin>"
    assert inv.normalize_key("550e8400-e29b-41d4-a716-446655440000") == "<uuid>"
    assert inv.normalize_key("2026-10-20T10:15:00Z") == "<timestamp>"
    assert inv.normalize_key("2026-10-20") == "<timestamp>"
    assert inv.normalize_key("12345") == "<n>"
    assert inv.normalize_key("owner@example.com") == "<email>"
    assert inv.normalize_key("esrkaflnxc4eghd46tw7fqg43pnspnnb") == "<id>"
    assert inv.normalize_key("odometer") == "odometer"


def test_normalize_key_keeps_long_field_names_readable() -> None:
    assert inv.normalize_key("remaining_charging_time_target_soc") == (
        "remaining_charging_time_target_soc"
    )
    assert inv.normalize_key("chargingSessionStartSocInPercent") == (
        "chargingSessionStartSocInPercent"
    )
    assert inv.normalize_key("09_11_csm") == "09_11_csm"


def test_normalize_key_redacts_sensitive_content_embedded_in_a_key() -> None:
    assert inv.normalize_key("vehicle_WAUZZZ4G1XN000001") == "<redacted-key>"
    assert inv.normalize_key("trip_2026-10-20") == "<redacted-key>"
    assert inv.normalize_key("20.10.2026 10:15") == "<redacted-key>"
    assert inv.normalize_key("odo_123457") == "<redacted-key>"
    assert inv.normalize_key("x-550e8400-e29b-41d4-a716-446655440000") == "<contains-uuid>"


def test_loose_timestamps_are_classified_with_a_digit_free_pattern() -> None:
    assert inv.classify_string_value("20.10.2026 10:15") == "timestamp"
    assert inv.timestamp_pattern("20.10.2026 10:15") == "dd.dd.dddd dd:dd"
    assert inv.timestamp_pattern("2026-10-20 10:15:00.123 +02:00") == (
        "dddd-dd-dd dd:dd:dd.ddd +dd:dd"
    )


def test_values_with_spaces_or_opaque_ids_are_never_listed_as_enums(tmp_path: Path) -> None:
    docs = [
        {"label": "Max Mustermann", "ref": "esrkaflnxc4eghd46tw7fqg43pnspnnb", "x": "Home Sweet"},
        {"label": "Max Mustermann", "ref": "esrkaflnxc4eghd46tw7fqg43pnspnnb", "x": "Home Sweet"},
    ]
    for i, doc in enumerate(docs):
        (tmp_path / f"d{i}.json").write_text(json.dumps(doc), encoding="utf-8")
    report, _ = inv.generate_report([tmp_path])
    for leaked in ("Mustermann", "esrkaflnxc4eghd46tw7fqg43pnspnnb", "Home Sweet"):
        assert leaked not in report
    assert "id-like=2" in report


def test_normalize_key_keeps_known_uuid_verbatim() -> None:
    known = frozenset({"19ec0834-f150-3c73-b8c4-7069e2f79df1"})
    assert inv.normalize_key("19ec0834-F150-3c73-b8c4-7069e2f79df1", known) == (
        "19ec0834-F150-3c73-b8c4-7069e2f79df1"
    )
    assert inv.normalize_key("550e8400-e29b-41d4-a716-446655440000", known) == "<uuid>"


def test_merged_inventory_reports_normalized_path_once(tmp_path: Path) -> None:
    doc1 = tmp_path / "a.json"
    doc1.write_text(json.dumps({"vehicles": [{"vin": "A" * 17, "odometer": 1}]}), encoding="utf-8")
    doc2 = tmp_path / "b.json"
    doc2.write_text(json.dumps({"vehicles": [{"vin": "B" * 17, "odometer": 2}]}), encoding="utf-8")

    report, failed = inv.generate_report([doc1, doc2])

    assert not failed
    assert "$/vehicles/[]/vin" in report
    assert "$/vehicles/[]/odometer" in report


# --------------------------------------------------------------------------
# Timestamp pattern
# --------------------------------------------------------------------------


def test_timestamp_pattern_formats() -> None:
    assert inv.timestamp_pattern("2026-10-20T10:15:00Z") == "YYYY-MM-DDThh:mm:ssZ"
    assert inv.timestamp_pattern("2026-10-20T10:15:00.123Z") == "YYYY-MM-DDThh:mm:ss.fffZ"
    assert inv.timestamp_pattern("2026-10-20T10:15:00+02:00") == "YYYY-MM-DDThh:mm:ss+hh:mm"


def test_classify_string_value_kinds() -> None:
    assert inv.classify_string_value("") == "empty"
    assert inv.classify_string_value("2026-10-20T10:15:00Z") == "timestamp"
    assert inv.classify_string_value("2026-10-20") == "date"
    assert inv.classify_string_value("42.5") == "numeric-string"
    assert inv.classify_string_value("true") == "bool-string"
    assert inv.classify_string_value("owner@example.com") == "email"
    assert inv.classify_string_value("WAUZZZ4G1XN000001") == "vin"
    assert inv.classify_string_value("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert inv.classify_string_value("km") == "enum"
    assert inv.classify_string_value("some free text with spaces!!") == "text"


# --------------------------------------------------------------------------
# Enum exception
# --------------------------------------------------------------------------


def test_enum_values_listed_for_unit_field(tmp_path: Path) -> None:
    doc = tmp_path / "a.json"
    doc.write_text(json.dumps({"signal": {"unit": "km"}}), encoding="utf-8")

    report, failed = inv.generate_report([doc])

    assert not failed
    assert "enum values: km" in report


def test_enum_values_listed_for_name_field(tmp_path: Path) -> None:
    doc = tmp_path / "a.json"
    doc.write_text(json.dumps({"signal": {"name": "odometer"}}), encoding="utf-8")

    report, failed = inv.generate_report([doc])

    assert not failed
    assert "enum values: odometer" in report


def test_enum_suppressed_for_deny_listed_key(tmp_path: Path) -> None:
    doc = tmp_path / "a.json"
    doc.write_text(json.dumps({"vehicle": {"nickName": "MyCar"}}), encoding="utf-8")

    report, failed = inv.generate_report([doc])

    assert not failed
    assert "enum values" not in report


def test_enum_suppressed_with_no_enums_flag(tmp_path: Path) -> None:
    doc = tmp_path / "a.json"
    doc.write_text(json.dumps({"signal": {"unit": "km"}}), encoding="utf-8")

    report, failed = inv.generate_report([doc], enums=False)

    assert not failed
    assert "enum values" not in report


def test_enum_suppressed_for_single_occurrence_of_a_neutral_key(tmp_path: Path) -> None:
    doc = tmp_path / "a.json"
    doc.write_text(json.dumps({"trip": {"note": "CANARY-free-text-xyz"}}), encoding="utf-8")

    report, failed = inv.generate_report([doc])

    assert not failed
    assert "enum values" not in report


def test_enum_listed_for_a_neutral_key_once_the_value_recurs(tmp_path: Path) -> None:
    doc1 = tmp_path / "a.json"
    doc1.write_text(json.dumps({"trip": {"mode": "fast-charging"}}), encoding="utf-8")
    doc2 = tmp_path / "b.json"
    doc2.write_text(json.dumps({"trip": {"mode": "fast-charging"}}), encoding="utf-8")

    report, failed = inv.generate_report([doc1, doc2])

    assert not failed
    assert "enum values: fast-charging" in report


# --------------------------------------------------------------------------
# Known-key exception
# --------------------------------------------------------------------------


KNOWN_UUID = "19ec0834-f150-3c73-b8c4-7069e2f79df1"
UNKNOWN_UUID = "550e8400-e29b-41d4-a716-446655440000"


def test_known_key_kept_as_path_segment_and_listed_as_value(tmp_path: Path) -> None:
    doc = tmp_path / "a.json"
    doc.write_text(
        json.dumps({"signals": {KNOWN_UUID: {"key": KNOWN_UUID}}}),
        encoding="utf-8",
    )
    known_keys = frozenset({KNOWN_UUID})

    report, failed = inv.generate_report([doc], known_keys=known_keys)

    assert not failed
    assert f"$/signals/{KNOWN_UUID}/key" in report
    assert f"known keys: {KNOWN_UUID}" in report


def test_unknown_uuid_still_redacted_and_never_printed(tmp_path: Path) -> None:
    doc = tmp_path / "a.json"
    doc.write_text(
        json.dumps({"signals": {UNKNOWN_UUID: {"key": UNKNOWN_UUID}}}),
        encoding="utf-8",
    )
    known_keys = frozenset({KNOWN_UUID})

    report, failed = inv.generate_report([doc], known_keys=known_keys)

    assert not failed
    assert UNKNOWN_UUID not in report
    assert "<uuid>" in report


def test_load_known_keys_ignores_blanks_and_comments(tmp_path: Path) -> None:
    keys_file = tmp_path / "keys.txt"
    keys_file.write_text(f"# comment\n\n{KNOWN_UUID}\n  \n", encoding="utf-8")

    assert inv.load_known_keys(keys_file) == frozenset({KNOWN_UUID})


def test_load_known_keys_none_path_returns_empty() -> None:
    assert inv.load_known_keys(None) == frozenset()


# --------------------------------------------------------------------------
# Redundancy
# --------------------------------------------------------------------------


def test_redundancy_percentage_for_two_documents(tmp_path: Path) -> None:
    doc1 = tmp_path / "a.json"
    doc1.write_text(json.dumps({"a": 1, "b": 2}), encoding="utf-8")
    doc2 = tmp_path / "b.json"
    doc2.write_text(json.dumps({"a": 1, "b": 3}), encoding="utf-8")

    report, failed = inv.generate_report([doc1, doc2])

    assert not failed
    assert "## Redundancy" in report
    assert "document 2 vs document 1: 50.0% of leaf pairs repeated" in report


def test_array_duplicate_share(tmp_path: Path) -> None:
    doc1 = tmp_path / "a.json"
    doc1.write_text(json.dumps({"items": [1, 1, 2, 3]}), encoding="utf-8")
    doc2 = tmp_path / "b.json"
    doc2.write_text(json.dumps({"items": [4]}), encoding="utf-8")

    report, failed = inv.generate_report([doc1, doc2])

    assert not failed
    assert "array $/items/[]: 20.0% of elements are exact duplicates" in report


# --------------------------------------------------------------------------
# Malformed input
# --------------------------------------------------------------------------


def test_invalid_json_reported_without_leaking_content(tmp_path: Path) -> None:
    good = tmp_path / "a.json"
    good.write_text(json.dumps({"a": 1}), encoding="utf-8")
    bad = tmp_path / "b.json"
    bad.write_text("{not valid json, SECRET-CONTENT", encoding="utf-8")

    report, failed = inv.generate_report([good, bad])

    assert failed
    assert "SECRET-CONTENT" not in report
    assert "not valid JSON (JSONDecodeError)" in report


def test_malformed_zip_reported_without_crashing(tmp_path: Path) -> None:
    bad_zip = tmp_path / "broken.zip"
    bad_zip.write_bytes(b"not actually a zip file")

    report, failed = inv.generate_report([bad_zip])

    assert failed
    assert "not valid JSON" in report


def test_compact_report_has_one_line_per_path(tmp_path: Path) -> None:
    (tmp_path / "d.json").write_text(json.dumps({"mileage": {"unit": "km"}}), encoding="utf-8")
    report, _ = inv.generate_report([tmp_path], compact=True)
    unit_lines = [line for line in report.splitlines() if line.startswith("$/mileage/unit |")]
    assert len(unit_lines) == 1
    assert "enum values: km" in unit_lines[0]


def test_redundancy_reports_records_repeated_across_documents_and_within_one(
    tmp_path: Path,
) -> None:
    rec_a = {"key": "k1", "value": "1"}
    rec_b = {"key": "k2", "value": "2"}
    rec_c = {"key": "k3", "value": "3"}
    docs = [{"Data": [rec_a, rec_b]}, {"Data": [rec_a, rec_b, rec_c, rec_c]}]
    for i, doc in enumerate(docs):
        (tmp_path / f"d{i}.json").write_text(json.dumps(doc), encoding="utf-8")
    report, _ = inv.generate_report([tmp_path])
    assert "array $/Data/[]: 66.7% of distinct elements also in document 1" in report
    assert "- array $/Data/[]: 16.7% of elements are exact duplicates within" in report


def test_single_document_still_reports_duplicates_within_arrays(tmp_path: Path) -> None:
    rec = {"key": "k1", "value": "1"}
    (tmp_path / "d.json").write_text(json.dumps({"Data": [rec, rec]}), encoding="utf-8")
    report, _ = inv.generate_report([tmp_path])
    assert "- array $/Data/[]: 50.0% of elements are exact duplicates within" in report
