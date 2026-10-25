"""Tests for `providers.vwgroup.parser.VwGroupParser`."""

from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import UTC, datetime

import pytest

from carchive.core.errors import ProviderError
from carchive.core.models import TimestampQuality
from carchive.core.provider import ParseContext
from carchive.providers.vwgroup.parser import VwGroupParser

_VIN = "WAUZZZ4V0JA123456"
_NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


def _zip_with_json(document: object) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dataset.json", json.dumps(document))
    return buf.getvalue()


def _context(vin: str = _VIN) -> ParseContext:
    return ParseContext(vin=vin, request_kind="partial", delivered_at=_NOW, fetched_at=_NOW)


def test_parses_a_well_formed_document() -> None:
    document = {
        "vin": _VIN,
        "userId": "11111111-1111-1111-1111-111111111111",
        "Data": [
            {
                "key": "k1",
                "dataFieldName": "mileage",
                "timestampUtc": "2026-10-22T10:00:00.123Z",
                "value": "12345",
            }
        ],
    }
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert len(points) == 1
    point = points[0]
    assert point.key == "k1"
    assert point.field_name == "mileage"
    assert point.value_raw == "12345"
    assert point.captured_at_quality == TimestampQuality.EXACT
    assert point.captured_at == datetime(2026, 10, 22, 10, 0, 0, 123000, tzinfo=UTC)


def test_nanosecond_timestamp_is_truncated_not_rejected() -> None:
    document = {
        "Data": [
            {
                "key": "k1",
                "dataFieldName": "mileage",
                "timestampUtc": "2026-10-22T10:00:00.123456789Z",
                "value": "1",
            }
        ]
    }
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert points[0].captured_at == datetime(2026, 10, 22, 10, 0, 0, 123456, tzinfo=UTC)
    assert points[0].captured_at_quality == TimestampQuality.EXACT


def test_empty_timestamp_is_invalid() -> None:
    document = {
        "Data": [{"key": "k1", "dataFieldName": "mileage", "timestampUtc": "", "value": "1"}]
    }
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert points[0].captured_at is None
    assert points[0].captured_at_quality == TimestampQuality.INVALID


def test_1970_timestamp_is_invalid_not_rescaled() -> None:
    document = {
        "Data": [
            {
                "key": "k1",
                "dataFieldName": "powerCurve.0.timeCurve.0.soc",
                "timestampUtc": "1970-01-01T00:00:00.000Z",
                "value": "50",
            }
        ]
    }
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert points[0].captured_at is None
    assert points[0].captured_at_quality == TimestampQuality.INVALID


def test_null_value_becomes_none() -> None:
    document = {"Data": [{"key": "k1", "dataFieldName": "f", "timestampUtc": None, "value": None}]}
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert points[0].value_raw is None


def test_numeric_value_is_losslessly_re_encoded() -> None:
    document = {"Data": [{"key": "k1", "dataFieldName": "f", "timestampUtc": None, "value": 12.5}]}
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert points[0].value_raw == "12.5"


def test_object_value_is_losslessly_re_encoded() -> None:
    document = {
        "Data": [
            {
                "key": "k1",
                "dataFieldName": "f",
                "timestampUtc": None,
                "value": {"b": 2, "a": 1},
            }
        ]
    }
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert json.loads(points[0].value_raw or "") == {"a": 1, "b": 2}
    # Sorted keys make the re-encoding stable regardless of the source object's key order.
    assert points[0].value_raw == '{"a":1,"b":2}'


def test_record_without_data_field_name_is_skipped_and_counted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    document = {
        "Data": [
            {"key": "k1", "timestampUtc": None, "value": "1"},
            {"key": "k2", "dataFieldName": "mileage", "timestampUtc": None, "value": "2"},
            {"key": "k3", "dataFieldName": "", "timestampUtc": None, "value": "3"},
        ]
    }
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert len(points) == 1
    assert points[0].field_name == "mileage"
    assert "records_skipped" in capsys.readouterr().out


def test_user_id_never_appears_on_any_data_point() -> None:
    document = {
        "vin": _VIN,
        "userId": "secret-user-id",
        "Data": [{"key": "k1", "dataFieldName": "mileage", "timestampUtc": None, "value": "1"}],
    }
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    for point in points:
        assert "secret-user-id" not in point.key
        assert "secret-user-id" not in point.field_name
        assert point.value_raw is None or "secret-user-id" not in point.value_raw


def test_wrong_vehicle_vin_raises_provider_error() -> None:
    document = {"vin": "WAUZZZ4V0JA999999", "Data": []}
    with pytest.raises(ProviderError, match="different vehicle"):
        list(VwGroupParser().parse(_zip_with_json(document), _context()))


def test_wrong_vehicle_vin_never_appears_in_the_error_message() -> None:
    document = {"vin": "WAUZZZ4V0JA999999", "Data": []}
    with pytest.raises(ProviderError) as exc_info:
        list(VwGroupParser().parse(_zip_with_json(document), _context()))
    assert "WAUZZZ4V0JA999999" not in str(exc_info.value)
    assert _VIN not in str(exc_info.value)


def test_unknown_top_level_layout_raises_provider_error() -> None:
    document = {"something": "else"}
    with pytest.raises(ProviderError, match="unknown delivery layout"):
        list(VwGroupParser().parse(_zip_with_json(document), _context()))


def test_data_not_a_list_raises_provider_error() -> None:
    document = {"Data": "not-a-list"}
    with pytest.raises(ProviderError, match="unknown delivery layout"):
        list(VwGroupParser().parse(_zip_with_json(document), _context()))


def test_malformed_json_raises_provider_error() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dataset.json", "{not valid json")
    with pytest.raises(ProviderError, match="malformed"):
        list(VwGroupParser().parse(buf.getvalue(), _context()))


def test_missing_key_defaults_to_empty_string() -> None:
    document = {"Data": [{"dataFieldName": "mileage", "timestampUtc": None, "value": "1"}]}
    points = list(VwGroupParser().parse(_zip_with_json(document), _context()))

    assert points[0].key == ""


@pytest.mark.slow
def test_one_hundred_twenty_thousand_records_complete_quickly() -> None:
    document = {
        "vin": _VIN,
        "Data": [
            {
                "key": f"k{i}",
                "dataFieldName": f"field.{i % 50}",
                "timestampUtc": "2026-10-22T10:00:00Z",
                "value": str(i),
            }
            for i in range(120_000)
        ],
    }
    payload = _zip_with_json(document)

    started = time.monotonic()
    points = list(VwGroupParser().parse(payload, _context()))
    elapsed = time.monotonic() - started

    assert len(points) == 120_000
    assert elapsed < 20.0
