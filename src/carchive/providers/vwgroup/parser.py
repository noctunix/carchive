"""Parses a VW-group delivery ZIP into `core.models.DataPoint`s.

The portal's historical export and its continuous deliveries share one JSON shape:
`{"vin": ..., "userId": ..., "Data": [{"key", "dataFieldName", "timestampUtc", "value"},
...]}`. Every record's `value` is documented as always being a string, but the JSON decoder
is trusted over the documentation: a bare number, boolean, `null`, object or array is still
converted losslessly rather than rejected.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import structlog

from carchive.core.errors import ProviderError
from carchive.core.models import DataPoint
from carchive.core.provider import ParseContext
from carchive.core.timeutil import parse_timestamp
from carchive.providers.vwgroup import archive

logger = structlog.get_logger(__name__)


def _value_to_raw(value: object) -> str | None:
    """Convert one record's decoded JSON `value` to the lossless raw string Carchive stores.

    A plain string passes through unchanged; `null` becomes `None`; a number or boolean is
    re-encoded with `json.dumps` so the exact literal is recoverable; an object or array is
    re-encoded with sorted keys so the same structure always serializes identically.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):  # bool is a subclass of int, so this must come first
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


class VwGroupParser:
    """Turns a downloaded VW-group delivery archive into `DataPoint`s; satisfies `PayloadParser`."""

    parser_version = "vwgroup-records-1"

    def parse(self, payload: bytes, context: ParseContext) -> Iterable[DataPoint]:
        """Parse a delivery archive's single JSON document into `DataPoint`s.

        Args:
            payload: the raw bytes of the downloaded ZIP archive.
            context: metadata about the delivery, used to check the document's `vin`
                against the vehicle the delivery was downloaded for.

        Returns:
            One `DataPoint` per `Data` record whose `dataFieldName` is a non-empty string;
            records failing that check are skipped and counted in a single warning log.

        Raises:
            ProviderError: if the archive cannot be unpacked (see `archive.extract_json`),
                its JSON document is malformed, its top-level shape is not `{"Data": [...]}`,
                or its `vin` does not match `context.vin`.
        """
        json_bytes = archive.extract_json(payload)
        try:
            document = json.loads(json_bytes)
        except json.JSONDecodeError as exc:
            raise ProviderError(f"delivery JSON document is malformed: {exc}") from exc

        if not isinstance(document, dict) or not isinstance(document.get("Data"), list):
            keys = sorted(document.keys()) if isinstance(document, dict) else []
            raise ProviderError(f"unknown delivery layout: top-level keys {keys}")

        document_vin = document.get("vin")
        if isinstance(document_vin, str) and document_vin and document_vin != context.vin:
            # Never include a VIN in an exception message, even one later redacted: a VIN
            # is sensitive on its own, not just when it leaks together with other secrets.
            raise ProviderError("delivery belongs to a different vehicle")

        records: list[dict[str, Any]] = document["Data"]
        return list(self._parse_records(records))

    def _parse_records(self, records: list[dict[str, Any]]) -> Iterable[DataPoint]:
        skipped = 0
        for record in records:
            if not isinstance(record, dict):
                skipped += 1
                continue
            field_name = record.get("dataFieldName")
            if not isinstance(field_name, str) or not field_name:
                skipped += 1
                continue

            key = record.get("key")
            key_str = key if isinstance(key, str) else ""

            captured_at, quality = parse_timestamp(record.get("timestampUtc"))
            value_raw = _value_to_raw(record.get("value"))

            yield DataPoint(
                key=key_str,
                field_name=field_name,
                value_raw=value_raw,
                captured_at=captured_at,
                captured_at_quality=quality,
            )

        if skipped:
            logger.warning("vwgroup.parser.records_skipped", skipped=skipped)
