#!/usr/bin/env python3
"""Value-free structure inventory for EU Data Act portal exports.

Reads one or more JSON documents (plain `.json` files, `*.json` members
inside `.zip` archives, or directories full of either, recursed) and prints
a report of their *structure* - normalized key paths, JSON types, string
kinds, array lengths, duplication - without ever printing a value. The one
narrow exception is short enum-like strings (unit names, status codes, ...)
and, if `--known-keys` is given, UUIDs from the manufacturer's published
data-point dictionary; both are opt-outable with `--no-enums`.

No real export is ever read by anything other than this script, and nothing
it prints is meant to leave the machine before the owner has reviewed it.

Run with: uv run python inventory.py PATH [PATH ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from typing import Any

VIN_RE = re.compile(r"[A-HJ-NPR-Z0-9]{17}")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
TIMESTAMP_RE = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?"
)
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# Non-ISO date/time spellings seen in the manufacturer's dictionary, e.g.
# "dd.mm.yyyy hh:mm" or "yyyy-mm-dd hh:mm:ss.ms +hh:mm".
LOOSE_TIMESTAMP_RE = re.compile(
    r"\d{1,4}[-./]\d{1,2}[-./]\d{1,4}"
    r"(?:[ T]\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?)?"
    r"\s*(?:Z|UTC|[+-]\d{2}:?\d{2})?"
)
# Embedded anywhere in a key, these make the whole key a placeholder.
KEY_SENSITIVE_SEARCH_RE = re.compile(
    r"[A-HJ-NPR-Z0-9]{17}|[^@\s]+@[^@\s]+\.[^@\s]+|\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4}|\d{5,}"
)
DIGITS_RE = re.compile(r"\d+")
NUMERIC_STRING_RE = re.compile(r"-?\d+(\.\d+)?")
# Opaque identifiers (tokens, request ids such as "esrkaflnxc4eghd46tw7fqg43pnspnnb"):
# long, no word separators, several digits. Long snake_case or camelCase field
# names have no digits and stay readable.
ID_LIKE_RE = re.compile(r"[A-Za-z0-9+/=-]{16,}")
HEX_RE = re.compile(r"[0-9a-fA-F]{16,}")
ENUM_VALUE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-/%°]*")

SENSITIVE_STRING_KINDS = {
    "vin",
    "uuid",
    "known-key",
    "timestamp",
    "date",
    "numeric-string",
    "email",
    "id-like",
}
ENUM_DENY_KEYS = (
    "vin",
    "name",
    "nick",
    "mail",
    "user",
    "owner",
    "address",
    "street",
    "city",
    "zip",
    "postal",
    "lat",
    "lon",
    "lng",
    "position",
    "location",
    "coordinate",
    "plate",
    "license",
    "phone",
    "id",
    "label",
    "title",
    "alias",
    "comment",
    "note",
    "description",
    "text",
    "message",
    "destination",
    "poi",
    "home",
    "work",
    "contact",
    "driver",
    "first",
    "last",
    "surname",
    "token",
    "secret",
    "password",
)
ENUM_ALLOW_EXACT_KEYS = {
    "name",
    "key",
    "signal",
    "type",
    "unit",
    "field",
    "category",
    "cluster",
    "status",
    "state",
    "datatype",
    "unitofmeasure",
}
ENUM_MAX_DEFAULT = 12
KNOWN_KEY_DISPLAY_LIMIT = 200


def normalize_key(key: str, known_keys: frozenset[str] = frozenset()) -> str:
    """Maps a raw object key to a redaction placeholder, or returns it
    unchanged if it does not look dynamic/sensitive. A UUID present in
    `known_keys` (the manufacturer's published data-point dictionary) is
    kept verbatim instead of being redacted, since it is public vocabulary,
    not personal data."""
    if VIN_RE.fullmatch(key):
        return "<vin>"
    if UUID_RE.fullmatch(key):
        return key if key.lower() in known_keys else "<uuid>"
    if UUID_RE.search(key):
        return "<contains-uuid>"
    if TIMESTAMP_RE.fullmatch(key) or DATE_RE.fullmatch(key):
        return "<timestamp>"
    if DIGITS_RE.fullmatch(key):
        return "<n>"
    if EMAIL_RE.fullmatch(key):
        return "<email>"
    if _is_id_like(key):
        return "<id>"
    if KEY_SENSITIVE_SEARCH_RE.search(key) or LOOSE_TIMESTAMP_RE.fullmatch(key):
        return "<redacted-key>"
    return key


def _is_id_like(text: str) -> bool:
    if HEX_RE.fullmatch(text) and any(c.isdigit() for c in text):
        return True
    return bool(ID_LIKE_RE.fullmatch(text)) and sum(c.isdigit() for c in text) >= 2


def classify_string_value(value: str, known_keys: frozenset[str] = frozenset()) -> str:
    """Classifies a string leaf value into a reportable kind. Never returns
    or otherwise exposes the value itself."""
    if value == "":
        return "empty"
    if UUID_RE.fullmatch(value) and value.lower() in known_keys:
        return "known-key"
    if VIN_RE.fullmatch(value):
        return "vin"
    if UUID_RE.fullmatch(value):
        return "uuid"
    if EMAIL_RE.fullmatch(value):
        return "email"
    if TIMESTAMP_RE.fullmatch(value):
        return "timestamp"
    if DATE_RE.fullmatch(value):
        return "date"
    if LOOSE_TIMESTAMP_RE.fullmatch(value):
        return "timestamp"
    if NUMERIC_STRING_RE.fullmatch(value):
        return "numeric-string"
    if value.lower() in ("true", "false"):
        return "bool-string"
    if _is_id_like(value):
        return "id-like"
    if ENUM_VALUE_RE.fullmatch(value) and len(value) <= 40:
        return "enum"
    return "text"


def timestamp_pattern(value: str) -> str:
    """Derives a digit-free pattern string for a timestamp, e.g.
    'YYYY-MM-DDThh:mm:ss.fffZ' or 'YYYY-MM-DDThh:mm:ss+hh:mm'."""
    match = TIMESTAMP_RE.fullmatch(value)
    if not match:
        return re.sub(r"\d", "d", value) if LOOSE_TIMESTAMP_RE.fullmatch(value) else "?"
    pattern = "YYYY-MM-DDThh:mm:ss"
    frac = match.group("frac")
    if frac:
        pattern += "." + "f" * (len(frac) - 1)
    tz = match.group("tz")
    if tz == "Z":
        pattern += "Z"
    elif tz:
        pattern += "+hh:mm"
    return pattern


def decimal_places(value: float) -> int:
    text = repr(value)
    mantissa = text.lower().split("e")[0]
    return len(mantissa.split(".")[1]) if "." in mantissa else 0


def _json_type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise TypeError(f"unsupported JSON value type: {type(value)!r}")


def _format_path(path: tuple[str, ...]) -> str:
    return "$" + "".join(f"/{segment}" for segment in path)


def _last_key_name(path: str) -> str:
    segments = [seg for seg in path.strip("$/").split("/") if seg and seg != "[]"]
    return segments[-1] if segments else ""


@dataclass
class PathStats:
    occurrences: int = 0
    doc_ids: set[int] = field(default_factory=set)
    null_count: int = 0
    type_counts: Counter[str] = field(default_factory=Counter)
    array_lengths: list[int] = field(default_factory=list)
    string_kind_counts: Counter[str] = field(default_factory=Counter)
    timestamp_patterns: Counter[str] = field(default_factory=Counter)
    max_string_length: int = 0
    int_count: int = 0
    float_count: int = 0
    max_decimal_places: int = 0
    true_count: int = 0
    false_count: int = 0
    distinct_values: set[tuple[str, Any]] = field(default_factory=set)


def _canonical_hash(value: Any, salt: bytes) -> bytes:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(salt + canonical.encode("utf-8")).digest()


def _record_leaf(path: str, value: Any, doc_hashes: set[bytes], salt: bytes) -> None:
    pair_canonical = json.dumps(
        [path, value], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    doc_hashes.add(hashlib.sha256(salt + pair_canonical.encode("utf-8")).digest())


def _walk(
    value: Any,
    path: tuple[str, ...],
    doc_index: int,
    stats: dict[str, PathStats],
    doc_leaf_hashes: set[bytes],
    array_hashes: dict[str, list[bytes]],
    salt: bytes,
    known_keys: frozenset[str],
) -> None:
    path_str = _format_path(path)
    st = stats.setdefault(path_str, PathStats())
    st.occurrences += 1
    st.doc_ids.add(doc_index)

    if value is None:
        st.null_count += 1
        st.type_counts["null"] += 1
        _record_leaf(path_str, None, doc_leaf_hashes, salt)
        return
    if isinstance(value, bool):
        st.type_counts["boolean"] += 1
        if value:
            st.true_count += 1
        else:
            st.false_count += 1
        st.distinct_values.add(("boolean", value))
        _record_leaf(path_str, value, doc_leaf_hashes, salt)
        return
    if isinstance(value, int):
        st.type_counts["number"] += 1
        st.int_count += 1
        st.distinct_values.add(("number", value))
        _record_leaf(path_str, value, doc_leaf_hashes, salt)
        return
    if isinstance(value, float):
        st.type_counts["number"] += 1
        st.float_count += 1
        st.max_decimal_places = max(st.max_decimal_places, decimal_places(value))
        st.distinct_values.add(("number", value))
        _record_leaf(path_str, value, doc_leaf_hashes, salt)
        return
    if isinstance(value, str):
        st.type_counts["string"] += 1
        kind = classify_string_value(value, known_keys)
        st.string_kind_counts[kind] += 1
        st.max_string_length = max(st.max_string_length, len(value))
        if kind == "timestamp":
            st.timestamp_patterns[timestamp_pattern(value)] += 1
        st.distinct_values.add(("string", value))
        _record_leaf(path_str, value, doc_leaf_hashes, salt)
        return
    if isinstance(value, list):
        st.type_counts["array"] += 1
        st.array_lengths.append(len(value))
        child_path = path + ("[]",)
        child_path_str = _format_path(child_path)
        bucket = array_hashes.setdefault(child_path_str, [])
        for element in value:
            bucket.append(_canonical_hash(element, salt))
            _walk(
                element,
                child_path,
                doc_index,
                stats,
                doc_leaf_hashes,
                array_hashes,
                salt,
                known_keys,
            )
        return
    if isinstance(value, dict):
        st.type_counts["object"] += 1
        for key, child in value.items():
            norm_key = normalize_key(key, known_keys)
            _walk(
                child,
                path + (norm_key,),
                doc_index,
                stats,
                doc_leaf_hashes,
                array_hashes,
                salt,
                known_keys,
            )
        return
    raise TypeError(f"unsupported JSON value type: {type(value)!r}")


def _enum_allowed_at(path: str) -> bool:
    key = _last_key_name(path).lower()
    if key in ENUM_ALLOW_EXACT_KEYS:
        return True
    return not any(bad in key for bad in ENUM_DENY_KEYS)


def _plain_enum_values(
    path: str, st: PathStats, enum_max: int, known_keys: frozenset[str]
) -> list[str] | None:
    values = sorted(
        v
        for (kind, v) in st.distinct_values
        if kind == "string" and classify_string_value(v, known_keys) not in SENSITIVE_STRING_KINDS
    )
    if not values or len(values) > enum_max:
        return None
    if any(len(v) > 40 for v in values):
        return None
    if not all(ENUM_VALUE_RE.fullmatch(v) for v in values):
        return None
    # A field name outside the known structural vocabulary (unit, status, ...) only
    # gets treated as a controlled vocabulary if some value actually recurs - a
    # single free-text sentence that happens to fit the character class otherwise
    # would be listed on the strength of one occurrence.
    if _last_key_name(path).lower() not in ENUM_ALLOW_EXACT_KEYS:
        total_occurrences = sum(st.string_kind_counts.values())
        if total_occurrences <= len(values):
            return None
    return values


def _known_key_values(st: PathStats, known_keys: frozenset[str]) -> list[str] | None:
    if not known_keys:
        return None
    values = sorted(
        v for (kind, v) in st.distinct_values if kind == "string" and v.lower() in known_keys
    )
    return values or None


@dataclass
class DocSource:
    sort_key: str
    size_bytes: int
    read: Callable[[], bytes]


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _raiser(exc: Exception) -> Callable[[], bytes]:
    def _read() -> bytes:
        raise exc

    return _read


def _zip_member_reader(path: Path, member: str) -> Callable[[], bytes]:
    def _read() -> bytes:
        with zipfile.ZipFile(path) as archive:
            return archive.read(member)

    return _read


def _zip_sources(path: Path) -> list[DocSource]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".json")
            ]
    except (zipfile.BadZipFile, OSError) as exc:
        return [DocSource(sort_key=str(path), size_bytes=_safe_size(path), read=_raiser(exc))]
    return [
        DocSource(
            sort_key=f"{path}!{info.filename}",
            size_bytes=info.file_size,
            read=_zip_member_reader(path, info.filename),
        )
        for info in infos
    ]


def _collect_from_path(path: Path) -> list[DocSource]:
    if path.is_dir():
        sources: list[DocSource] = []
        for child in sorted(path.rglob("*")):
            if not child.is_file():
                continue
            suffix = child.suffix.lower()
            if suffix == ".json":
                sources.append(
                    DocSource(
                        sort_key=str(child), size_bytes=_safe_size(child), read=child.read_bytes
                    )
                )
            elif suffix == ".zip":
                sources.extend(_zip_sources(child))
        return sources
    suffix = path.suffix.lower()
    if suffix == ".zip":
        return _zip_sources(path)
    if suffix == ".json":
        return [DocSource(sort_key=str(path), size_bytes=_safe_size(path), read=path.read_bytes)]
    raise SystemExit(f"unsupported input path (expected .json/.zip/directory): {path}")


def _collect_sources(paths: Iterable[Path]) -> list[DocSource]:
    sources: list[DocSource] = []
    for path in paths:
        sources.extend(_collect_from_path(path))
    sources.sort(key=lambda s: s.sort_key)
    return sources


def load_known_keys(path: Path | None) -> frozenset[str]:
    """Loads a newline-separated list of known UUID data-point keys (from the
    manufacturer's published data dictionary). Blank lines and `#` comments
    are ignored; comparison elsewhere is case-insensitive."""
    if path is None:
        return frozenset()
    keys = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keys.add(stripped.lower())
    return frozenset(keys)


def _array_stats_line(lengths: list[int]) -> str:
    return f"array length: min={min(lengths)} median={median(lengths):g} max={max(lengths)}"


def _render_path_block(
    path: str, st: PathStats, n_docs: int, enums: bool, enum_max: int, known_keys: frozenset[str]
) -> list[str]:
    lines = [f"### {path}"]
    lines.append(f"- occurrences: {st.occurrences} (in {len(st.doc_ids)}/{n_docs} documents)")
    if st.null_count:
        lines.append(f"- null: {st.null_count}")
    types = ", ".join(f"{name}={count}" for name, count in sorted(st.type_counts.items()))
    lines.append(f"- types: {types}")
    if st.distinct_values:
        lines.append(f"- distinct values: {len(st.distinct_values)}")
    if st.array_lengths:
        lines.append(f"- {_array_stats_line(st.array_lengths)}")
    if st.type_counts.get("string"):
        lines.append(f"- max string length: {st.max_string_length}")
        kinds = ", ".join(f"{k}={v}" for k, v in sorted(st.string_kind_counts.items()))
        lines.append(f"- string kinds: {kinds}")
        if st.timestamp_patterns:
            patterns = ", ".join(f"{p}={c}" for p, c in sorted(st.timestamp_patterns.items()))
            lines.append(f"- timestamp pattern: {patterns}")
    if st.int_count or st.float_count:
        lines.append(
            f"- numbers: int={st.int_count} float={st.float_count}"
            f" max decimal places={st.max_decimal_places}"
        )
    if st.type_counts.get("boolean"):
        lines.append(f"- booleans: true={st.true_count} false={st.false_count}")
    if enums and _enum_allowed_at(path):
        plain = _plain_enum_values(path, st, enum_max, known_keys)
        if plain:
            lines.append(f"- enum values: {', '.join(plain)}")
        known = _known_key_values(st, known_keys)
        if known:
            shown = known[:KNOWN_KEY_DISPLAY_LIMIT]
            suffix = (
                f", ... {len(known) - KNOWN_KEY_DISPLAY_LIMIT} more"
                if len(known) > KNOWN_KEY_DISPLAY_LIMIT
                else ""
            )
            lines.append(f"- known keys: {', '.join(shown)}{suffix}")
    return lines


def _redundancy_lines(
    doc_leaf_hashes: list[tuple[int, set[bytes]]],
    doc_element_hashes: list[dict[str, list[bytes]]],
) -> list[str]:
    lines = []
    pairs = zip(doc_leaf_hashes, doc_leaf_hashes[1:], strict=False)
    for index, ((prev_num, previous), (cur_num, current)) in enumerate(pairs, start=1):
        share = (len(current & previous) / len(current) * 100) if current else 0.0
        lines.append(
            f"- document {cur_num} vs document {prev_num}: {share:.1f}% of leaf pairs repeated"
        )
        prev_elements = doc_element_hashes[index - 1]
        for path, element_list in sorted(doc_element_hashes[index].items()):
            elements = set(element_list)
            if elements:
                previous_set = set(prev_elements.get(path, []))
                repeated = len(elements & previous_set) / len(elements) * 100
                lines.append(
                    f"  - array {path}: {repeated:.1f}% of distinct elements"
                    f" also in document {prev_num}"
                )
    totals: Counter[str] = Counter()
    duplicates: Counter[str] = Counter()
    for per_doc in doc_element_hashes:
        for path, element_list in per_doc.items():
            totals[path] += len(element_list)
            duplicates[path] += len(element_list) - len(set(element_list))
    for path in sorted(totals):
        if totals[path]:
            share = duplicates[path] / totals[path] * 100
            lines.append(
                f"- array {path}: {share:.1f}% of elements are exact duplicates"
                " within their document"
            )
    return lines


def generate_report(
    paths: Sequence[Path],
    *,
    enums: bool = True,
    enum_max: int = ENUM_MAX_DEFAULT,
    known_keys: frozenset[str] = frozenset(),
    compact: bool = False,
) -> tuple[str, bool]:
    """Builds the value-free structure inventory report for `paths`.

    Returns the report text and whether any document failed to parse.
    """
    sources = _collect_sources(paths)
    salt = secrets.token_bytes(32)
    stats: dict[str, PathStats] = {}
    array_hashes: dict[str, list[bytes]] = {}
    doc_leaf_hashes: list[tuple[int, set[bytes]]] = []
    doc_element_hashes: list[dict[str, list[bytes]]] = []

    lines = [
        "# Value-free structure inventory",
        "",
        "Review this report before sharing. It is meant to contain no values, but check anyway.",
        "",
        "## Documents",
    ]

    any_failed = False
    n_parsed = 0
    for doc_number, source in enumerate(sources, start=1):
        try:
            raw = source.read()
            data = json.loads(raw)
        except Exception as exc:  # deliberately broad: report only the class, never the message
            lines.append(f"document {doc_number}: not valid JSON ({type(exc).__name__})")
            any_failed = True
            continue
        lines.append(
            f"document {doc_number}: size={source.size_bytes} bytes, type={_json_type_name(data)}"
        )
        doc_hashes: set[bytes] = set()
        lengths_before = {path: len(hashes) for path, hashes in array_hashes.items()}
        _walk(data, (), n_parsed, stats, doc_hashes, array_hashes, salt, known_keys)
        doc_leaf_hashes.append((doc_number, doc_hashes))
        doc_element_hashes.append(
            {path: hashes[lengths_before.get(path, 0) :] for path, hashes in array_hashes.items()}
        )
        n_parsed += 1

    lines.append("")
    lines.append("## Structural inventory")
    for path in sorted(stats):
        block = _render_path_block(path, stats[path], n_parsed, enums, enum_max, known_keys)
        if compact:
            lines.append(" | ".join([block[0].removeprefix("### ")] + [b[2:] for b in block[1:]]))
        else:
            lines.append("")
            lines.extend(block)

    if doc_leaf_hashes:
        lines.append("")
        lines.append("## Redundancy")
        lines.extend(_redundancy_lines(doc_leaf_hashes, doc_element_hashes))

    return "\n".join(lines) + "\n", any_failed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("paths", nargs="+", type=Path, metavar="PATH")
    parser.add_argument(
        "--out", type=Path, default=None, help="write the report to this file instead of stdout"
    )
    parser.add_argument(
        "--no-enums", action="store_true", help="never list short enum-like string values"
    )
    parser.add_argument(
        "--enum-max",
        type=int,
        default=ENUM_MAX_DEFAULT,
        help=f"max distinct values for the enum exception (default: {ENUM_MAX_DEFAULT})",
    )
    parser.add_argument(
        "--compact", action="store_true", help="one line per path instead of one block per path"
    )
    parser.add_argument(
        "--known-keys",
        type=Path,
        default=None,
        help="file with one known data-point UUID per line; those keys/values are kept verbatim",
    )
    return parser


def main(argv: list[str]) -> int:
    args = build_arg_parser().parse_args(argv)
    known_keys = load_known_keys(args.known_keys)
    report, any_failed = generate_report(
        args.paths,
        enums=not args.no_enums,
        enum_max=args.enum_max,
        known_keys=known_keys,
        compact=args.compact,
    )
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
