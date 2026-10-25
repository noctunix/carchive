"""Read-only views on the captured files and records, for the `tail` command.

Databases are opened read-only and are never created here; an account that
has not fetched anything yet simply contributes nothing.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

_NAME_TIMESTAMP = re.compile(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})_")
_FRACTION = re.compile(r"\.(\d+)")


@dataclass(frozen=True)
class FileRow:
    account: str
    fetched_at: str
    created_at: str
    dataset_type: str
    size_bytes: int
    has_content: bool
    records: int | None


@dataclass(frozen=True)
class FieldSummary:
    name: str
    records: int
    newest: str
    accounts: tuple[str, ...]


@dataclass(frozen=True)
class Record:
    account: str
    timestamp: str
    field: str
    value: str


def _open_read_only(path: Path) -> sqlite3.Connection | None:
    if not path.is_file():
        return None
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,))
    return row.fetchone() is not None


def _created_from_name(name: str) -> str:
    match = _NAME_TIMESTAMP.match(name)
    if not match:
        return "?"
    y, mo, d, h, mi, s = match.groups()
    return f"{y}-{mo}-{d}T{h}:{mi}:{s}Z"


def _records_of(raw_json: str) -> list[dict[str, object]] | None:
    """The record list of a delivered document, or None if its layout is not
    the known `{"Data": [...]}` one."""
    try:
        document = json.loads(raw_json)
    except json.JSONDecodeError:
        return None
    data = document.get("Data") if isinstance(document, dict) else None
    if not isinstance(data, list):
        return None
    return [r for r in data if isinstance(r, dict)]


_BRACKET_INDEX = re.compile(r"\[\d+\]")


def generic_field_name(name: str) -> str:
    """Collapses array indices to the dictionary's `[*]`, whichever way they
    are written: `powerCurve.3.soc`, `powerCurve.[3].soc` and `powerCurve[3].soc`
    all become `powerCurve.[*].soc`."""
    text = _BRACKET_INDEX.sub(".[*]", name).replace("..[*]", ".[*]")
    return ".".join("[*]" if part.isdigit() else part for part in text.split("."))


def _matches(needle: str | None, name: str) -> bool:
    if needle is None:
        return True
    return needle in name.lower() or needle in generic_field_name(name).lower()


def _sort_key(timestamp: str) -> datetime:
    # fromisoformat takes at most microseconds; the portal sends up to nanoseconds.
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6], timestamp.replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def recent_files(sources: Sequence[tuple[str, Path]], limit: int) -> list[FileRow]:
    """The `limit` most recently fetched files over all `(account, db)` sources,
    newest first, content and no-content placeholders alike."""
    rows: list[FileRow] = []
    for account, db_path in sources:
        conn = _open_read_only(db_path)
        if conn is None:
            continue
        with closing(conn):
            for fetched, name, dtype, size, raw in conn.execute(
                "SELECT fetched_at_utc, dataset_name, dataset_type, size_bytes, raw_json"
                " FROM captures ORDER BY id DESC LIMIT ?",
                (limit,),
            ):
                records = _records_of(raw)
                rows.append(
                    FileRow(
                        account,
                        fetched,
                        _created_from_name(name),
                        dtype,
                        size,
                        True,
                        len(records) if records is not None else None,
                    )
                )
            if _has_table(conn, "placeholders"):
                for fetched, name, dtype, size in conn.execute(
                    "SELECT fetched_at_utc, dataset_name, dataset_type, size_bytes"
                    " FROM placeholders ORDER BY id DESC LIMIT ?",
                    (limit,),
                ):
                    rows.append(
                        FileRow(account, fetched, _created_from_name(name), dtype, size, False, 0)
                    )
    rows.sort(key=lambda r: (r.fetched_at, r.created_at), reverse=True)
    return rows[:limit]


def _captures_newest_first(conn: sqlite3.Connection) -> Iterator[str]:
    for (raw,) in conn.execute("SELECT raw_json FROM captures ORDER BY id DESC"):
        yield raw


def recent_records(
    sources: Sequence[tuple[str, Path]], limit: int, field: str | None = None
) -> tuple[list[Record], int]:
    """The `limit` newest records (by their own timestamp) from the most
    recently fetched documents, optionally only fields containing `field`.
    Also returns how many documents had an unknown layout and were skipped."""
    needle = field.lower() if field else None
    found: list[Record] = []
    unknown = 0
    for account, db_path in sources:
        conn = _open_read_only(db_path)
        if conn is None:
            continue
        collected = 0
        with closing(conn):
            for raw in _captures_newest_first(conn):
                records = _records_of(raw)
                if records is None:
                    unknown += 1
                    continue
                for record in records:
                    name = str(record.get("dataFieldName", ""))
                    if not _matches(needle, name):
                        continue
                    found.append(
                        Record(
                            account,
                            str(record.get("timestampUtc", "")),
                            name,
                            str(record.get("value", "")),
                        )
                    )
                    collected += 1
                if collected >= limit:
                    break
    found.sort(key=lambda r: _sort_key(r.timestamp), reverse=True)
    return found[:limit], unknown


def field_summary(
    sources: Sequence[tuple[str, Path]], field: str | None = None
) -> tuple[list[FieldSummary], int]:
    """Every field seen in any fetched document, with its record count and
    newest record timestamp, sorted by name. Also returns how many documents
    had an unknown layout."""
    needle = field.lower() if field else None
    counts: dict[str, int] = {}
    newest: dict[str, str] = {}
    seen_in: dict[str, set[str]] = {}
    unknown = 0
    for account, db_path in sources:
        conn = _open_read_only(db_path)
        if conn is None:
            continue
        with closing(conn):
            for raw in _captures_newest_first(conn):
                records = _records_of(raw)
                if records is None:
                    unknown += 1
                    continue
                for record in records:
                    concrete = str(record.get("dataFieldName", ""))
                    if not _matches(needle, concrete):
                        continue
                    name = generic_field_name(concrete)
                    counts[name] = counts.get(name, 0) + 1
                    seen_in.setdefault(name, set()).add(account)
                    timestamp = str(record.get("timestampUtc", ""))
                    if name not in newest or _sort_key(timestamp) > _sort_key(newest[name]):
                        newest[name] = timestamp
    summary = [
        FieldSummary(name, counts[name], newest[name], tuple(sorted(seen_in[name])))
        for name in sorted(counts)
    ]
    return summary, unknown


def format_fields(summary: Sequence[FieldSummary]) -> str:
    width = max(len(f.name) for f in summary)
    lines = [f"{'field':<{width}}  {'records':>8}  newest record (UTC)             accounts"]
    for f in summary:
        lines.append(f"{f.name:<{width}}  {f.records:>8}  {f.newest:<31} {', '.join(f.accounts)}")
    return "\n".join(lines)


def format_files(rows: Sequence[FileRow]) -> str:
    lines = ["fetched (UTC)             created (UTC)         account     type     size  content"]
    for r in rows:
        content = (
            f"{r.records} records"
            if r.has_content and r.records is not None
            else ("unknown layout" if r.has_content else "empty")
        )
        lines.append(
            f"{r.fetched_at[:19]:<25} {r.created_at:<21} {r.account:<11} {r.dataset_type:<7}"
            f" {r.size_bytes:>6}  {content}"
        )
    return "\n".join(lines)


def format_records(records: Sequence[Record], multiple_accounts: bool) -> str:
    width = max((len(r.field) for r in records), default=10)
    lines = []
    for r in records:
        account = f"{r.account:<11} " if multiple_accounts else ""
        lines.append(f"{r.timestamp:<30} {account}{r.field:<{width}}  {r.value}")
    return "\n".join(lines)


@dataclass(frozen=True)
class RunInfo:
    started_at: datetime
    outcome: str
    listed: int | None
    placeholders: int | None
    downloaded: int | None
    with_content: int | None
    pending: int | None
    message: str | None


@dataclass(frozen=True)
class RequestStatus:
    account: str
    vin: str
    dataset_type: str
    last_run: RunInfo
    last_ok_at: datetime | None
    last_content_created: str | None
    last_content_fetched: str | None
    empty_since_content: int
    first_empty_since_content: str | None


@dataclass(frozen=True)
class AccountProblem:
    account: str
    at: datetime
    message: str | None


@dataclass(frozen=True)
class PortalStatus:
    requests: list[RequestStatus]
    login_problems: list[AccountProblem]
    newest_run: datetime | None
    accounts_without_runs: list[str]


def _parse_utc(text: str) -> datetime:
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _run_info(row: tuple[object, ...]) -> RunInfo:
    started, outcome, listed, placeholders, downloaded, with_content, pending, message = row
    return RunInfo(
        _parse_utc(str(started)),
        str(outcome),
        listed if isinstance(listed, int) else None,
        placeholders if isinstance(placeholders, int) else None,
        downloaded if isinstance(downloaded, int) else None,
        with_content if isinstance(with_content, int) else None,
        pending if isinstance(pending, int) else None,
        str(message) if message is not None else None,
    )


_RUN_COLUMNS = (
    "started_at_utc, outcome, listed, placeholders, downloaded, with_content, pending, message"
)


def portal_status(sources: Sequence[tuple[str, Path]]) -> PortalStatus:
    """Collects, per account, vehicle and dataset type, the last recorded run,
    the last file with content and how many empty files followed it."""
    requests: list[RequestStatus] = []
    problems: list[AccountProblem] = []
    without_runs: list[str] = []
    newest: datetime | None = None
    for account, db_path in sources:
        conn = _open_read_only(db_path)
        if conn is None or not _has_table(conn, "fetch_runs"):
            without_runs.append(account)
            if conn is not None:
                conn.close()
            continue
        with closing(conn):
            row = conn.execute("SELECT MAX(started_at_utc) FROM fetch_runs").fetchone()
            if row[0] is None:
                without_runs.append(account)
                continue
            account_newest = _parse_utc(str(row[0]))
            newest = account_newest if newest is None else max(newest, account_newest)

            login = conn.execute(
                f"SELECT {_RUN_COLUMNS} FROM fetch_runs WHERE vin = '*' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            last_any = conn.execute(
                "SELECT started_at_utc FROM fetch_runs WHERE vin != '*' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if login is not None and (last_any is None or str(login[0]) > str(last_any[0])):
                info = _run_info(login)
                problems.append(AccountProblem(account, info.started_at, info.message))

            pairs = conn.execute(
                "SELECT DISTINCT vin, dataset_type FROM fetch_runs WHERE vin != '*'"
                " ORDER BY vin, dataset_type"
            ).fetchall()
            for vin, dataset_type in pairs:
                last = conn.execute(
                    f"SELECT {_RUN_COLUMNS} FROM fetch_runs WHERE vin = ? AND dataset_type = ?"
                    " ORDER BY id DESC LIMIT 1",
                    (vin, dataset_type),
                ).fetchone()
                ok = conn.execute(
                    "SELECT started_at_utc FROM fetch_runs WHERE vin = ? AND dataset_type = ?"
                    " AND outcome = 'ok' ORDER BY id DESC LIMIT 1",
                    (vin, dataset_type),
                ).fetchone()
                pattern = f"%{vin}%"
                content = conn.execute(
                    "SELECT dataset_name, fetched_at_utc FROM captures"
                    " WHERE dataset_type = ? AND dataset_name LIKE ?"
                    " ORDER BY dataset_name DESC LIMIT 1",
                    (dataset_type, pattern),
                ).fetchone()
                after = content[0] if content else ""
                empty = (0, None)
                if _has_table(conn, "placeholders"):
                    empty = conn.execute(
                        "SELECT COUNT(*), MIN(dataset_name) FROM placeholders"
                        " WHERE dataset_type = ? AND dataset_name LIKE ? AND dataset_name > ?",
                        (dataset_type, pattern, after),
                    ).fetchone()
                requests.append(
                    RequestStatus(
                        account,
                        str(vin),
                        str(dataset_type),
                        _run_info(last),
                        _parse_utc(str(ok[0])) if ok else None,
                        _created_from_name(content[0]) if content else None,
                        str(content[1])[:19] if content else None,
                        int(empty[0] or 0),
                        _created_from_name(empty[1]) if empty[1] else None,
                    )
                )
    return PortalStatus(requests, problems, newest, without_runs)


def _ago(then: datetime, now: datetime) -> str:
    minutes = int((now - then).total_seconds() // 60)
    if minutes < 1:
        return "just now"
    if minutes < 120:
        return f"{minutes} min ago"
    if minutes < 48 * 60:
        return f"{minutes // 60} h ago"
    return f"{minutes // (24 * 60)} days ago"


def _mask(vin: str) -> str:
    return f"{vin[:3]}…{vin[-3:]}" if len(vin) > 6 else vin


def format_status(status: PortalStatus, now: datetime, expect_every_min: int) -> str:
    """Renders the status; the first line says whether runs happen on schedule."""
    lines: list[str] = []
    if status.newest_run is None:
        lines.append("schedule: no runs recorded yet")
    else:
        late = now - status.newest_run > timedelta(minutes=2 * expect_every_min)
        verdict = (
            f"WARNING: no run for longer than {2 * expect_every_min} min - check 'schedule status'"
            if late
            else "ok"
        )
        lines.append(
            f"schedule: last run {status.newest_run:%Y-%m-%d %H:%M} UTC"
            f" ({_ago(status.newest_run, now)}) - {verdict}"
        )
    for problem in status.login_problems:
        lines.append(
            f"{problem.account}: LOGIN FAILED {_ago(problem.at, now)}: {problem.message or ''}"
        )
    for account in status.accounts_without_runs:
        lines.append(f"{account}: no runs recorded yet")
    for r in status.requests:
        run = r.last_run
        lines.append("")
        lines.append(f"{r.account} / {_mask(r.vin)} / {r.dataset_type}")
        if run.outcome == "ok":
            detail = (
                f"ok: {run.listed} listed, {run.placeholders} empty,"
                f" {run.downloaded} new ({run.with_content} with content), {run.pending} waiting"
            )
        else:
            detail = f"{run.outcome}: {run.message or ''}"
        lines.append(
            f"  last run:     {run.started_at:%Y-%m-%d %H:%M} UTC ({_ago(run.started_at, now)}),"
            f" {detail}"
        )
        if run.outcome != "ok" and r.last_ok_at is not None:
            lines.append(f"  last ok run:  {r.last_ok_at:%Y-%m-%d %H:%M} UTC")
        if r.last_content_created is None:
            content = "never"
        else:
            content = f"created {r.last_content_created}, fetched {r.last_content_fetched}"
        lines.append(f"  last content: {content}")
        if r.empty_since_content:
            since = f" since {r.first_empty_since_content}" if r.first_empty_since_content else ""
            lines.append(f"  empty files:  {r.empty_since_content} in a row{since}")
    return "\n".join(lines)
