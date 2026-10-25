#!/usr/bin/env python3
"""Periodic sampler for a VW-group "EU Data Act" portal data-request.

Logs into https://eu-data-act.drivesomethinggreater.com (the data-delivery
portal VW/Audi/Skoda/Seat/Cupra point to from their EU Data Act notices),
downloads the newest dataset for one configured vehicle if it has not been
captured yet, and stores the raw JSON on disk plus one row in a local
SQLite database. Intended to be invoked by cron every few minutes; a run
that finds nothing new is a successful no-op, not an error.

The portal has no documented public API. The request shapes and the login
flow below were worked out by reading evcc's MIT-licensed `eudataact`
client (https://github.com/evcc-io/evcc/tree/master/vehicle/vw/eudataact)
and reimplemented independently; nothing here is copied from it. Treat the
endpoint paths as unverified until a real run against your own account
confirms them - the portal can change its layout without notice.
"""

from __future__ import annotations

import argparse
import configparser
import fcntl
import getpass
import hashlib
import io
import json
import logging
import logging.handlers
import os
import re
import secrets
import sqlite3
import sys
import time
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, parse_qs, urljoin, urlparse

import requests

import captures_view
import scheduling

PORTAL_BASE_URL = "https://eu-data-act.drivesomethinggreater.com"
IDENTITY_BASE_URL = "https://identity.vwgroup.io"
AUTHORIZE_URL = f"{IDENTITY_BASE_URL}/oidc/v1/authorize"
REDIRECT_URI = f"{PORTAL_BASE_URL}/login"
OIDC_SCOPE = "openid cars profile"

# OIDC client ids per VW group brand. These identify a public, pre-registered
# identity-service client (the same one the portal's own web frontend uses),
# not a per-user secret; documented by several independent reverse-engineering
# projects (e.g. ioBroker.vw-connect's euDataAct module).
BRAND_CLIENT_IDS = {
    "volkswagen": (
        "9b58543e-1c15-4193-91d5-8a14145bebb0@apps_vw-dilab_com",
        "VOLKSWAGEN_PASSENGER_CARS",
    ),
    "audi": ("cc29b87a-5e9a-4362-aecf-5adea6b01bbb@apps_vw-dilab_com", "AUDI"),
    "skoda": ("3ea88bf9-1d4e-4a68-b3ad-4098c1f1d246@apps_vw-dilab_com", "SKODA"),
    "seat": ("f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com", "SEAT"),
    "cupra": ("f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com", "CUPRA"),
}

# The delivery endpoints accept exactly "all" and "partial" (the portal's own
# 400 response names both); which one the account's data request was set up
# with is unknown ahead of time, so both are tried in this order.
DEFAULT_DATASET_TYPES = ("all", "partial")

# The portal keeps at most this many files per data request and cancels a
# request whose files are not downloaded within the retention period; empty
# "no content" placeholders count towards both, so they are downloaded too.
PORTAL_MAX_FILES = 30
PORTAL_RETENTION_DAYS = 7
QUEUE_WARN_FILES = 25
QUEUE_WARN_AGE_DAYS = 5
PLACEHOLDER_SUFFIX = "_no_content_found.zip"
_NAME_TIMESTAMP = re.compile(r"^(\d{14})_")
MAX_LOGIN_REDIRECTS = 10

# (connect, read) seconds for every request: a hanging portal must not stall
# the run, and with it every later scheduled run waiting on the run lock.
REQUEST_TIMEOUT = (15.0, 120.0)
# Upper bounds for what a download may be: the largest real file seen so far is
# a 17 MB JSON document; these leave ample room and stop a broken or hostile
# response from exhausting memory.
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100

# The portal's API gateway answers bursts (e.g. catching up on a full queue)
# with 429; waits up to this long per hint, then leaves the rest to the next run.
RATE_LIMIT_MAX_WAIT_S = 120.0
RATE_LIMIT_DEFAULT_WAIT_S = 60.0
RATE_LIMIT_MAX_RETRIES = 3
# Minimum spacing between two portal API requests, so catching up on a full
# queue does not arrive as a burst in the first place.
REQUEST_INTERVAL_S = 1.0
_RETRY_IN_SECONDS = re.compile(r"try again in (\d+) seconds", re.IGNORECASE)

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "carchive" / "config.ini"
LEGACY_CONFIG_PATH = Path.home() / ".config" / "eu-data-act-sampler" / "config.ini"
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "carchive"


class LoginError(RuntimeError):
    pass


class PortalError(RuntimeError):
    pass


class TypeUnavailableError(PortalError):
    """The vehicle has no data request of the asked dataset type."""


class RateLimitedError(RuntimeError):
    """The portal kept answering 429 Too Many Requests."""


@dataclass(frozen=True)
class PortalConfig:
    brand: str
    user: str
    password: str
    vin: str | None


@dataclass(frozen=True)
class AccountConfig:
    """One portal login and the vehicles collected through it."""

    name: str
    portal: PortalConfig
    vins: tuple[str, ...]
    dataset_type: str | None
    data_dir: Path


@dataclass(frozen=True)
class Vehicle:
    vin: str
    name: str


@dataclass(frozen=True)
class DatasetInfo:
    name: str
    created_on: str | None

    @property
    def is_placeholder(self) -> bool:
        return self.name.lower().endswith(PLACEHOLDER_SUFFIX)

    def created_at(self) -> datetime | None:
        """Creation time from the `YYYYmmddHHMMSS_` file name prefix (UTC),
        or None if the name does not carry one."""
        match = _NAME_TIMESTAMP.match(self.name)
        if not match:
            return None
        return datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC)


class _FormParser(HTMLParser):
    """Extracts a `<form id=...>` element's action and its `<input>` fields."""

    def __init__(self, form_id: str):
        super().__init__()
        self._target_id = form_id
        self._depth = 0
        self.action: str | None = None
        self.inputs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "form":
            if self._depth == 0 and attrs_dict.get("id") == self._target_id:
                self._depth = 1
                self.action = attrs_dict.get("action")
            elif self._depth:
                self._depth += 1
        elif tag == "input" and self._depth:
            name = attrs_dict.get("name")
            if name:
                self.inputs[name] = attrs_dict.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._depth:
            self._depth -= 1


def _parse_form(html: str, form_id: str) -> tuple[str, dict[str, str]]:
    parser = _FormParser(form_id)
    parser.feed(html)
    if parser.action is None:
        raise LoginError(f"form #{form_id} not found (portal layout may have changed)")
    return parser.action, parser.inputs


_IDK_BLOCK = re.compile(r"window\._IDK\s*=\s*(.*?)[;<]", re.DOTALL)


def _parse_credentials_page(html: str) -> dict[str, Any]:
    """Decodes the inline `window._IDK = {...}` template model the identity
    service embeds as loosely-quoted JS (single-quoted strings, unquoted keys,
    a trailing comma), not valid JSON."""
    match = _IDK_BLOCK.search(html)
    if not match:
        raise LoginError("credentials page template not found (portal layout may have changed)")
    text = match.group(1).replace("'", '"')
    text = re.sub(r"(\s)(\w+)(\s*):", r'\1"\2"\3:', text)
    text = re.sub(r",\s*}", "}", text, flags=re.DOTALL)
    try:
        decoded: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoginError(f"could not decode credentials page template: {exc}") from exc
    return decoded


def _is_user_page(url: ParseResult, portal_host: str | None) -> bool:
    return (
        url.scheme == "https"
        and url.hostname == portal_host
        and url.path.startswith("/content/euda/")
        and url.path.endswith("user.html")
    )


def _is_marketing_consent_page(url: ParseResult, identity_host: str | None) -> bool:
    return url.hostname == identity_host and "/consent/marketing/" in url.path


def _finalize_login_response(
    session: requests.Session,
    resp: requests.Response,
    identity_host: str | None,
    portal_host: str | None,
) -> tuple[str, requests.Response | None]:
    """Follows redirects like a real login would, but stops *before* fetching
    a target that is the portal's user page or a marketing-consent page - the
    URL itself is all that step needs - and rejects any other host as an
    unexpected redirect target. Returns the final URL and, if it was actually
    fetched, the response holding its body."""
    hops = 0
    while True:
        if not (300 <= resp.status_code < 400) or "Location" not in resp.headers:
            return resp.url, resp
        target = urljoin(resp.url, resp.headers["Location"])
        parsed = urlparse(target)
        if (
            parsed.scheme != "https"
            or _is_user_page(parsed, portal_host)
            or _is_marketing_consent_page(parsed, identity_host)
        ):
            return target, None
        if parsed.hostname not in (identity_host, portal_host):
            raise LoginError(f"unexpected login redirect host: {parsed.hostname}")
        hops += 1
        if hops > MAX_LOGIN_REDIRECTS:
            raise LoginError("too many login redirects")
        resp = session.get(target, allow_redirects=False, timeout=REQUEST_TIMEOUT)


def _perform_login(
    session: requests.Session,
    config: PortalConfig,
    identity_host: str | None,
    portal_host: str | None,
) -> None:
    try:
        client_id, state_suffix = BRAND_CLIENT_IDS[config.brand.lower()]
    except KeyError:
        raise LoginError(f"unknown brand '{config.brand}'") from None

    query = {
        "client_id": client_id,
        "response_type": "code",
        "scope": OIDC_SCOPE,
        "state": f"de__en__{state_suffix}",
        "redirect_uri": REDIRECT_URI,
        "prompt": "login",
        "nonce": secrets.token_urlsafe(32)[:43],
    }
    authorize_resp = session.get(
        AUTHORIZE_URL, params=query, allow_redirects=False, timeout=REQUEST_TIMEOUT
    )
    _, login_form_resp = _finalize_login_response(
        session, authorize_resp, identity_host, portal_host
    )
    if login_form_resp is None:
        raise LoginError("login form page was not reached")

    action, fields = _parse_form(login_form_resp.text, "emailPasswordForm")
    identifier_url = urljoin(IDENTITY_BASE_URL, action)
    identifier_resp = session.post(
        identifier_url,
        data={
            "_csrf": fields.get("_csrf", ""),
            "relayState": fields.get("relayState", ""),
            "hmac": fields.get("hmac", ""),
            "email": config.user,
        },
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )
    _, credentials_resp = _finalize_login_response(
        session, identifier_resp, identity_host, portal_host
    )
    if credentials_resp is None:
        raise LoginError("credentials page was not reached after the identifier step")

    template = _parse_credentials_page(credentials_resp.text)
    model = template.get("templateModel", {})
    if model.get("error"):
        raise LoginError(f"portal rejected identifier: {model['error']}")

    password_url = identifier_url.replace(
        model.get("identifierUrl", ""), model.get("postAction", "")
    )
    password_resp = session.post(
        password_url,
        data={
            "_csrf": template.get("csrf_token", ""),
            "relayState": model.get("relayState", ""),
            "hmac": model.get("hmac", ""),
            "email": config.user,
            "password": config.password,
        },
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )
    final_url, _landing_resp = _finalize_login_response(
        session, password_resp, identity_host, portal_host
    )
    final_parsed = urlparse(final_url)

    if _is_marketing_consent_page(final_parsed, identity_host):
        callback = parse_qs(final_parsed.query).get("callback", [None])[0]
        if not callback:
            raise LoginError("marketing consent page is missing its callback url")
        callback_resp = session.get(callback, allow_redirects=False, timeout=REQUEST_TIMEOUT)
        final_url, _landing_resp = _finalize_login_response(
            session, callback_resp, identity_host, portal_host
        )
        final_parsed = urlparse(final_url)

    if any(marker in final_parsed.path for marker in ("signin-service", "/consent", "/error")):
        raise LoginError(
            "login did not complete - open the portal in a browser and confirm any pending"
            " consent, then retry"
        )
    if not _is_user_page(final_parsed, portal_host):
        raise LoginError(f"login did not complete: unexpected landing page {final_url}")


def _parse_vehicle_list(data: Any) -> list[Vehicle]:
    raw = data if isinstance(data, list) else data.get("vehicles", [])
    vehicles = []
    for entry in raw:
        vin = entry.get("vin") or entry.get("vehicleIdentificationNumber", "")
        if not vin:
            continue
        name = next(
            (
                entry[k]
                for k in ("nickName", "vehicleNickname", "nickname", "modelName")
                if entry.get(k)
            ),
            "",
        )
        vehicles.append(Vehicle(vin=vin, name=name))
    return vehicles


def _parse_dataset_list(data: Any) -> list[DatasetInfo]:
    # Includes the "..._no_content_found.zip" placeholders the portal emits
    # for cycles without vehicle data; callers tell them apart via
    # `is_placeholder`.
    if isinstance(data, dict) and "files" not in data:
        logging.warning("unrecognized dataset list shape, top-level keys: %s", sorted(data))
    raw = data if isinstance(data, list) else data.get("files", [])
    datasets = [
        DatasetInfo(name=entry["name"], created_on=entry.get("createdOn"))
        for entry in raw
        if entry.get("name")
    ]
    datasets.sort(key=lambda d: (d.created_on or "", d.name))
    return datasets


def _queue_warnings(pending: list[DatasetInfo], now: datetime) -> list[str]:
    """Warnings about files still waiting in the portal after this run. A
    full list of already downloaded files is normal: the portal shows the
    newest files only."""
    warnings = []
    if len(pending) >= QUEUE_WARN_FILES:
        warnings.append(
            f"{len(pending)} files not downloaded yet, the portal lists at most"
            f" {PORTAL_MAX_FILES}; older ones may be lost"
        )
    ages = [now - created for d in pending if (created := d.created_at()) is not None]
    if ages and max(ages).days >= QUEUE_WARN_AGE_DAYS:
        warnings.append(
            f"oldest undownloaded file is {max(ages).days} days old; the portal cancels the"
            f" request when files stay undownloaded for {PORTAL_RETENTION_DAYS} days"
        )
    return warnings


def _retry_after_seconds(resp: requests.Response) -> float:
    header = resp.headers.get("Retry-After", "")
    if header.strip().isdigit():
        return float(header)
    match = _RETRY_IN_SECONDS.search(resp.text)
    return float(match.group(1)) if match else RATE_LIMIT_DEFAULT_WAIT_S


def _delivery_url(vin: str, identifier: str) -> str:
    return f"{PORTAL_BASE_URL}/proxy_api/euda-apim/datadelivery/vehicles/{vin}/{identifier}"


def _extract_json_payload(archive_bytes: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise PortalError(f"downloaded archive has too many members ({len(infos)})")
            json_infos = [i for i in infos if i.filename.lower().endswith(".json")]
            if not json_infos:
                raise PortalError("downloaded archive contains no JSON document")
            # The declared size can lie, so the read itself is bounded too.
            with archive.open(json_infos[0]) as member:
                data = member.read(MAX_JSON_BYTES + 1)
    except zipfile.BadZipFile as exc:
        raise PortalError("downloaded file is not a valid ZIP archive") from exc
    if len(data) > MAX_JSON_BYTES:
        raise PortalError("JSON document in the archive exceeds the size limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PortalError("JSON document in the archive is not valid UTF-8") from exc


class PortalClient:
    """Authenticated client for one portal account. Re-logs in once on a
    401/403 before giving up, since the portal session is short-lived."""

    def __init__(
        self,
        config: PortalConfig,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        request_interval_s: float = REQUEST_INTERVAL_S,
    ):
        self._config = config
        self._sleep = sleep
        self._clock = clock
        self._request_interval_s = request_interval_s
        self._last_request_at: float | None = None
        self._session = requests.Session()
        self._identity_host = urlparse(IDENTITY_BASE_URL).hostname
        self._portal_host = urlparse(PORTAL_BASE_URL).hostname

    def login(self) -> None:
        _perform_login(self._session, self._config, self._identity_host, self._portal_host)

    def _get(self, url: str, **kwargs: Any) -> requests.Response:
        resp = self._get_respecting_rate_limit(url, **kwargs)
        if resp.status_code in (401, 403):
            logging.info("portal session expired, logging in again")
            self.login()
            resp = self._get_respecting_rate_limit(url, **kwargs)
        return resp

    def _get_respecting_rate_limit(self, url: str, **kwargs: Any) -> requests.Response:
        for attempt in range(RATE_LIMIT_MAX_RETRIES + 1):
            self._pace()
            resp = self._session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
            self._last_request_at = self._clock()
            if resp.status_code != 429:
                return resp
            wait = _retry_after_seconds(resp)
            if attempt == RATE_LIMIT_MAX_RETRIES or wait > RATE_LIMIT_MAX_WAIT_S:
                break
            logging.info("portal rate limit hit, waiting %.0f s", wait)
            self._sleep(wait)
        raise RateLimitedError(f"portal rate limit persists: {resp.text[:200]}")

    def _pace(self) -> None:
        if self._last_request_at is None:
            return
        remaining = self._request_interval_s - (self._clock() - self._last_request_at)
        if remaining > 0:
            self._sleep(remaining)

    def list_vehicles(self) -> list[Vehicle]:
        resp = self._get(
            f"{PORTAL_BASE_URL}/proxy_api/consent/me/vehicles",
            params={"viewPosition": "FRONT_LEFT"},
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        return _parse_vehicle_list(resp.json())

    def resolve_identifier(self, vin: str, dataset_type: str) -> str:
        # Each dataset type is its own data request with its own identifier;
        # listing "all" with the "partial" request's identifier is rejected
        # with "Invalid identifier provided."
        resp = self._get(
            f"{PORTAL_BASE_URL}/proxy_api/euda-apim/datarequest/vehicles/{vin}"
            f"/metadata/{dataset_type}",
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 404:
            raise TypeUnavailableError(
                f"no '{dataset_type}' data request configured for this vehicle"
            )
        if 400 <= resp.status_code < 500:
            raise TypeUnavailableError(
                f"dataset type '{dataset_type}' rejected: {resp.status_code} {resp.text[:200]}"
            )
        resp.raise_for_status()
        identifier = str(resp.json().get("Identifier", ""))
        if not identifier:
            raise PortalError("portal returned no data request identifier")
        return identifier

    def list_datasets(self, vin: str, identifier: str, dataset_type: str) -> list[DatasetInfo]:
        resp = self._get(
            f"{_delivery_url(vin, identifier)}/list",
            headers={"Accept": "application/json", "type": dataset_type},
        )
        if resp.status_code == 404:
            return []
        if 400 <= resp.status_code < 500:
            raise TypeUnavailableError(
                f"dataset type '{dataset_type}' rejected: {resp.status_code} {resp.text[:200]}"
            )
        resp.raise_for_status()
        return _parse_dataset_list(resp.json())

    def download_dataset(self, vin: str, identifier: str, name: str, dataset_type: str) -> bytes:
        resp = self._get(
            f"{_delivery_url(vin, identifier)}/download",
            headers={"filename": name, "type": dataset_type},
            stream=True,
        )
        with resp:
            resp.raise_for_status()
            chunks = []
            received = 0
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                received += len(chunk)
                if received > MAX_DOWNLOAD_BYTES:
                    raise PortalError("download exceeds the size limit")
                chunks.append(chunk)
        return b"".join(chunks)


def _open_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fetched_at_utc TEXT NOT NULL,
            dataset_name TEXT NOT NULL UNIQUE,
            dataset_created_on TEXT,
            dataset_type TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            raw_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fetch_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at_utc TEXT NOT NULL,
            finished_at_utc TEXT NOT NULL,
            vin TEXT NOT NULL,
            dataset_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            listed INTEGER,
            placeholders INTEGER,
            downloaded INTEGER,
            with_content INTEGER,
            pending INTEGER,
            message TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS placeholders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fetched_at_utc TEXT NOT NULL,
            dataset_name TEXT NOT NULL UNIQUE,
            dataset_created_on TEXT,
            dataset_type TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL
        )
        """
    )
    return conn


def _already_captured(conn: sqlite3.Connection, dataset_name: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM captures WHERE dataset_name = ?"
            " UNION ALL SELECT 1 FROM placeholders WHERE dataset_name = ?",
            (dataset_name, dataset_name),
        ).fetchone()
        is not None
    )


@dataclass(frozen=True)
class FetchStats:
    listed: int
    placeholders: int
    downloaded: int
    with_content: int
    pending: int


_VIN_IN_TEXT = re.compile(r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])")


def _record_run(
    conn: sqlite3.Connection,
    started: datetime,
    vin: str,
    dataset_type: str,
    outcome: str,
    stats: FetchStats | None = None,
    message: str | None = None,
) -> None:
    """Stores one run outcome for the `status` command; messages are kept short
    and VIN-masked because they may come from exception texts."""
    if message is not None:
        message = _VIN_IN_TEXT.sub(lambda m: _mask_vin(m.group(0)), message)[:300]
    conn.execute(
        "INSERT INTO fetch_runs (started_at_utc, finished_at_utc, vin, dataset_type, outcome,"
        " listed, placeholders, downloaded, with_content, pending, message)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            started.isoformat(),
            datetime.now(UTC).isoformat(),
            vin,
            dataset_type,
            outcome,
            stats.listed if stats else None,
            stats.placeholders if stats else None,
            stats.downloaded if stats else None,
            stats.with_content if stats else None,
            stats.pending if stats else None,
            message,
        ),
    )
    conn.commit()


def _store_placeholder(
    conn: sqlite3.Connection, dataset: DatasetInfo, dataset_type: str, archive_bytes: bytes
) -> None:
    conn.execute(
        "INSERT INTO placeholders"
        " (fetched_at_utc, dataset_name, dataset_created_on, dataset_type, sha256, size_bytes)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            datetime.now(UTC).isoformat(),
            dataset.name,
            dataset.created_on,
            dataset_type,
            hashlib.sha256(archive_bytes).hexdigest(),
            len(archive_bytes),
        ),
    )
    conn.commit()


def _store_capture(
    conn: sqlite3.Connection, dataset: DatasetInfo, dataset_type: str, raw_json: str
) -> None:
    raw_bytes = raw_json.encode("utf-8")
    conn.execute(
        "INSERT INTO captures"
        " (fetched_at_utc, dataset_name, dataset_created_on, dataset_type,"
        " sha256, size_bytes, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.now(UTC).isoformat(),
            dataset.name,
            dataset.created_on,
            dataset_type,
            hashlib.sha256(raw_bytes).hexdigest(),
            len(raw_bytes),
            raw_json,
        ),
    )
    conn.commit()


def _write_json_file(data_dir: Path, dataset: DatasetInfo, raw_json: str) -> Path:
    captures_dir = data_dir / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", dataset.name)
    out_path = captures_dir / safe_name
    if out_path.suffix.lower() != ".json":
        out_path = out_path.with_name(out_path.name + ".json")
    out_path.write_text(raw_json, encoding="utf-8")
    return out_path


_ACCOUNT_SECTION = re.compile(r"^account:([A-Za-z0-9_-]+)$")


def _mask_vin(vin: str) -> str:
    return f"{vin[:3]}…{vin[-3:]}" if len(vin) > 6 else vin


def _portal_config(section: configparser.SectionProxy, where: str, vin: str | None) -> PortalConfig:
    brand = section.get("brand", "").strip()
    if brand.lower() not in BRAND_CLIENT_IDS:
        raise SystemExit(
            f"unknown brand '{brand}' in {where}, expected one of {sorted(BRAND_CLIENT_IDS)}"
        )
    return PortalConfig(
        brand=brand,
        user=section.get("user", ""),
        password=section.get("password", ""),
        vin=vin,
    )


def load_accounts(path: Path, data_dir_override: Path | None = None) -> list[AccountConfig]:
    """Reads every account from the config file: the single-account `[portal]`
    section (data directly in the data dir, as before) and any number of
    `[account:<name>]` sections (data in `<data_dir>/<name>`)."""
    # RawConfigParser: a password containing "%" must not be run through
    # ConfigParser's default interpolation.
    parser = configparser.RawConfigParser()
    if not parser.read(path):
        hint = (
            f" (an old one exists at {LEGACY_CONFIG_PATH}; move it there)"
            if path == DEFAULT_CONFIG_PATH and LEGACY_CONFIG_PATH.exists()
            else "; create one with the 'init' command"
        )
        raise SystemExit(f"config file not found: {path}{hint}")
    configured_dir = parser.get("storage", "data_dir", fallback="").strip()
    base_dir = data_dir_override or (
        Path(configured_dir).expanduser() if configured_dir else DEFAULT_DATA_DIR
    )

    accounts = []
    if parser.has_section("portal"):
        section = parser["portal"]
        vin = section.get("vin", "").strip() or None
        accounts.append(
            AccountConfig(
                name="default",
                portal=_portal_config(section, f"{path} [portal]", vin),
                vins=(vin,) if vin else (),
                dataset_type=parser.get("request", "dataset_type", fallback="").strip() or None,
                data_dir=base_dir,
            )
        )
    for section_name in parser.sections():
        match = _ACCOUNT_SECTION.match(section_name)
        if not match:
            continue
        section = parser[section_name]
        if match.group(1) == "default" and parser.has_section("portal"):
            raise SystemExit(f"{path}: [account:default] clashes with the [portal] section")
        vins = tuple(v for v in re.split(r"[\s,]+", section.get("vins", "")) if v)
        accounts.append(
            AccountConfig(
                name=match.group(1),
                portal=_portal_config(section, f"{path} [{section_name}]", None),
                vins=vins,
                dataset_type=section.get("dataset_type", "").strip() or None,
                data_dir=base_dir / match.group(1),
            )
        )
    if not accounts:
        raise SystemExit(f"config file {path} has neither [portal] nor [account:<name>] sections")
    return accounts


def _account_section(name: str, brand: str, user: str, password: str, vins: list[str]) -> str:
    lines = [
        f"[account:{name}]",
        f"brand = {brand}",
        f"user = {user}",
        f"password = {password}",
        f"vins = {', '.join(vins)}" if vins else "# vins = run 'list-vehicles' and add them here",
    ]
    return "\n".join(lines) + "\n"


def _ask(prompt: Callable[[str], str], question: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return prompt(f"{question}{suffix}: ").strip() or default


def _choose_vins(prompt: Callable[[str], str], vehicles: list[Vehicle]) -> list[str]:
    for number, vehicle in enumerate(vehicles, start=1):
        print(f"  {number}) {vehicle.vin}  {vehicle.name}")
    while True:
        answer = _ask(prompt, "Vehicles to collect (numbers, comma-separated)", "all")
        if answer.lower() == "all":
            return [v.vin for v in vehicles]
        picks = [part for part in re.split(r"[\s,]+", answer) if part]
        if picks and all(p.isdigit() and 1 <= int(p) <= len(vehicles) for p in picks):
            return [vehicles[int(p) - 1].vin for p in picks]
        print("Please enter numbers from the list, or 'all'.")


def _write_config_section(path: Path, text: str, header: str) -> None:
    """Creates the file owner-only (0600) or appends to it; it holds passwords,
    so an existing file is tightened to 0600 as well."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
        existing = path.read_text(encoding="utf-8")
        separator = "" if existing.endswith("\n\n") or not existing else "\n"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(separator + text)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(header + "\n" + text)


def run_init(
    path: Path,
    prompt: Callable[[str], str] = input,
    secret: Callable[[str], str] = getpass.getpass,
    client_factory: Callable[[PortalConfig], PortalClient] = PortalClient,
) -> int:
    """Asks for one account interactively, optionally tests the login and
    picks the vehicles, and writes it to the config file - creating the file
    or appending a new account section, never overwriting anything."""
    existing = configparser.RawConfigParser()
    existing.read(path)
    taken = {m.group(1) for name in existing.sections() if (m := _ACCOUNT_SECTION.match(name))}
    if existing.has_section("portal"):
        taken.add("default")

    header = ""
    if path.exists():
        print(f"Adding an account to {path}.")
    else:
        print(f"Creating {path}.")
        data_dir = _ask(prompt, "Data directory", str(DEFAULT_DATA_DIR))
        header = f"[storage]\ndata_dir = {data_dir}\n"

    brands = {b.lower(): b for b in ("Audi", "Volkswagen", "Skoda", "Seat", "Cupra")}
    while (brand := _ask(prompt, f"Brand ({', '.join(brands.values())})").lower()) not in brands:
        print("Unknown brand.")
    while True:
        name = _ask(prompt, "Account name (letters, digits, - and _)", brand)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            print("Only letters, digits, - and _ please.")
        elif name in taken:
            print(f"An account named '{name}' already exists.")
        else:
            break
    user = _ask(prompt, "Portal login (e-mail)")
    password = secret("Portal password (not shown): ")
    if not user or not password or password != password.strip():
        print("Login and password must not be empty or start/end with spaces.")
        return 2

    portal = PortalConfig(brand=brands[brand], user=user, password=password, vin=None)
    vins: list[str] = []
    if _ask(prompt, "Test the login and pick vehicles now? (y/n)", "y").lower().startswith("y"):
        try:
            client = client_factory(portal)
            client.login()
            vehicles = client.list_vehicles()
        except (LoginError, PortalError, requests.RequestException) as exc:
            print(f"Login or vehicle list failed: {exc}")
            if not _ask(prompt, "Save the account anyway? (y/n)", "n").lower().startswith("y"):
                return 1
        else:
            if vehicles:
                vins = _choose_vins(prompt, vehicles)
            else:
                print("The account has no vehicles linked in the portal yet.")

    _write_config_section(path, _account_section(name, brands[brand], user, password, vins), header)
    print(f"Saved account '{name}' to {path} (readable only by you).")
    if not vins:
        print("Add the VINs as 'vins = ...' before running fetch.")
    return 0


def run_login_test(account: AccountConfig) -> int:
    PortalClient(account.portal).login()
    logging.info("%s: login succeeded", account.name)
    return 0


def run_list_vehicles(account: AccountConfig) -> int:
    for vehicle in PortalClient(account.portal).list_vehicles():
        print(f"{account.name}\t{vehicle.vin}\t{vehicle.name}")
    return 0


def _select_downloads(
    datasets: list[DatasetInfo], captured: set[str], limit: int
) -> list[DatasetInfo]:
    """Returns every dataset not captured yet, oldest first, capped at the
    `limit` oldest so a long backlog is worked off over several runs."""
    return [d for d in datasets if d.name not in captured][:limit]


def _fetch_type(
    client: PortalClient,
    conn: sqlite3.Connection,
    data_dir: Path,
    vin: str,
    dataset_type: str,
    max_downloads: int,
    label: str = "",
) -> FetchStats:
    prefix = f"{label} " if label else ""
    identifier = client.resolve_identifier(vin, dataset_type)
    datasets = client.list_datasets(vin, identifier, dataset_type)
    placeholders = sum(d.is_placeholder for d in datasets)
    logging.info(
        "%stype '%s': %d files listed, %d of them no-content placeholders",
        prefix,
        dataset_type,
        len(datasets),
        placeholders,
    )

    captured = {d.name for d in datasets if _already_captured(conn, d.name)}
    to_download = _select_downloads(datasets, captured, max_downloads)
    for dataset in to_download:
        archive_bytes = client.download_dataset(vin, identifier, dataset.name, dataset_type)
        if dataset.is_placeholder:
            _store_placeholder(conn, dataset, dataset_type, archive_bytes)
            logging.debug("acknowledged placeholder %s", dataset.name)
            continue
        raw_json = _extract_json_payload(archive_bytes)
        _store_capture(conn, dataset, dataset_type, raw_json)
        out_path = _write_json_file(data_dir, dataset, raw_json)
        logging.info("captured new dataset -> %s", out_path)
    content = sum(not d.is_placeholder for d in to_download)
    logging.info(
        "%stype '%s': downloaded %d new files (%d with content)",
        prefix,
        dataset_type,
        len(to_download),
        content,
    )
    downloaded = {d.name for d in to_download}
    pending = [d for d in datasets if d.name not in captured and d.name not in downloaded]
    if pending:
        logging.info(
            "%stype '%s': %d more files left for the next run", prefix, dataset_type, len(pending)
        )
    for warning in _queue_warnings(pending, datetime.now(UTC)):
        logging.warning("%stype '%s': %s", prefix, dataset_type, warning)
    return FetchStats(len(datasets), placeholders, len(to_download), content, len(pending))


def run_fetch(
    account: AccountConfig,
    max_downloads: int = 50,
    dataset_type_override: str | None = None,
    client_factory: Callable[[PortalConfig], PortalClient] = PortalClient,
) -> int:
    """Downloads every file not captured yet for each vehicle and dataset
    type of one account, empty placeholders included: the portal lists only
    the newest files and cancels requests with undownloaded old files."""
    if not account.vins:
        logging.error(
            "%s: no vehicle configured: run 'list-vehicles' and add the VIN to the config",
            account.name,
        )
        return 2

    dataset_type = dataset_type_override or account.dataset_type
    types = [dataset_type] if dataset_type else list(DEFAULT_DATASET_TYPES)
    result = 0
    conn = _open_database(account.data_dir / "captures.sqlite3")
    try:
        client = client_factory(account.portal)
        started = datetime.now(UTC)
        try:
            client.login()
        except (LoginError, requests.RequestException) as exc:
            _record_run(conn, started, "*", "*", "login_failed", message=str(exc))
            raise
        for vin in account.vins:
            label = f"{account.name}/{_mask_vin(vin)}"
            available = 0
            for candidate in types:
                started = datetime.now(UTC)
                try:
                    stats = _fetch_type(
                        client, conn, account.data_dir, vin, candidate, max_downloads, label
                    )
                except TypeUnavailableError as exc:
                    _record_run(conn, started, vin, candidate, "unavailable", message=str(exc))
                    logging.info("%s type '%s' not available: %s", label, candidate, exc)
                    continue
                except RateLimitedError as exc:
                    _record_run(conn, started, vin, candidate, "rate_limited", message=str(exc))
                    logging.warning("%s %s; the rest follows on the next run", label, exc)
                    return result
                except (PortalError, requests.RequestException) as exc:
                    _record_run(conn, started, vin, candidate, "error", message=str(exc))
                    logging.error("%s type '%s' failed: %s", label, candidate, exc)
                    available += 1
                    result = 1
                    continue
                _record_run(conn, started, vin, candidate, "ok", stats)
                available += 1
            if not available:
                logging.error("%s: no data request of type %s found", label, " or ".join(types))
                result = 2
    finally:
        conn.close()
    return result


def run_for_accounts(accounts: list[AccountConfig], command: Callable[[AccountConfig], int]) -> int:
    """Runs `command` for each account in turn - never in parallel, the
    portal already rate-limits a single client. A failing account does not
    stop the others; the worst exit code wins."""
    worst = 0
    for account in accounts:
        try:
            code = command(account)
        except (LoginError, PortalError) as exc:
            logging.error("%s: %s", account.name, exc)
            code = 1
        except requests.RequestException as exc:
            logging.error("%s: request to the portal failed: %s", account.name, exc)
            code = 1
        worst = max(worst, code)
    return worst


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"config file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="overrides [storage] data_dir from the config file",
    )
    parser.add_argument(
        "--account",
        action="append",
        default=None,
        help="only this account (name of an [account:<name>] section, or 'default'); repeatable",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="also log to this file, rotated at 1 MB with 5 old files kept",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    # The same two options are also accepted after the command name
    # ("tail --account a6"); SUPPRESS keeps a value given before it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--account", action="append", default=argparse.SUPPRESS, help="only this account"
    )
    common.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "init",
        help="interactively add a portal account to the config file (creates it if needed)",
    )
    sub.add_parser("login-test", parents=[common], help="only perform the login and report success")
    sub.add_parser(
        "list-vehicles",
        parents=[common],
        help="log in and print the VIN/name of each vehicle linked to the account",
    )
    schedule = sub.add_parser(
        "schedule",
        help="install, remove or show the periodic fetch (systemd user timer or crontab)",
    )
    schedule.add_argument("action", choices=("install", "remove", "status"))
    schedule.add_argument(
        "--backend",
        choices=("auto", "systemd", "cron"),
        default="auto",
        help="auto: systemd user timer if lingering is enabled, else crontab",
    )
    schedule.add_argument(
        "--interval",
        type=int,
        default=15,
        help=f"minutes between runs, one of {scheduling.VALID_INTERVALS} (default: 15)",
    )
    status = sub.add_parser(
        "status",
        parents=[common],
        help="show whether scheduled runs happen and what each data request delivered last",
    )
    status.add_argument(
        "--expect-every",
        type=int,
        default=15,
        help="minutes between scheduled runs; a longer gap is flagged (default: 15)",
    )
    fields = sub.add_parser(
        "fields",
        parents=[common],
        help="list the data fields seen so far, array indices collapsed to [*]",
    )
    fields.add_argument("--field", default=None, help="only fields whose name contains this")
    tail = sub.add_parser(
        "tail",
        parents=[common],
        help="show the most recently fetched files, or with --records their newest data records",
    )
    tail.add_argument("-n", type=int, default=20, help="number of lines (default: 20)")
    tail.add_argument(
        "--records", action="store_true", help="show data records instead of fetched files"
    )
    tail.add_argument(
        "--field", default=None, help="with --records: only fields whose name contains this"
    )
    fetch = sub.add_parser(
        "fetch",
        parents=[common],
        help="download the newest dataset if it hasn't been captured yet (the cron command)",
    )
    fetch.add_argument(
        "--dataset-type", default=None, help="overrides [request] dataset_type from the config file"
    )
    fetch.add_argument(
        "--max-downloads",
        type=int,
        default=50,
        help="max files downloaded per dataset type and run (default: 50)",
    )
    return parser


def main(argv: list[str]) -> int:
    args = build_arg_parser().parse_args(argv)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log_file is not None:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            logging.handlers.RotatingFileHandler(
                args.log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
            )
        )
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )

    if args.command == "init":
        return run_init(args.config)
    if args.command == "schedule":
        return run_schedule(args)

    accounts = load_accounts(args.config, args.data_dir)
    if args.account:
        unknown = set(args.account) - {a.name for a in accounts}
        if unknown:
            raise SystemExit(f"unknown account(s): {', '.join(sorted(unknown))}")
        accounts = [a for a in accounts if a.name in args.account]

    if args.command == "login-test":
        return run_for_accounts(accounts, run_login_test)
    if args.command == "list-vehicles":
        return run_for_accounts(accounts, run_list_vehicles)
    if args.command == "tail":
        return run_tail(accounts, args.n, args.records, args.field)
    if args.command == "fields":
        return run_fields(accounts, args.field)
    if args.command == "status":
        return run_status(accounts, args.expect_every)
    with _single_run_lock(scheduling.state_dir() / "fetch.lock") as acquired:
        if not acquired:
            logging.info("another fetch is still running, skipping this one")
            return 0
        return run_for_accounts(
            accounts, lambda account: run_fetch(account, args.max_downloads, args.dataset_type)
        )


def run_status(accounts: list[AccountConfig], expect_every_min: int) -> int:
    if (scheduling.systemd_user_dir() / f"{scheduling.UNIT_NAME}.timer").exists():
        installed = "systemd user timer"
    elif scheduling.CRON_BEGIN in scheduling.read_crontab(scheduling.run_command):
        installed = "crontab"
    else:
        installed = "none (see 'schedule install')"
    print(f"installed:  {installed}")
    sources = [(a.name, a.data_dir / "captures.sqlite3") for a in accounts]
    status = captures_view.portal_status(sources)
    print(captures_view.format_status(status, datetime.now(UTC), expect_every_min))
    return 0


def run_fields(accounts: list[AccountConfig], field: str | None) -> int:
    sources = [(a.name, a.data_dir / "captures.sqlite3") for a in accounts]
    summary, unknown = captures_view.field_summary(sources, field)
    print(captures_view.format_fields(summary) if summary else "no fields seen yet")
    if unknown:
        print(f"({unknown} fetched documents have an unknown layout and were skipped)")
    return 0


def run_tail(accounts: list[AccountConfig], limit: int, records: bool, field: str | None) -> int:
    sources = [(a.name, a.data_dir / "captures.sqlite3") for a in accounts]
    if not records:
        rows = captures_view.recent_files(sources, limit)
        print(captures_view.format_files(rows) if rows else "nothing fetched yet")
        return 0
    found, unknown = captures_view.recent_records(sources, limit, field)
    if found:
        print(captures_view.format_records(found, len(accounts) > 1))
    else:
        print("no records" + (f" with a field containing '{field}'" if field else ""))
    if unknown:
        print(f"({unknown} fetched documents have an unknown layout and were skipped)")
    return 0


@contextmanager
def _single_run_lock(path: Path) -> Iterator[bool]:
    """Yields whether this process got the lock; a slow run (rate limit,
    catch-up) must not be overlapped by the next scheduled one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True


def run_schedule(args: argparse.Namespace) -> int:
    if args.action == "remove":
        return scheduling.remove()
    if args.action == "status":
        return scheduling.status()
    if not args.config.exists():
        raise SystemExit(f"config file not found: {args.config}; create one with 'init' first")
    script = Path(__file__).resolve()
    config = args.config.expanduser().resolve()
    try:
        return scheduling.install(
            lambda log_file: scheduling.fetch_command(script, config, log_file),
            args.backend,
            args.interval,
        )
    except RuntimeError as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
