"""Tests for eu_data_act_sampler.py.

Network-free: everything that talks to the portal (login flow, API calls) is
exercised against fixtures here, never the real service.

Run with: pytest test_eu_data_act_sampler.py
"""

from __future__ import annotations

import io
import sqlite3
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

import eu_data_act_sampler as sampler

EMAIL_FORM_HTML = """
<html><body>
<form id="other"><input name="ignored" value="x"></form>
<form id="emailPasswordForm" action="/signin-service/v1/some-client/login/identifier">
  <input type="hidden" name="_csrf" value="csrf-token-1">
  <input type="hidden" name="relayState" value="relay-1">
  <input type="hidden" name="hmac" value="hmac-1">
</form>
</body></html>
"""

CREDENTIALS_PAGE_HTML = """
<script>
window._IDK = {
  templateModel: {
    hmac: 'hmac-2',
    relayState: 'relay-2',
    postAction: '/signin-service/v1/some-client/login/authenticate',
    identifierUrl: '/signin-service/v1/some-client/login/identifier',
    error: '',
  },
  currentLocale: 'de',
  csrf_parameterName: '_csrf',
  csrf_token: 'csrf-token-2',
};
</script>
"""


def _zip_with(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buf.getvalue()


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.ini"
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Login-page form/template parsing
# --------------------------------------------------------------------------


def test_parse_form_extracts_action_and_hidden_fields() -> None:
    action, fields = sampler._parse_form(EMAIL_FORM_HTML, "emailPasswordForm")
    assert action == "/signin-service/v1/some-client/login/identifier"
    assert fields["_csrf"] == "csrf-token-1"
    assert fields["relayState"] == "relay-1"
    assert fields["hmac"] == "hmac-1"


def test_parse_form_missing_form_raises() -> None:
    with pytest.raises(sampler.LoginError):
        sampler._parse_form(EMAIL_FORM_HTML, "doesNotExist")


def test_parse_credentials_page_decodes_loosely_quoted_template_model() -> None:
    template = sampler._parse_credentials_page(CREDENTIALS_PAGE_HTML)
    assert template["csrf_token"] == "csrf-token-2"
    model = template["templateModel"]
    assert model["hmac"] == "hmac-2"
    assert model["postAction"] == "/signin-service/v1/some-client/login/authenticate"
    assert model["error"] == ""


def test_parse_credentials_page_missing_block_raises() -> None:
    with pytest.raises(sampler.LoginError):
        sampler._parse_credentials_page("<html>nothing here</html>")


# --------------------------------------------------------------------------
# Landing-page classification (where the redirect-following loop stops)
# --------------------------------------------------------------------------


def test_is_user_page_recognizes_portal_user_page() -> None:
    url = urlparse("https://eu-data-act.drivesomethinggreater.com/content/euda/de/en/user.html")
    assert sampler._is_user_page(url, "eu-data-act.drivesomethinggreater.com")


def test_is_user_page_rejects_other_path() -> None:
    url = urlparse("https://eu-data-act.drivesomethinggreater.com/content/euda/de/en/consent.html")
    assert not sampler._is_user_page(url, "eu-data-act.drivesomethinggreater.com")


def test_is_marketing_consent_page_recognized() -> None:
    url = urlparse(
        "https://identity.vwgroup.io/signin-service/v1/consent/marketing/abc?callback=https://x"
    )
    assert sampler._is_marketing_consent_page(url, "identity.vwgroup.io")


# --------------------------------------------------------------------------
# Dataset/vehicle list decoding
# --------------------------------------------------------------------------


def test_parse_dataset_list_sorts_oldest_to_newest_and_flags_placeholders() -> None:
    raw = [
        {"name": "b.zip", "createdOn": "2026-10-20T10:00:00Z"},
        {"name": "a.zip", "createdOn": "2026-10-20T09:00:00Z"},
        {"name": "empty_no_content_found.zip", "createdOn": "2026-10-20T09:30:00Z"},
    ]
    datasets = sampler._parse_dataset_list(raw)
    assert [d.name for d in datasets] == ["a.zip", "empty_no_content_found.zip", "b.zip"]
    assert [d.is_placeholder for d in datasets] == [False, True, False]


def test_dataset_created_at_comes_from_the_name_prefix() -> None:
    dataset = sampler.DatasetInfo("20261022164821_VIN_no_content_found.zip", None)
    assert dataset.created_at() == datetime(2026, 10, 22, 16, 48, 21, tzinfo=UTC)
    assert sampler.DatasetInfo("odd.zip", None).created_at() is None


def test_queue_warnings_only_concern_files_still_waiting_in_the_portal() -> None:
    now = datetime(2026, 10, 22, 17, 0, tzinfo=UTC)
    assert sampler._queue_warnings([], now) == []
    pending = [sampler.DatasetInfo(f"2026102216{i:02d}00_x.zip", None) for i in range(25)]
    assert "25 files not downloaded yet" in sampler._queue_warnings(pending, now)[0]
    old = [sampler.DatasetInfo("20261016120000_x.zip", None)]
    assert "6 days old" in sampler._queue_warnings(old, now)[0]


def test_parse_dataset_list_accepts_wrapped_files_response() -> None:
    datasets = sampler._parse_dataset_list({"files": [{"name": "only.zip", "createdOn": None}]})
    assert [d.name for d in datasets] == ["only.zip"]


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, str]):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self) -> dict[str, str]:
        return self._payload

    def raise_for_status(self) -> None:
        pass


class _RecordingSession:
    def __init__(self, response: _FakeResponse):
        self.urls: list[str] = []
        self._response = response

    def get(self, url: str, **_kwargs: object) -> _FakeResponse:
        self.urls.append(url)
        return self._response


def _client_with(response: _FakeResponse) -> tuple[sampler.PortalClient, _RecordingSession]:
    client = sampler.PortalClient(sampler.PortalConfig("Audi", "u", "p", "VIN1"))
    session = _RecordingSession(response)
    client._session = session  # type: ignore[assignment]
    return client, session


@pytest.mark.parametrize("dataset_type", ["all", "partial"])
def test_resolve_identifier_uses_the_requested_dataset_type(dataset_type: str) -> None:
    client, session = _client_with(_FakeResponse(200, {"Identifier": "abc"}))
    assert client.resolve_identifier("VIN1", dataset_type) == "abc"
    assert session.urls[0].endswith(f"/datarequest/vehicles/VIN1/metadata/{dataset_type}")


def test_resolve_identifier_rejected_type_raises() -> None:
    client, _ = _client_with(_FakeResponse(400, {"message": "Invalid identifier provided."}))
    with pytest.raises(sampler.PortalError, match="'all' rejected"):
        client.resolve_identifier("VIN1", "all")


def test_parse_vehicle_list_picks_first_available_name_field() -> None:
    vehicles = sampler._parse_vehicle_list(
        [{"vehicleIdentificationNumber": "VIN123", "modelName": "Model"}]
    )
    assert vehicles == [sampler.Vehicle(vin="VIN123", name="Model")]


def test_parse_vehicle_list_skips_entries_without_vin() -> None:
    assert sampler._parse_vehicle_list([{"modelName": "NoVin"}]) == []


# --------------------------------------------------------------------------
# Downloaded-archive handling
# --------------------------------------------------------------------------


def test_extract_json_payload_reads_first_json_entry() -> None:
    data = _zip_with({"dataset.json": '{"vin": "x"}'})
    assert sampler._extract_json_payload(data) == '{"vin": "x"}'


def test_extract_json_payload_raises_without_json_entry() -> None:
    data = _zip_with({"readme.txt": "no json here"})
    with pytest.raises(sampler.PortalError):
        sampler._extract_json_payload(data)


# --------------------------------------------------------------------------
# Capture storage (SQLite dedup + raw JSON files)
# --------------------------------------------------------------------------


def test_already_captured_dedups_by_dataset_name(tmp_path: Path) -> None:
    conn = sampler._open_database(tmp_path / "captures.sqlite3")
    dataset = sampler.DatasetInfo(name="first.zip", created_on="2026-10-20T10:00:00Z")
    assert not sampler._already_captured(conn, dataset.name)
    sampler._store_capture(conn, dataset, "all", '{"a": 1}')
    assert sampler._already_captured(conn, dataset.name)
    with pytest.raises(sqlite3.IntegrityError):
        sampler._store_capture(conn, dataset, "all", '{"a": 2}')
    conn.close()


def test_write_json_file_sanitizes_dataset_name(tmp_path: Path) -> None:
    dataset = sampler.DatasetInfo(name="odd name/../etc.zip", created_on=None)
    out_path = sampler._write_json_file(tmp_path, dataset, '{"a": 1}')
    assert out_path.is_file()
    assert out_path.read_text(encoding="utf-8") == '{"a": 1}'
    assert out_path.is_relative_to(tmp_path)


# --------------------------------------------------------------------------
# Config loading
# --------------------------------------------------------------------------


def test_load_accounts_legacy_portal_section(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        "[portal]\nbrand = Audi\nuser = a@b.c\npassword = secret\nvin = VIN123\n"
        "[request]\ndataset_type = partial\n",
    )
    (account,) = sampler.load_accounts(path, tmp_path / "data")
    assert account.name == "default"
    assert account.portal.brand == "Audi"
    assert account.vins == ("VIN123",)
    assert account.dataset_type == "partial"
    assert account.data_dir == tmp_path / "data"


def test_load_accounts_named_sections_get_their_own_data_dir(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        "[storage]\ndata_dir = "
        + str(tmp_path / "store")
        + "\n[account:mine]\nbrand = Audi\nuser = a@b.c\npassword = p1\nvins = VIN1\n"
        "[account:kodiaq]\nbrand = Skoda\nuser = f@b.c\npassword = p%2\n"
        "vins = VIN2, VIN3\n",
    )
    accounts = sampler.load_accounts(path)
    assert [a.name for a in accounts] == ["mine", "kodiaq"]
    assert accounts[1].vins == ("VIN2", "VIN3")
    assert accounts[1].portal.password == "p%2"
    assert accounts[1].data_dir == tmp_path / "store" / "kodiaq"


def test_load_accounts_rejects_unknown_brand(tmp_path: Path) -> None:
    path = _write_config(tmp_path, "[account:x]\nbrand = Toyota\nuser = a@b.c\npassword = s\n")
    with pytest.raises(SystemExit):
        sampler.load_accounts(path)


def test_load_accounts_without_vin_has_no_vehicles(tmp_path: Path) -> None:
    path = _write_config(tmp_path, "[portal]\nbrand = Skoda\nuser = a@b.c\npassword = secret\n")
    (account,) = sampler.load_accounts(path)
    assert account.vins == ()


def test_load_accounts_requires_some_account(tmp_path: Path) -> None:
    path = _write_config(tmp_path, "[storage]\ndata_dir = /tmp/x\n")
    with pytest.raises(SystemExit):
        sampler.load_accounts(path)


def test_run_for_accounts_continues_after_a_failing_account() -> None:
    def account(name: str) -> sampler.AccountConfig:
        return sampler.AccountConfig(
            name, sampler.PortalConfig("Audi", "u", "p", None), ("VIN",), None, Path("/tmp")
        )

    seen: list[str] = []

    def command(acc: sampler.AccountConfig) -> int:
        seen.append(acc.name)
        if acc.name == "broken":
            raise sampler.LoginError("bad password")
        return 0

    assert sampler.run_for_accounts([account("broken"), account("ok")], command) == 1
    assert seen == ["broken", "ok"]


def test_run_fetch_collects_every_vehicle_of_an_account(tmp_path: Path) -> None:
    portal = _FakePortal({"20261022092341_x.zip": _zip_with({"d.json": '{"Data": []}'})})
    account = sampler.AccountConfig(
        "friends",
        sampler.PortalConfig("Skoda", "u", "p", None),
        ("TMBAAAAAAAA000001", "TMBAAAAAAAA000002"),
        "partial",
        tmp_path / "friends",
    )

    def factory(_config: sampler.PortalConfig) -> Any:
        return portal

    assert sampler.run_fetch(account, client_factory=factory) == 0
    assert len(portal.downloads) == 1  # same file name for both fakes: captured once
    assert (tmp_path / "friends" / "captures.sqlite3").is_file()


def _datasets(*names: str) -> list[sampler.DatasetInfo]:
    return [sampler.DatasetInfo(name=n, created_on=f"2026-10-2{i}") for i, n in enumerate(names)]


def test_select_downloads_skips_captured_oldest_first_and_caps() -> None:
    datasets = _datasets("a.zip", "b.zip", "c.zip", "d.zip")
    selected = sampler._select_downloads(datasets, {"b.zip"}, 2)
    assert [d.name for d in selected] == ["a.zip", "c.zip"]


class _FakePortal:
    def __init__(self, files: dict[str, bytes]):
        self.files = files
        self.downloads: list[str] = []

    def login(self) -> None:
        pass

    def resolve_identifier(self, vin: str, dataset_type: str) -> str:
        if dataset_type != "partial":
            raise sampler.TypeUnavailableError(f"no '{dataset_type}' data request")
        return "ident"

    def list_datasets(self, vin: str, identifier: str, dataset_type: str) -> list[Any]:
        return sampler._parse_dataset_list([{"name": n, "createdOn": None} for n in self.files])

    def download_dataset(self, vin: str, identifier: str, name: str, dataset_type: str) -> bytes:
        self.downloads.append(name)
        return self.files[name]


def test_fetch_type_downloads_placeholders_too_and_only_once(tmp_path: Path) -> None:
    portal = _FakePortal(
        {
            "20261022092341_x_no_content_found.zip": _zip_with({}),
            "20261022093937_x.zip": _zip_with({"data.json": '{"Data": []}'}),
        }
    )
    conn = sampler._open_database(tmp_path / "captures.sqlite3")
    client: Any = portal
    sampler._fetch_type(client, conn, tmp_path, "VIN1", "partial", 50)
    assert len(portal.downloads) == 2
    assert conn.execute("SELECT COUNT(*) FROM placeholders").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 1
    sampler._fetch_type(client, conn, tmp_path, "VIN1", "partial", 50)
    assert len(portal.downloads) == 2
    conn.close()


def test_fetch_type_raises_for_an_unavailable_type(tmp_path: Path) -> None:
    conn = sampler._open_database(tmp_path / "captures.sqlite3")
    client: Any = _FakePortal({})
    with pytest.raises(sampler.PortalError):
        sampler._fetch_type(client, conn, tmp_path, "VIN1", "all", 50)
    conn.close()


class _ScriptedResponse:
    def __init__(self, status_code: int, text: str = "", headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _ScriptedSession:
    def __init__(self, responses: list[_ScriptedResponse]):
        self._responses = responses
        self.calls = 0

    def get(self, url: str, **_kwargs: object) -> _ScriptedResponse:
        self.calls += 1
        return self._responses.pop(0)


def _client_with_script(
    responses: list[_ScriptedResponse],
) -> tuple[sampler.PortalClient, _ScriptedSession, list[float]]:
    waits: list[float] = []
    client = sampler.PortalClient(
        sampler.PortalConfig("Audi", "u", "p", "VIN1"), waits.append, request_interval_s=0.0
    )
    session = _ScriptedSession(responses)
    client._session = session  # type: ignore[assignment]
    return client, session, waits


def test_rate_limit_waits_for_the_hint_and_retries() -> None:
    client, session, waits = _client_with_script(
        [
            _ScriptedResponse(429, headers={"Retry-After": "7"}),
            _ScriptedResponse(429, "Rate limit is exceeded. Try again in 12 seconds."),
            _ScriptedResponse(200),
        ]
    )
    assert client._get("https://example.invalid/x").status_code == 200
    assert waits == [7.0, 12.0]
    assert session.calls == 3


def test_rate_limit_gives_up_when_the_hint_is_too_long() -> None:
    client, _, waits = _client_with_script([_ScriptedResponse(429, headers={"Retry-After": "600"})])
    with pytest.raises(sampler.RateLimitedError):
        client._get("https://example.invalid/x")
    assert waits == []


def test_rate_limit_gives_up_after_the_retry_budget() -> None:
    client, _, waits = _client_with_script([_ScriptedResponse(429)] * 4)
    with pytest.raises(sampler.RateLimitedError):
        client._get("https://example.invalid/x")
    assert waits == [60.0, 60.0, 60.0]


def test_requests_are_spaced_by_the_request_interval() -> None:
    now = [100.0]
    waits: list[float] = []

    def sleep(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    client = sampler.PortalClient(
        sampler.PortalConfig("Audi", "u", "p", "VIN1"), sleep, lambda: now[0], 1.0
    )
    client._session = _ScriptedSession([_ScriptedResponse(200)] * 3)  # type: ignore[assignment]
    client._get("https://example.invalid/a")
    now[0] += 0.25
    client._get("https://example.invalid/b")
    now[0] += 5.0
    client._get("https://example.invalid/c")
    assert waits == [0.75]


class _InitPortal:
    def __init__(self, vehicles: list[sampler.Vehicle], fail: bool = False):
        self._vehicles = vehicles
        self._fail = fail

    def login(self) -> None:
        if self._fail:
            raise sampler.LoginError("rejected")

    def list_vehicles(self) -> list[sampler.Vehicle]:
        return self._vehicles


def _scripted(answers: list[str]) -> Any:
    remaining = list(answers)
    return lambda _question: remaining.pop(0)


def test_init_creates_an_owner_only_config_that_loads_back(tmp_path: Path) -> None:
    path = tmp_path / "carchive" / "config.ini"
    portal = _InitPortal([sampler.Vehicle("VIN1", "A6"), sampler.Vehicle("VIN2", "Q4")])
    code = sampler.run_init(
        path,
        prompt=_scripted([str(tmp_path / "data"), "audi", "", "me@example.com", "y", "2"]),
        secret=lambda _q: "p%ss#word",
        client_factory=lambda _c: portal,  # type: ignore[arg-type,return-value]
    )
    assert code == 0
    assert path.stat().st_mode & 0o777 == 0o600
    (account,) = sampler.load_accounts(path)
    assert account.name == "audi"
    assert account.portal.brand == "Audi"
    assert account.portal.password == "p%ss#word"
    assert account.vins == ("VIN2",)
    assert account.data_dir == tmp_path / "data" / "audi"


def test_init_appends_without_touching_existing_accounts(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path, "[account:skoda]\nbrand = Skoda\nuser = a@b.c\npassword = s\nvins = V0\n"
    )
    portal = _InitPortal([sampler.Vehicle("VIN9", "Kamiq")])
    code = sampler.run_init(
        path,
        prompt=_scripted(["skoda", "skoda", "kamiq", "friend@example.com", "y", "all"]),
        secret=lambda _q: "secret",
        client_factory=lambda _c: portal,  # type: ignore[arg-type,return-value]
    )
    assert code == 0
    accounts = sampler.load_accounts(path)
    assert [(a.name, a.vins) for a in accounts] == [("skoda", ("V0",)), ("kamiq", ("VIN9",))]


def test_init_failed_login_saves_nothing_unless_asked(tmp_path: Path) -> None:
    path = tmp_path / "config.ini"
    code = sampler.run_init(
        path,
        prompt=_scripted(["", "audi", "", "me@example.com", "y", "n"]),
        secret=lambda _q: "wrong",
        client_factory=lambda _c: _InitPortal([], fail=True),  # type: ignore[arg-type,return-value]
    )
    assert code == 1
    assert not path.exists()


def test_single_run_lock_rejects_an_overlapping_run(tmp_path: Path) -> None:
    lock = tmp_path / "state" / "fetch.lock"
    with sampler._single_run_lock(lock) as first:
        assert first
        with sampler._single_run_lock(lock) as second:
            assert not second
    with sampler._single_run_lock(lock) as again:
        assert again


def test_account_option_is_accepted_before_and_after_the_command() -> None:
    parser = sampler.build_arg_parser()
    before = parser.parse_args(["--account", "a6", "tail"])
    after = parser.parse_args(["tail", "--account", "a6", "-v"])
    neither = parser.parse_args(["tail"])
    assert before.account == ["a6"]
    assert after.account == ["a6"]
    assert after.verbose
    assert neither.account is None


def test_extract_json_payload_rejects_broken_or_oversized_archives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(sampler.PortalError, match="not a valid ZIP"):
        sampler._extract_json_payload(b"not a zip")
    many = _zip_with({f"f{i}.txt": "" for i in range(sampler.MAX_ARCHIVE_MEMBERS + 1)})
    with pytest.raises(sampler.PortalError, match="too many members"):
        sampler._extract_json_payload(many)
    monkeypatch.setattr(sampler, "MAX_JSON_BYTES", 10)
    with pytest.raises(sampler.PortalError, match="size limit"):
        sampler._extract_json_payload(_zip_with({"d.json": '{"Data": ["0123456789"]}'}))
    with pytest.raises(sampler.PortalError, match="UTF-8"):
        monkeypatch.setattr(sampler, "MAX_JSON_BYTES", 1000)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("d.json", b"\xff\xfe")
        sampler._extract_json_payload(buf.getvalue())


class _StreamingResponse(_ScriptedResponse):
    def __init__(self, chunks: list[bytes]):
        super().__init__(200)
        self._chunks = chunks

    def __enter__(self) -> _StreamingResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        pass

    def raise_for_status(self) -> None:
        pass

    def iter_content(self, chunk_size: int) -> list[bytes]:
        return self._chunks


def test_download_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sampler, "MAX_DOWNLOAD_BYTES", 8)
    client, _, _ = _client_with_script([_StreamingResponse([b"12345", b"678"])])
    assert client.download_dataset("VIN1", "id", "f.zip", "partial") == b"12345678"
    client, _, _ = _client_with_script([_StreamingResponse([b"12345", b"6789"])])
    with pytest.raises(sampler.PortalError, match="size limit"):
        client.download_dataset("VIN1", "id", "f.zip", "partial")


def test_run_fetch_records_ok_unavailable_and_login_failure(tmp_path: Path) -> None:
    portal = _FakePortal({"20261022092341_x_no_content_found.zip": _zip_with({})})
    account = sampler.AccountConfig(
        "a6", sampler.PortalConfig("Audi", "u", "p", None), ("VIN1",), None, tmp_path
    )

    def factory(_config: sampler.PortalConfig) -> Any:
        return portal

    assert sampler.run_fetch(account, client_factory=factory) == 0
    conn = sqlite3.connect(tmp_path / "captures.sqlite3")
    rows = conn.execute("SELECT dataset_type, outcome, placeholders FROM fetch_runs").fetchall()
    assert sorted(rows) == [("all", "unavailable", None), ("partial", "ok", 1)]

    class _Broken(_FakePortal):
        def login(self) -> None:
            raise sampler.LoginError("rejected")

    with pytest.raises(sampler.LoginError):
        sampler.run_fetch(account, client_factory=lambda _c: _Broken({}))  # type: ignore[arg-type,return-value]
    last = conn.execute("SELECT vin, outcome FROM fetch_runs ORDER BY id DESC LIMIT 1").fetchone()
    assert last == ("*", "login_failed")
    conn.close()
