"""Tests for the operator login: middleware, login/setup/logout routes and password change."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import httpx
import pytest
from babel.messages.extract import extract_from_file
from babel.messages.pofile import read_po
from fastapi import FastAPI

from carchive.config import Settings, write_operator_hash
from carchive.logging_setup import configure_logging
from carchive.services.accounts import AccountService
from carchive.services.app_services import AppServices
from carchive.services.operator_auth import (
    LoginThrottle,
    OperatorAuth,
    OperatorAuthError,
)
from carchive.storage.db import Database
from carchive.web.app import create_app
from carchive.web.auth import SESSION_COOKIE_NAME
from carchive.web.i18n import LANG_COOKIE_NAME
from tests.web.conftest import OPERATOR_PASSWORD, FakeScheduler

LOOPBACK = ("127.0.0.1", 50000)
REMOTE = ("203.0.113.9", 50001)
NEW_PASSWORD = "another synthetic password"
ORIGIN = {"Origin": "http://localhost"}


@pytest.fixture
def fresh_auth(db: Database, tmp_path: Path) -> OperatorAuth:
    """A login backend with no password set."""
    return OperatorAuth(db, tmp_path / "fresh" / "secrets.toml")


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    configure_logging(verbose=False, fmt="json")
    caplog.set_level("INFO")
    return caplog


def _app(
    db: Database,
    settings: Settings,
    accounts: AccountService,
    auth: OperatorAuth,
    throttle: LoginThrottle,
) -> FastAPI:
    return create_app(AppServices(db, FakeScheduler(), accounts, auth, throttle), settings)


def _anon(
    app: FastAPI, *, peer: tuple[str, int] = LOOPBACK, scheme: str = "http"
) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=peer)
    return httpx.AsyncClient(transport=transport, base_url=f"{scheme}://localhost", cookies={})


async def _post(
    client: httpx.AsyncClient,
    path: str,
    data: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    if "csrf_token" not in client.cookies:
        await client.get("/healthz")
    form = {"csrf_token": client.cookies["csrf_token"], **data}
    return await client.post(path, data=form, headers={**ORIGIN, **(headers or {})})


def _normalized(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r'name="csrf_token" value="[^"]*"', "", html))


def _session_cookie(response: httpx.Response) -> str:
    match = re.search(rf"{SESSION_COOKIE_NAME}=([^;]+)", response.headers.get("set-cookie", ""))
    assert match is not None, response.headers
    return match.group(1)


def _set_cookie_lines(response: httpx.Response) -> list[str]:
    return [v for k, v in response.headers.multi_items() if k == "set-cookie"]


def _session_cookie_line(response: httpx.Response) -> str:
    return next(v for v in _set_cookie_lines(response) if v.startswith(SESSION_COOKIE_NAME))


@pytest.fixture
def app(
    db: Database,
    settings: Settings,
    accounts: AccountService,
    operator_auth: OperatorAuth,
    login_throttle: LoginThrottle,
) -> FastAPI:
    return _app(db, settings, accounts, operator_auth, login_throttle)


@pytest.fixture
def fresh_app(
    db: Database,
    settings: Settings,
    accounts: AccountService,
    fresh_auth: OperatorAuth,
    login_throttle: LoginThrottle,
) -> FastAPI:
    return _app(db, settings, accounts, fresh_auth, login_throttle)


# --- without a session ----------------------------------------------------------


async def test_get_without_session_redirects_to_login(app: FastAPI) -> None:
    async with _anon(app) as client:
        for path in ("/", "/settings", "/accounts", "/vehicles", "/data", "/setup"):
            response = await client.get(path)
            assert response.status_code == 303, path
            assert response.headers["location"] == "/login"
        head = await client.head("/")
        assert head.status_code == 303


async def test_language_switch_needs_no_session(app: FastAPI, fresh_app: FastAPI) -> None:
    for target in (app, fresh_app):
        async with _anon(target) as client:
            response = await client.get("/lang/de", headers={"Referer": "http://localhost/login"})

        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert "lang=de" in response.headers["set-cookie"]


async def test_language_switch_with_unknown_code_is_404_without_session(app: FastAPI) -> None:
    async with _anon(app) as client:
        response = await client.get("/lang/xx")

    assert response.status_code == 404


@pytest.mark.parametrize(
    "referer",
    [
        "http://localhost//evil.example/x",
        "http://localhost/\\evil.example",
        "http://evil.example/login",
        "https://evil.example//login",
        "javascript:alert(1)",
    ],
)
async def test_language_switch_never_redirects_off_site(app: FastAPI, referer: str) -> None:
    async with _anon(app) as client:
        response = await client.get("/lang/en", headers={"Referer": referer})

    assert response.status_code == 303
    assert response.headers["location"] == "/"


async def test_htmx_request_without_session_gets_401_and_hx_redirect(app: FastAPI) -> None:
    async with _anon(app) as client:
        response = await client.get("/", headers={"HX-Request": "true"})

    assert response.status_code == 401
    assert response.headers["hx-redirect"] == "/login"


async def test_post_without_session_gets_401_not_a_redirect(app: FastAPI) -> None:
    async with _anon(app) as client:
        deleted = await _post(client, "/accounts/x/delete", {})
        upload = await client.post(
            f"/settings/catalog/import?csrf_token={client.cookies['csrf_token']}",
            files={"file": ("d.pdf", b"x", "application/pdf")},
            headers=ORIGIN,
        )

    assert deleted.status_code == 401
    assert upload.status_code == 401
    assert "location" not in deleted.headers


async def test_public_paths_need_no_session(app: FastAPI) -> None:
    async with _anon(app) as client:
        health = await client.get("/healthz")
        static = await client.get("/static/css/app.css")
        login = await client.get("/login")
        setup = await client.get("/login/setup")

    assert health.status_code in (200, 503)
    assert static.status_code == 200
    assert login.status_code == 200
    assert "Sign in" in login.text
    assert setup.status_code == 303
    assert setup.headers["location"] == "/login"


async def test_garbage_and_oversized_session_cookies_are_rejected(app: FastAPI) -> None:
    async with _anon(app) as client:
        for value in ("garbage", "x" * 5000):
            response = await client.get("/", headers={"Cookie": f"{SESSION_COOKIE_NAME}={value}"})
            assert response.status_code == 303


async def test_signed_in_client_reaches_pages_and_sees_sign_out(
    app: FastAPI, operator_auth: OperatorAuth
) -> None:
    session = await operator_auth.create_session()
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session.token)
        page = await client.get("/")
        login = await client.get("/login")

    assert page.status_code == 200
    assert 'action="/logout"' in page.text
    assert login.status_code == 303
    assert login.headers["location"] == "/"


# --- first password -------------------------------------------------------------


async def test_without_password_everything_redirects_to_login(fresh_app: FastAPI) -> None:
    async with _anon(fresh_app) as client:
        page = await client.get("/vehicles")
        post = await _post(client, "/accounts/x/delete", {})
        form = await client.get("/login")

    assert page.status_code == 303 and page.headers["location"] == "/login"
    assert post.status_code == 303 and post.headers["location"] == "/login"
    assert "Set a password" in form.text
    assert "setup_token" not in form.text
    assert 'action="/logout"' not in form.text


async def test_setup_from_loopback_sets_the_first_password(
    fresh_app: FastAPI, fresh_auth: OperatorAuth
) -> None:
    async with _anon(fresh_app) as client:
        response = await _post(
            client,
            "/login/setup",
            {"new_password": NEW_PASSWORD, "new_password_repeat": NEW_PASSWORD},
        )
        client.cookies.set(SESSION_COOKIE_NAME, _session_cookie(response))
        page = await client.get("/")

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert page.status_code == 200
    assert await fresh_auth.verify_password(NEW_PASSWORD)


async def test_setup_from_remote_peer_needs_no_token(
    fresh_app: FastAPI, fresh_auth: OperatorAuth
) -> None:
    async with _anon(fresh_app, peer=REMOTE) as client:
        shown = await client.get("/login")
        response = await _post(
            client,
            "/login/setup",
            {"new_password": NEW_PASSWORD, "new_password_repeat": NEW_PASSWORD},
        )

    assert 'name="setup_token"' not in shown.text
    assert response.status_code == 303
    assert await fresh_auth.verify_password(NEW_PASSWORD)


async def test_setup_rejects_weak_or_mismatched_passwords(
    fresh_app: FastAPI, fresh_auth: OperatorAuth
) -> None:
    async with _anon(fresh_app) as client:
        short = await _post(
            client, "/login/setup", {"new_password": "short", "new_password_repeat": "short"}
        )
        mismatch = await _post(
            client,
            "/login/setup",
            {"new_password": NEW_PASSWORD, "new_password_repeat": NEW_PASSWORD + "x"},
        )

    assert short.status_code == 400
    assert "at least 16 characters" in short.text
    assert mismatch.status_code == 400
    assert "do not match" in mismatch.text
    assert not fresh_auth.password_is_set()
    assert SESSION_COOKIE_NAME not in short.headers.get("set-cookie", "")


async def test_second_setup_is_told_a_password_exists(
    fresh_app: FastAPI, fresh_auth: OperatorAuth
) -> None:
    async def setup(password: str) -> httpx.Response:
        async with _anon(fresh_app) as client:
            return await _post(
                client,
                "/login/setup",
                {"new_password": password, "new_password_repeat": password},
            )

    first, second = await asyncio.gather(
        setup("first synthetic password"), setup("second synthetic password")
    )

    assert sorted([first.status_code, second.status_code]) == [303, 409]
    loser = first if first.status_code == 409 else second
    winner_password = (
        "first synthetic password" if first.status_code == 303 else "second synthetic password"
    )
    assert "A password is already set" in loser.text
    assert "Sign in" in loser.text
    assert SESSION_COOKIE_NAME not in loser.headers.get("set-cookie", "")
    assert await fresh_auth.verify_password(winner_password)


async def test_first_password_never_appears_in_logs_or_responses(
    fresh_app: FastAPI, logs: pytest.LogCaptureFixture
) -> None:
    async with _anon(fresh_app, peer=REMOTE) as client:
        responses = [
            await client.get("/login"),
            await _post(
                client,
                "/login/setup",
                {"new_password": NEW_PASSWORD, "new_password_repeat": NEW_PASSWORD + "x"},
            ),
            await _post(
                client,
                "/login/setup",
                {"new_password": NEW_PASSWORD, "new_password_repeat": NEW_PASSWORD},
            ),
        ]

    for response in responses:
        assert NEW_PASSWORD not in response.text
    assert NEW_PASSWORD not in "".join(r.getMessage() for r in logs.records)


# --- signing in -----------------------------------------------------------------


async def test_login_success_sets_a_hardened_cookie_and_goes_to_root(
    app: FastAPI, operator_auth: OperatorAuth
) -> None:
    async with _anon(app) as client:
        response = await _post(client, "/login", {"password": OPERATOR_PASSWORD})
        client.cookies.set(SESSION_COOKIE_NAME, _session_cookie(response))
        page = await client.get("/settings")

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    line = _session_cookie_line(response)
    assert "HttpOnly" in line
    assert "SameSite=strict" in line or "SameSite=Strict" in line
    assert "Path=/" in line
    assert "expires=" in line.lower()
    assert "Secure" not in line
    assert page.status_code == 200


async def test_login_cookie_is_secure_only_over_https(app: FastAPI) -> None:
    async with _anon(app, scheme="https") as client:
        response = await _post(
            client,
            "/login",
            {"password": OPERATOR_PASSWORD},
            headers={"Origin": "https://localhost"},
        )

    assert "Secure" in _session_cookie_line(response)


async def test_login_ignores_a_next_parameter(app: FastAPI) -> None:
    async with _anon(app) as client:
        response = await _post(
            client,
            "/login?next=https://evil.example/",
            {"password": OPERATOR_PASSWORD, "next": "https://evil.example/"},
        )

    assert response.headers["location"] == "/"


async def test_login_failure_is_uniform_logged_and_sets_no_cookie(
    app: FastAPI, logs: pytest.LogCaptureFixture
) -> None:
    async with _anon(app, peer=REMOTE) as client:
        response = await _post(client, "/login", {"password": "wrong synthetic password"})

    assert response.status_code == 401
    assert "Invalid password" in response.text
    assert SESSION_COOKIE_NAME not in response.headers.get("set-cookie", "")
    messages = [r.getMessage() for r in logs.records]
    failed = [m for m in messages if "operator.login_failed" in m]
    assert len(failed) == 1 and REMOTE[0] in failed[0]
    assert not any("wrong synthetic password" in m for m in messages)


async def test_login_without_csrf_token_is_refused(app: FastAPI) -> None:
    async with _anon(app) as client:
        response = await client.post("/login", data={"password": OPERATOR_PASSWORD}, headers=ORIGIN)

    assert response.status_code == 403


async def test_login_is_throttled_per_client_with_retry_after(
    app: FastAPI, login_throttle: LoginThrottle
) -> None:
    async with _anon(app, peer=REMOTE) as client:
        for _ in range(5):
            assert (await _post(client, "/login", {"password": "nope"})).status_code == 401
        locked = await _post(client, "/login", {"password": OPERATOR_PASSWORD})
    async with _anon(app, peer=("203.0.113.77", 1)) as other:
        fine = await _post(other, "/login", {"password": OPERATOR_PASSWORD})

    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) >= 1
    assert "Too many failed attempts" in locked.text
    assert SESSION_COOKIE_NAME not in locked.headers.get("set-cookie", "")
    assert fine.status_code == 303


async def test_global_lock_blocks_every_client_without_naming_the_key(
    app: FastAPI, login_throttle: LoginThrottle
) -> None:
    for _ in range(50):
        login_throttle.record_failure("*")
    async with _anon(app, peer=REMOTE) as client:
        by_global = await _post(client, "/login", {"password": OPERATOR_PASSWORD})
    for _ in range(5):
        login_throttle.record_failure("198.51.100.5")
    async with _anon(app, peer=("198.51.100.5", 1)) as other:
        by_client = await _post(other, "/login", {"password": OPERATOR_PASSWORD})

    assert by_global.status_code == by_client.status_code == 429
    assert _normalized(by_global.text) == _normalized(by_client.text)


async def test_success_resets_the_client_key_but_not_the_global_one(
    app: FastAPI, login_throttle: LoginThrottle
) -> None:
    for _ in range(49):
        login_throttle.record_failure("*")
    for _ in range(3):
        login_throttle.record_failure(REMOTE[0])
    async with _anon(app, peer=REMOTE) as client:
        ok = await _post(client, "/login", {"password": OPERATOR_PASSWORD})
        assert ok.status_code == 303
        assert login_throttle.retry_after(REMOTE[0]) is None
        # The global counter survived: one more failure reaches its threshold of 50.
        await _post(client, "/login", {"password": "nope"})
    assert login_throttle.retry_after("*") is not None


async def test_forwarded_for_does_not_change_the_throttle_key(app: FastAPI) -> None:
    async with _anon(app, peer=REMOTE) as client:
        for index in range(5):
            await _post(
                client,
                "/login",
                {"password": "nope"},
                headers={"X-Forwarded-For": f"10.0.0.{index}"},
            )
        locked = await _post(
            client,
            "/login",
            {"password": OPERATOR_PASSWORD},
            headers={"X-Forwarded-For": "10.9.9.9"},
        )

    assert locked.status_code == 429


async def test_trusted_proxy_throttles_by_the_forwarded_address(
    db: Database,
    settings: Settings,
    accounts: AccountService,
    operator_auth: OperatorAuth,
    login_throttle: LoginThrottle,
) -> None:
    trusting_settings = settings.model_copy(update={"trusted_proxies": (REMOTE[0],)})
    app = _app(db, trusting_settings, accounts, operator_auth, login_throttle)
    async with _anon(app, peer=REMOTE) as client:
        for _ in range(5):
            await _post(
                client,
                "/login",
                {"password": "nope"},
                headers={"X-Forwarded-For": "10.0.0.5"},
            )
        still_fine = await _post(
            client,
            "/login",
            {"password": OPERATOR_PASSWORD},
            headers={"X-Forwarded-For": "10.0.0.6"},
        )
    assert still_fine.status_code == 303
    assert login_throttle.retry_after("10.0.0.5") is not None
    assert login_throttle.retry_after(REMOTE[0]) is None


# --- signing out and changing the password --------------------------------------


async def test_logout_revokes_the_session_and_clears_the_cookie(
    app: FastAPI, operator_auth: OperatorAuth
) -> None:
    session = await operator_auth.create_session()
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session.token)
        response = await _post(client, "/logout", {})

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    line = _session_cookie_line(response)
    assert "Max-Age=0" in line
    assert "HttpOnly" in line and "Path=/" in line
    assert not await operator_auth.validate_session(session.token)


async def test_password_change_replaces_all_sessions(
    app: FastAPI, operator_auth: OperatorAuth, login_throttle: LoginThrottle
) -> None:
    old = await operator_auth.create_session()
    other = await operator_auth.create_session()
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, old.token)
        response = await _post(
            client,
            "/settings/password",
            {
                "current_password": OPERATOR_PASSWORD,
                "new_password": NEW_PASSWORD,
                "repeat": NEW_PASSWORD,
            },
        )
        new_token = _session_cookie(response)
        client.cookies.set(SESSION_COOKIE_NAME, new_token)
        page = await client.get("/settings")

    assert response.status_code == 200
    assert "Password changed" in response.text
    assert not await operator_auth.validate_session(old.token)
    assert not await operator_auth.validate_session(other.token)
    assert await operator_auth.validate_session(new_token)
    assert page.status_code == 200
    assert await operator_auth.verify_password(NEW_PASSWORD)
    assert not await operator_auth.verify_password(OPERATOR_PASSWORD)


async def test_password_change_with_wrong_current_password_changes_nothing(
    app: FastAPI, operator_auth: OperatorAuth, login_throttle: LoginThrottle
) -> None:
    session = await operator_auth.create_session()
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session.token)
        response = await _post(
            client,
            "/settings/password",
            {"current_password": "not it", "new_password": NEW_PASSWORD, "repeat": NEW_PASSWORD},
        )

    assert response.status_code == 403
    assert "The current password is wrong." in response.text
    assert SESSION_COOKIE_NAME not in response.headers.get("set-cookie", "")
    assert await operator_auth.verify_password(OPERATOR_PASSWORD)
    assert await operator_auth.validate_session(session.token)


async def test_password_change_is_throttled_like_login(
    app: FastAPI, operator_auth: OperatorAuth
) -> None:
    session = await operator_auth.create_session()
    form = {"current_password": "not it", "new_password": NEW_PASSWORD, "repeat": NEW_PASSWORD}
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session.token)
        for _ in range(5):
            await _post(client, "/settings/password", form)
        locked = await _post(
            client, "/settings/password", {**form, "current_password": OPERATOR_PASSWORD}
        )

    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) >= 1
    assert await operator_auth.verify_password(OPERATOR_PASSWORD) is True


@pytest.mark.parametrize(
    ("new", "repeat", "text"),
    [("short", "short", "at least 16 characters"), (NEW_PASSWORD, "different", "do not match")],
)
async def test_password_change_rejects_bad_new_passwords(
    app: FastAPI, operator_auth: OperatorAuth, new: str, repeat: str, text: str
) -> None:
    session = await operator_auth.create_session()
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session.token)
        response = await _post(
            client,
            "/settings/password",
            {"current_password": OPERATOR_PASSWORD, "new_password": new, "repeat": repeat},
        )

    assert response.status_code == 400
    assert text in response.text
    assert await operator_auth.verify_password(OPERATOR_PASSWORD)
    assert await operator_auth.validate_session(session.token)


# --- failing login system -------------------------------------------------------


async def test_open_secrets_file_gives_503_not_setup_or_access(
    app: FastAPI, operator_auth: OperatorAuth, tmp_path: Path, logs: pytest.LogCaptureFixture
) -> None:
    session = await operator_auth.create_session()
    (tmp_path / "auth" / "secrets.toml").chmod(0o644)
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session.token)
        page = await client.get("/")
        login = await client.get("/login")

    assert page.status_code == 503
    assert login.status_code == 503
    assert "Set a password" not in login.text
    assert any("operator.auth_unavailable" in r.getMessage() for r in logs.records)


async def test_broken_stored_hash_gives_503_on_login_not_401(app: FastAPI, tmp_path: Path) -> None:
    write_operator_hash(tmp_path / "auth" / "secrets.toml", "not-an-argon2-hash")
    async with _anon(app) as client:
        response = await _post(client, "/login", {"password": OPERATOR_PASSWORD})

    assert response.status_code == 503
    assert SESSION_COOKIE_NAME not in response.headers.get("set-cookie", "")


async def test_session_lookup_failure_gives_503(
    app: FastAPI, operator_auth: OperatorAuth, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = await operator_auth.create_session()

    async def boom(_token: str) -> bool:
        raise OperatorAuthError("session store broke")

    monkeypatch.setattr(operator_auth, "validate_session", boom)
    async with _anon(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session.token)
        response = await client.get("/")

    assert response.status_code == 503
    assert "session store broke" not in response.text


# --- translations ---------------------------------------------------------------


async def test_login_page_is_translated_to_german(app: FastAPI) -> None:
    async with _anon(app) as client:
        client.cookies.set(LANG_COOKIE_NAME, "de")
        response = await client.get("/login")

    assert "Anmelden" in response.text
    assert "Sign in" not in response.text


def test_every_template_message_has_a_german_translation() -> None:
    root = Path(__file__).parents[2] / "src" / "carchive" / "web"
    with (root / "locale" / "de" / "LC_MESSAGES" / "messages.po").open("rb") as handle:
        catalog = read_po(handle, locale="de")
    missing = []
    for template in sorted((root / "templates").glob("*.html")):
        for _line, message, _comments, _ctx in extract_from_file(
            "jinja2", template, options={"extensions": "jinja2.ext.i18n"}
        ):
            text = message if isinstance(message, str) else message[0]
            entry = catalog.get(text)
            if entry is None or not entry.string:
                missing.append((template.name, text))
    assert missing == []
