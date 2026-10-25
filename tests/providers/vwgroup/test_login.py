"""Tests for the VW-group OIDC login flow, against `httpx.MockTransport` fixtures only."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from carchive.core.errors import AuthenticationError, NeedsAttentionError, TransientError
from carchive.providers.vwgroup import login

PASSWORD = "s3cr3t-canary-password"

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

NO_FORM_HTML = "<html><body>no login form here</body></html>"


def _credentials_page_html(error: str = "") -> str:
    return f"""
<script>
window._IDK = {{
  templateModel: {{
    hmac: 'hmac-2',
    relayState: 'relay-2',
    postAction: '/signin-service/v1/some-client/login/authenticate',
    identifierUrl: '/signin-service/v1/some-client/login/identifier',
    error: '{error}',
  }},
  currentLocale: 'de',
  csrf_parameterName: '_csrf',
  csrf_token: 'csrf-token-2',
}};
</script>
"""


def _redirect(location: str) -> httpx.Response:
    return httpx.Response(302, headers={"Location": location})


def _build_handler(
    routes: dict[tuple[str, str], httpx.Response | Exception],
) -> Callable[[httpx.Request], httpx.Response]:
    """Build a `MockTransport` handler keyed by `(method, path)`, ignoring host and query."""

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        try:
            outcome = routes[key]
        except KeyError:
            raise AssertionError(f"unscripted request: {key}") from None
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return handler


def _client(routes: dict[tuple[str, str], httpx.Response | Exception]) -> httpx.AsyncClient:
    transport = httpx.MockTransport(_build_handler(routes))
    return httpx.AsyncClient(transport=transport, follow_redirects=False)


_SUCCESS_ROUTES_BASE: dict[tuple[str, str], httpx.Response | Exception] = {
    ("GET", "/oidc/v1/authorize"): _redirect("https://identity.vwgroup.io/login-form"),
    ("GET", "/login-form"): httpx.Response(200, text=EMAIL_FORM_HTML),
    ("POST", "/signin-service/v1/some-client/login/identifier"): _redirect(
        "https://identity.vwgroup.io/credentials-page"
    ),
    ("GET", "/credentials-page"): httpx.Response(200, text=_credentials_page_html()),
}


async def test_login_succeeds_directly_to_the_user_page() -> None:
    routes = {
        **_SUCCESS_ROUTES_BASE,
        ("POST", "/signin-service/v1/some-client/login/authenticate"): _redirect(
            "https://eu-data-act.drivesomethinggreater.com/content/euda/de/en/user.html"
        ),
    }
    client = _client(routes)
    try:
        await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()


async def test_login_succeeds_through_marketing_consent_detour() -> None:
    routes = {
        **_SUCCESS_ROUTES_BASE,
        ("POST", "/signin-service/v1/some-client/login/authenticate"): _redirect(
            "https://identity.vwgroup.io/signin-service/v1/consent/marketing/abc"
            "?callback=https://identity.vwgroup.io/marketing-callback"
        ),
        ("GET", "/marketing-callback"): _redirect(
            "https://eu-data-act.drivesomethinggreater.com/content/euda/de/en/user.html"
        ),
    }
    client = _client(routes)
    try:
        await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()


async def test_wrong_password_raises_authentication_error_and_never_echoes_it() -> None:
    routes = {
        **_SUCCESS_ROUTES_BASE,
        ("POST", "/signin-service/v1/some-client/login/authenticate"): httpx.Response(
            200, text=_credentials_page_html(error="Bad credentials")
        ),
    }
    client = _client(routes)
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()
    assert PASSWORD not in str(exc_info.value)
    assert "Bad credentials" in str(exc_info.value)


async def test_rejected_identifier_raises_authentication_error() -> None:
    routes = {
        **_SUCCESS_ROUTES_BASE,
        ("GET", "/credentials-page"): httpx.Response(
            200, text=_credentials_page_html(error="unknown user")
        ),
    }
    client = _client(routes)
    try:
        with pytest.raises(AuthenticationError, match="unknown user"):
            await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()


async def test_missing_login_form_raises_needs_attention() -> None:
    routes = {
        **_SUCCESS_ROUTES_BASE,
        ("GET", "/login-form"): httpx.Response(200, text=NO_FORM_HTML),
    }
    client = _client(routes)
    try:
        with pytest.raises(NeedsAttentionError, match="form"):
            await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()


async def test_redirect_to_foreign_host_raises_needs_attention() -> None:
    routes = {
        **_SUCCESS_ROUTES_BASE,
        ("POST", "/signin-service/v1/some-client/login/authenticate"): _redirect(
            "https://evil.example.com/phish"
        ),
    }
    client = _client(routes)
    try:
        with pytest.raises(NeedsAttentionError, match="host"):
            await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()


async def test_too_many_redirects_raises_needs_attention() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oidc/v1/authorize":
            return _redirect("https://identity.vwgroup.io/bounce/0")
        if request.url.path.startswith("/bounce/"):
            n = int(request.url.path.rsplit("/", 1)[1])
            return _redirect(f"https://identity.vwgroup.io/bounce/{n + 1}")
        raise AssertionError(f"unscripted request: {request.url.path}")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        with pytest.raises(NeedsAttentionError, match="too many"):
            await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()


async def test_timeout_raises_transient_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("connect timed out")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        with pytest.raises(TransientError):
            await login.perform_login(client, "audi", "user@example.com", PASSWORD)
    finally:
        await client.aclose()


async def test_unknown_brand_raises_value_error() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
        follow_redirects=False,
    )
    try:
        with pytest.raises(ValueError, match="unknown VW-group brand"):
            await login.perform_login(client, "toyota", "user@example.com", PASSWORD)
    finally:
        await client.aclose()
