"""Operator login for the web GUI: the authentication middleware and cookie/client helpers.

Pure ASGI middleware like `web.security`. Every request except the health probe, static
files, the language switch and the login pages needs a valid session; without one it is
redirected or refused.
The client address comes from the ASGI scope (the socket peer) by default; forwarding
headers are only trusted for peers listed in `Settings.trusted_proxies`, which is empty
unless the operator runs a known reverse proxy in front.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

import structlog
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from carchive.config import ConfigError, InsecureSecretsError
from carchive.core.redact import redact
from carchive.services.operator_auth import (
    THROTTLE_GLOBAL_KEY,
    LoginThrottle,
    OperatorAuth,
    OperatorAuthError,
)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

logger = structlog.get_logger(__name__)

SESSION_COOKIE_NAME = "carchive_session"
LOGIN_PATH = "/login"
LOGIN_SETUP_PATH = "/login/setup"

_LOGIN_PATHS = frozenset({LOGIN_PATH, LOGIN_SETUP_PATH})
_UNKNOWN_CLIENT = "unknown"

AUTH_ERRORS = (InsecureSecretsError, ConfigError, OperatorAuthError, SQLAlchemyError, OSError)
"""Failures of the login state itself; they end in a 503, never in a login decision."""


def _header_value(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _is_trusted_proxy(peer: str, trusted_proxies: Sequence[str]) -> bool:
    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in trusted_proxies:
        try:
            if peer_address == ipaddress.ip_address(entry):
                return True
        except ValueError:
            if peer_address in ipaddress.ip_network(entry, strict=False):
                return True
    return False


def _forwarded_peer(scope: Scope) -> str | None:
    """Return the left-most, validated address from `X-Forwarded-For`, if any.

    Only the first entry is used: it is the one set by the actual client, everything to
    its right was appended by proxies on the way. A missing, empty or syntactically
    invalid entry yields `None` rather than unvalidated free text.
    """
    header = _header_value(scope.get("headers", []), b"x-forwarded-for")
    if not header:
        return None
    candidate = header.split(",", 1)[0].strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def client_key(scope: Scope, trusted_proxies: Sequence[str] = ()) -> str:
    """Return the key identifying the requesting client for the login throttle.

    Normally this is the socket peer's address. If the peer itself is listed in
    `trusted_proxies`, the left-most address of its `X-Forwarded-For` header is used
    instead, since that header then names the real client rather than being attacker-
    controlled free text. An untrusted peer's `X-Forwarded-For` header is always ignored.

    Args:
        scope: the ASGI connection scope.
        trusted_proxies: socket peer addresses or networks allowed to set
            `X-Forwarded-For`; empty trusts no one, which is the default.

    Returns:
        The client address to key the throttle on, or a fixed placeholder if the server
        reports no peer at all.
    """
    client = scope.get("client")
    if not client or not isinstance(client[0], str) or not client[0]:
        return _UNKNOWN_CLIENT
    peer = str(client[0])
    if not trusted_proxies or not _is_trusted_proxy(peer, trusted_proxies):
        return peer
    return _forwarded_peer(scope) or peer


def set_session_cookie(
    response: Response, token: str, *, expires_at: datetime, secure: bool
) -> None:
    """Attach the session cookie to a response.

    Args:
        response: the response to modify.
        token: the raw session token.
        expires_at: the session's absolute expiry, used as the cookie's `Expires`.
        secure: whether to set the `Secure` attribute (the request arrived over HTTPS).
    """
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        expires=expires_at,
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict",
    )


def clear_session_cookie(response: Response, *, secure: bool) -> None:
    """Attach a cookie deletion with the same attributes the session cookie was set with.

    Args:
        response: the response to modify.
        secure: whether to set the `Secure` attribute.
    """
    response.delete_cookie(
        SESSION_COOKIE_NAME, path="/", secure=secure, httponly=True, samesite="strict"
    )


def is_secure_request(scope: Scope) -> bool:
    """Return whether the connection itself is HTTPS, as the server reports it."""
    return bool(scope.get("scheme") == "https")


def request_state(scope: Scope) -> dict[str, Any]:
    """Return the per-request state dict that `AuthMiddleware` fills in."""
    state: dict[str, Any] = scope.setdefault("state", {})
    return state


def unavailable_response(request: Request) -> Response:
    """Render the generic 503 page for a failing login system; it carries no detail.

    Args:
        request: the current request.

    Returns:
        The 503 error page.
    """
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "error.html", {"status_code": 503, "vehicle_count": 0}, status_code=503
    )


@dataclass(frozen=True, slots=True)
class PasswordAttempt:
    """The result of checking a password against the throttle and the stored hash.

    Attributes:
        outcome: `"ok"` for a match, `"wrong"` for a mismatch, `"locked"` if the throttle
            refused the attempt before the password was looked at.
        retry_after: seconds until a new attempt is allowed; only set for `"locked"`.
    """

    outcome: Literal["ok", "wrong", "locked"]
    retry_after: int = 0


async def attempt_password(
    operator_auth: OperatorAuth,
    throttle: LoginThrottle,
    lock: asyncio.Lock,
    scope: Scope,
    password: str,
    trusted_proxies: Sequence[str] = (),
) -> PasswordAttempt:
    """Check a password for the requesting client, counting failures against the throttle.

    Attempts are serialized by `lock`, so concurrent requests cannot slip past a lockout.
    Failures count for the client's address and for the global key; a success clears only
    the client's key, so one valid login does not erase a distributed attack's count.

    Args:
        operator_auth: the login backend.
        throttle: the process-wide throttle.
        lock: serializes attempts; shared by every caller that checks the operator password.
        scope: the ASGI scope, source of the client address.
        password: the password to check.
        trusted_proxies: see `client_key`; empty trusts no peer, which is the default.

    Returns:
        The outcome; the password is not checked while the client or the global key is
        locked, and the result does not say which one.

    Raises:
        InsecureSecretsError: if the secrets file is group/world-accessible.
        ConfigError: if the secrets file is malformed.
        OperatorAuthError: if the stored hash is unusable.
    """
    key = client_key(scope, trusted_proxies)
    async with lock:
        waits = [throttle.retry_after(key), throttle.retry_after(THROTTLE_GLOBAL_KEY)]
        locked_for = max((wait for wait in waits if wait is not None), default=None)
        if locked_for is not None:
            return PasswordAttempt("locked", retry_after=locked_for)
        if await operator_auth.verify_password(password):
            throttle.record_success(key)
            return PasswordAttempt("ok")
        throttle.record_failure(key)
        throttle.record_failure(THROTTLE_GLOBAL_KEY)
    logger.warning("operator.login_failed", client=key)
    return PasswordAttempt("wrong")


def _is_public_path(path: str) -> bool:
    return (
        path == "/healthz"
        or path == "/static"
        or path.startswith("/static/")
        or path.startswith("/lang/")
    )


class AuthMiddleware:
    """Requires a valid operator session for everything except the public paths.

    Public: `/healthz`, `/static/*`, `/lang/*`, `/login` and `/login/setup`. On the login
    pages the session is still looked up so the page can tell whether someone is signed in.
    With no password set, every other request is redirected to `/login` (303), where the
    password can be chosen. With a password set but no valid session: HTMX requests get 401 with
    `HX-Redirect`, other `GET`/`HEAD` requests are redirected to `/login`, anything else gets
    a plain 401.
    If the login state cannot be determined (broken secrets file, database error) the
    request gets a 503 page: it is never treated as "no password" or "signed in".

    Fills `scope["state"]` with `password_set` and `authenticated` for the routes and
    templates.

    Args:
        app: the wrapped ASGI application.
        operator_auth: the login backend.
    """

    def __init__(self, app: ASGIApp, operator_auth: OperatorAuth) -> None:
        self._app = app
        self._auth = operator_auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Let public paths through, check the session for the rest."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        state = request_state(scope)
        state["password_set"] = False
        state["authenticated"] = False
        path = scope["path"]
        if _is_public_path(path):
            await self._app(scope, receive, send)
            return

        request = Request(scope, receive)
        try:
            password_set = await asyncio.to_thread(self._auth.password_is_set)
            token = request.cookies.get(SESSION_COOKIE_NAME)
            authenticated = (
                password_set and bool(token) and await self._auth.validate_session(token or "")
            )
        except Exception as exc:  # unknown login state must end in a 503, never in access
            logger.error("operator.auth_unavailable", error=redact(str(exc)))
            await unavailable_response(request)(scope, receive, send)
            return
        state["password_set"] = password_set
        state["authenticated"] = authenticated

        if path in _LOGIN_PATHS or authenticated:
            await self._app(scope, receive, send)
            return
        await self._deny(request, password_set=password_set)(scope, receive, send)

    @staticmethod
    def _deny(request: Request, *, password_set: bool) -> Response:
        if not password_set:
            return RedirectResponse(LOGIN_PATH, status_code=303)
        # An HTMX swap would render a followed redirect inside the page fragment.
        if "hx-request" in request.headers:
            return PlainTextResponse(
                "Authentication required", status_code=401, headers={"HX-Redirect": LOGIN_PATH}
            )
        if request.method in ("GET", "HEAD"):
            return RedirectResponse(LOGIN_PATH, status_code=303)
        return PlainTextResponse("Authentication required", status_code=401)
