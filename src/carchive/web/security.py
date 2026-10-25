"""CSRF protection, the CSRF cookie and baseline security headers.

Written as pure ASGI middleware, not Starlette's `BaseHTTPMiddleware`: the request body has
to be read once to find a form-encoded CSRF token, and `BaseHTTPMiddleware` reading the
body itself is a well-known way to break the downstream route handler's own body access
unless the read is carefully replayed, which is what `_buffer_body` does explicitly here.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable, MutableMapping
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlsplit

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

CSRF_COOKIE_NAME = "csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER_NAME = b"x-csrf-token"

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Generous for the hand-written forms this app has; large uploads go through a dedicated
# route with its own streaming size limit, never through this buffering middleware.
_MAX_BODY_BYTES = 1_000_000

SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "x-content-type-options": "nosniff",
    # Not "no-referrer": the HTML standard's "append the Origin header" algorithm folds in
    # the referrer policy and sends the literal string "null" on a same-origin form POST
    # when it resolves to no referrer, which the CSRF check below then rejects as
    # cross-origin. "same-origin" never leaks a referrer to another origin either, but
    # keeps the real Origin on same-origin navigations.
    "referrer-policy": "same-origin",
    "x-frame-options": "DENY",
}

# Six months; deliberately without includeSubDomains/preload, which are hard to undo.
_HSTS_HEADER = (b"strict-transport-security", b"max-age=15552000")


def _header_value(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _cookie_value(headers: list[tuple[bytes, bytes]], name: str) -> str | None:
    cookie_header = _header_value(headers, b"cookie")
    if not cookie_header:
        return None
    jar: SimpleCookie = SimpleCookie()
    try:
        jar.load(cookie_header)
    except ValueError:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


def _query_param(scope: Scope, name: str) -> str | None:
    """Return the first value of query-string parameter `name`, or `None` if absent."""
    values = parse_qs(scope.get("query_string", b"").decode("latin-1")).get(name)
    return values[0] if values else None


def _host_allowed(url: str | None, allowed_hosts: frozenset[str]) -> bool:
    """Return whether `url`'s host (from an `Origin`/`Referer` header) is in `allowed_hosts`."""
    if not url:
        return False
    hostname = urlsplit(url).hostname
    if hostname is None:
        return False
    return hostname.strip("[]").lower() in allowed_hosts


async def _buffer_body(receive: Receive) -> tuple[bytes, Receive]:
    """Read the whole request body and return it alongside a `receive` that replays it.

    Raises:
        ValueError: if the body exceeds `_MAX_BODY_BYTES`.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > _MAX_BODY_BYTES:
            raise ValueError("request body exceeds the CSRF middleware's size limit")
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    body = b"".join(chunks)

    already_replayed = False

    async def replay_receive() -> Message:
        nonlocal already_replayed
        if not already_replayed:
            already_replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return body, replay_receive


def _extract_form_token(content_type: str | None, body: bytes) -> str | None:
    """Return the `csrf_token` field from an `application/x-www-form-urlencoded` body.

    Multipart forms are not parsed here (that needs a streaming, size-bounded parser of its
    own); a multipart POST must send the token as the `X-CSRF-Token` header instead.
    """
    if not content_type or "application/x-www-form-urlencoded" not in content_type:
        return None
    try:
        fields = parse_qs(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    values = fields.get(CSRF_FORM_FIELD)
    return values[0] if values else None


def _csrf_cookie_header(token: str, *, secure: bool) -> str:
    parts = [f"{CSRF_COOKIE_NAME}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


class SecurityMiddleware:
    """CSRF protection, the CSRF cookie, and baseline security headers on every response.

    For `POST`/`PUT`/`PATCH`/`DELETE`, requires the CSRF cookie to be present and to match
    either the `X-CSRF-Token` header or a `csrf_token` form field, and requires the
    `Origin` (falling back to `Referer`) header's host to be in `allowed_hosts`; otherwise
    responds `403` without reaching the application. Every response, including that `403`,
    carries the baseline security headers (plus HSTS when enabled and the request arrived
    over HTTPS); a missing CSRF cookie is set on the way out.

    A request to one of `streaming_paths` is exempted from the body-buffering above: its
    body is passed straight through to the route, which is expected to enforce its own
    streaming size limit. Its CSRF token therefore cannot be read from a form field (that
    would need buffering the exact body this path exists to avoid) and arrives instead as
    the `X-CSRF-Token` header or, for a plain HTML form post with no script to set a
    header, the `csrf_token` query-string parameter on the request's own URL.

    Args:
        app: the wrapped ASGI application.
        allowed_hosts: hosts an `Origin`/`Referer` header must match for a state-changing
            request to be accepted.
        streaming_paths: exact request paths exempted from body buffering, for routes that
            stream a large upload to disk with their own size limit (e.g. a catalog PDF
            import) instead of relying on this middleware's small in-memory cap.
        hsts: whether to send `Strict-Transport-Security` on HTTPS responses.
    """

    def __init__(
        self,
        app: ASGIApp,
        allowed_hosts: tuple[str, ...],
        *,
        streaming_paths: frozenset[str] = frozenset(),
        hsts: bool = True,
    ) -> None:
        self._app = app
        self._hsts = hsts
        self._allowed_hosts = frozenset(host.strip("[]").lower() for host in allowed_hosts)
        self._streaming_paths = streaming_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Enforce CSRF protection for state-changing methods, then call the app."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        existing_cookie = _cookie_value(headers, CSRF_COOKIE_NAME)
        token = existing_cookie if existing_cookie else secrets.token_urlsafe(32)
        scope.setdefault("state", {})["csrf_token"] = token

        send = self._wrap_send(send, scope, needs_cookie=existing_cookie is None, token=token)

        if scope["method"] in _UNSAFE_METHODS:
            origin = _header_value(headers, b"origin") or _header_value(headers, b"referer")

            if scope["path"] in self._streaming_paths:
                provided = _header_value(headers, CSRF_HEADER_NAME) or _query_param(
                    scope, CSRF_FORM_FIELD
                )
                if (
                    existing_cookie is None
                    or provided is None
                    or not secrets.compare_digest(existing_cookie, provided)
                    or not _host_allowed(origin, self._allowed_hosts)
                ):
                    await self._reject(send, 403, "CSRF validation failed")
                    return
                await self._app(scope, receive, send)
                return

            try:
                body, receive = await _buffer_body(receive)
            except ValueError:
                await self._reject(send, 413, "request body too large")
                return

            content_type = _header_value(headers, b"content-type")
            header_token = _header_value(headers, CSRF_HEADER_NAME)
            provided = header_token or _extract_form_token(content_type, body)

            if (
                existing_cookie is None
                or provided is None
                or not secrets.compare_digest(existing_cookie, provided)
                or not _host_allowed(origin, self._allowed_hosts)
            ):
                await self._reject(send, 403, "CSRF validation failed")
                return

        await self._app(scope, receive, send)

    def _wrap_send(self, send: Send, scope: Scope, *, needs_cookie: bool, token: str) -> Send:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers_out = list(message.get("headers", []))
                for name, value in SECURITY_HEADERS.items():
                    headers_out.append((name.encode(), value.encode()))
                secure = scope.get("scheme") == "https"
                if secure and self._hsts:
                    headers_out.append(_HSTS_HEADER)
                if needs_cookie:
                    cookie = _csrf_cookie_header(token, secure=secure)
                    headers_out.append((b"set-cookie", cookie.encode()))
                message = {**message, "headers": headers_out}
            await send(message)

        return send_with_headers

    async def _reject(self, send: Send, status: int, reason: str) -> None:
        body = f"<!doctype html><title>{status}</title><p>{reason}</p>".encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/html; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": body})
