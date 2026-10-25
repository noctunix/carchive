"""Tests for `carchive.web.security.SecurityMiddleware`, isolated from the rest of the app."""

from __future__ import annotations

import httpx
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from carchive.web.security import CSRF_COOKIE_NAME, SecurityMiddleware


async def _echo(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def _build_app(
    allowed_hosts: tuple[str, ...] = ("localhost",),
    *,
    streaming_paths: frozenset[str] = frozenset(),
    hsts: bool = True,
) -> Starlette:
    return Starlette(
        routes=[
            Route("/get", _echo, methods=["GET"]),
            Route("/post", _echo, methods=["POST"]),
            Route("/upload", _echo, methods=["POST"]),
        ],
        middleware=[
            Middleware(
                SecurityMiddleware,
                allowed_hosts=allowed_hosts,
                streaming_paths=streaming_paths,
                hsts=hsts,
            )
        ],
    )


def _client(app: Starlette, base_url: str = "http://localhost") -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)


async def test_get_sets_csrf_cookie_and_security_headers() -> None:
    async with _client(_build_app()) as client:
        response = await client.get("/get")

    assert response.status_code == 200
    assert CSRF_COOKIE_NAME in response.cookies
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "same-origin"
    assert "script-src 'self'" in response.headers["content-security-policy"]


async def test_hsts_is_sent_over_https_only_with_conservative_directives() -> None:
    async with _client(_build_app(), "https://localhost") as client:
        response = await client.get("/get")

    assert response.headers["strict-transport-security"] == "max-age=15552000"


async def test_no_hsts_over_plain_http() -> None:
    async with _client(_build_app()) as client:
        response = await client.get("/get")

    assert "strict-transport-security" not in response.headers


async def test_hsts_is_also_sent_on_rejected_requests_over_https() -> None:
    async with _client(_build_app(), "https://localhost") as client:
        response = await client.post("/post")

    assert response.status_code == 403
    assert response.headers["strict-transport-security"] == "max-age=15552000"


async def test_get_does_not_overwrite_an_existing_cookie() -> None:
    async with _client(_build_app()) as client:
        await client.get("/get")
        token = client.cookies[CSRF_COOKIE_NAME]
        second = await client.get("/get")

    assert client.cookies[CSRF_COOKIE_NAME] == token
    assert "set-cookie" not in second.headers


async def test_post_without_token_is_rejected() -> None:
    async with _client(_build_app()) as client:
        response = await client.post("/post")

    assert response.status_code == 403


async def test_post_with_token_but_foreign_origin_is_rejected() -> None:
    async with _client(_build_app()) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        response = await client.post(
            "/post", headers={"X-CSRF-Token": token, "Origin": "http://evil.example"}
        )

    assert response.status_code == 403


async def test_post_with_mismatched_token_is_rejected() -> None:
    async with _client(_build_app()) as client:
        await client.get("/get")
        response = await client.post(
            "/post", headers={"X-CSRF-Token": "wrong-token", "Origin": "http://localhost"}
        )

    assert response.status_code == 403


async def test_post_with_matching_token_and_allowed_origin_is_accepted() -> None:
    async with _client(_build_app()) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        response = await client.post(
            "/post", headers={"X-CSRF-Token": token, "Origin": "http://localhost"}
        )

    assert response.status_code == 200
    assert response.text == "ok"


async def test_post_with_form_field_token_and_allowed_referer_is_accepted() -> None:
    async with _client(_build_app()) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        response = await client.post(
            "/post",
            data={"csrf_token": token},
            headers={"Referer": "http://localhost/some-form"},
        )

    assert response.status_code == 200


async def test_streaming_path_accepts_token_in_header() -> None:
    app = _build_app(streaming_paths=frozenset({"/upload"}))
    async with _client(app) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        response = await client.post(
            "/upload",
            content=b"x" * 2_000_000,
            headers={"X-CSRF-Token": token, "Origin": "http://localhost"},
        )

    assert response.status_code == 200


async def test_streaming_path_accepts_token_in_query_string() -> None:
    app = _build_app(streaming_paths=frozenset({"/upload"}))
    async with _client(app) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        response = await client.post(
            f"/upload?csrf_token={token}",
            content=b"x" * 2_000_000,
            headers={"Origin": "http://localhost"},
        )

    assert response.status_code == 200


async def test_streaming_path_without_token_is_rejected() -> None:
    app = _build_app(streaming_paths=frozenset({"/upload"}))
    async with _client(app) as client:
        await client.get("/get")
        response = await client.post(
            "/upload", content=b"x" * 2_000_000, headers={"Origin": "http://localhost"}
        )

    assert response.status_code == 403


async def test_streaming_path_with_foreign_origin_is_rejected() -> None:
    app = _build_app(streaming_paths=frozenset({"/upload"}))
    async with _client(app) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        response = await client.post(
            "/upload",
            content=b"x" * 2_000_000,
            headers={"X-CSRF-Token": token, "Origin": "http://evil.example"},
        )

    assert response.status_code == 403


async def test_non_streaming_path_still_buffers_and_enforces_the_small_limit() -> None:
    app = _build_app(streaming_paths=frozenset({"/upload"}))
    async with _client(app) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        response = await client.post(
            "/post",
            content=b"x" * 2_000_000,
            headers={"X-CSRF-Token": token, "Origin": "http://localhost"},
        )

    assert response.status_code == 413


async def test_oversized_body_is_rejected() -> None:
    async with _client(_build_app()) as client:
        token = (await client.get("/get")).cookies[CSRF_COOKIE_NAME]
        oversized = "x" * 2_000_000
        response = await client.post(
            "/post",
            data={"csrf_token": token, "padding": oversized},
            headers={"Origin": "http://localhost"},
        )

    assert response.status_code == 413


async def test_hsts_can_be_disabled_without_dropping_other_headers_or_the_secure_cookie() -> None:
    async with _client(_build_app(hsts=False), "https://localhost") as client:
        response = await client.get("/get")
        rejected = await client.post("/post")

    assert "strict-transport-security" not in response.headers
    assert "strict-transport-security" not in rejected.headers
    assert rejected.status_code == 403
    assert "content-security-policy" in response.headers
    assert "Secure" in response.headers["set-cookie"]
