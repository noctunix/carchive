"""Tests for `carchive.web.uploads.read_multipart_upload`."""

from __future__ import annotations

import stat
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from carchive.web.uploads import UploadError, UploadTooLargeError, read_multipart_upload


def _build_app(dest_dir: Path, max_body_bytes: int) -> Starlette:
    async def upload(request: Request) -> Response:
        try:
            result = await read_multipart_upload(
                request, file_field="file", max_body_bytes=max_body_bytes, dest_dir=dest_dir
            )
        except UploadTooLargeError:
            return JSONResponse({"error": "too_large"}, status_code=413)
        except UploadError:
            return JSONResponse({"error": "invalid"}, status_code=400)
        return JSONResponse(
            {
                "path": str(result.path),
                "fields": result.fields,
                "original_filename": result.original_filename,
                "mode": stat.S_IMODE(result.path.stat().st_mode),
                "content": result.path.read_bytes().decode(),
            }
        )

    return Starlette(routes=[Route("/upload", upload, methods=["POST"])])


def _client(app: Starlette) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


async def test_writes_the_file_field_owner_only(tmp_path: Path) -> None:
    app = _build_app(tmp_path, max_body_bytes=1_000_000)
    async with _client(app) as client:
        response = await client.post(
            "/upload",
            files={"file": ("dict.pdf", b"pdf-bytes-here", "application/pdf")},
            data={"catalog_version": "6.0"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["content"] == "pdf-bytes-here"
    assert body["fields"] == {"catalog_version": "6.0"}
    assert body["original_filename"] == "dict.pdf"
    assert body["mode"] == 0o600


async def test_oversized_upload_is_rejected_and_temp_file_removed(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    app = _build_app(upload_dir, max_body_bytes=10)
    async with _client(app) as client:
        response = await client.post(
            "/upload",
            files={"file": ("dict.pdf", b"x" * 1000, "application/pdf")},
        )

    assert response.status_code == 413
    assert list(upload_dir.iterdir()) == []


async def test_missing_file_field_is_rejected(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    app = _build_app(upload_dir, max_body_bytes=1_000_000)
    async with _client(app) as client:
        response = await client.post("/upload", data={"catalog_version": "6.0"})

    assert response.status_code == 400
    assert list(upload_dir.iterdir()) == []


async def test_missing_content_type_is_rejected(tmp_path: Path) -> None:
    app = _build_app(tmp_path, max_body_bytes=1_000_000)
    async with _client(app) as client:
        response = await client.post("/upload", content=b"not multipart at all")

    assert response.status_code == 400
