"""End-to-end: the app served by uvicorn over real TLS with a synthetic certificate."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import socket
import ssl
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import uvicorn
from starlette.types import ASGIApp

from carchive.cli import _hardened_ssl_context
from carchive.config import Settings
from carchive.services import tls_selfsigned
from carchive.services.accounts import AccountService
from carchive.storage.db import Database
from carchive.web.app import create_app
from tests.services.tls_fixtures import TlsFiles, make_files
from tests.web.conftest import FakeScheduler, build_services

_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class RunningServer:
    """A server listening on a free loopback port."""

    port: int
    files: TlsFiles
    context: ssl.SSLContext


@contextlib.asynccontextmanager
async def _running(app: ASGIApp, files: TlsFiles) -> AsyncGenerator[RunningServer]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        app,
        log_config=None,
        ssl_certfile=files.certfile,
        ssl_keyfile=files.keyfile,
        ssl_context_factory=_hardened_ssl_context,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(_TIMEOUT_S):
            while not server.started:
                if task.done():
                    task.result()
                    raise AssertionError("server stopped before it started")
                await asyncio.sleep(0.01)
        assert config.ssl is not None
        yield RunningServer(port=port, files=files, context=config.ssl)
    finally:
        server.should_exit = True
        async with asyncio.timeout(_TIMEOUT_S):
            await task
        sock.close()


@pytest.fixture
async def tls_server(
    tmp_path: Path, db: Database, accounts: AccountService
) -> AsyncGenerator[RunningServer]:
    files = make_files(tmp_path)
    settings = Settings(
        data_dir=tmp_path / "data", tls_certfile=files.certfile, tls_keyfile=files.keyfile
    )
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)
    async with _running(app, files) as running:
        yield running


def _trusting_context(files: TlsFiles) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(files.certfile))


async def test_https_request_succeeds_and_sends_hsts(tls_server: RunningServer) -> None:
    context = _trusting_context(tls_server.files)

    async with httpx.AsyncClient(verify=context, timeout=_TIMEOUT_S) as client:
        response = await client.get(f"https://localhost:{tls_server.port}/healthz")

    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == "max-age=15552000"
    assert "content-security-policy" in response.headers


async def test_https_sets_the_secure_csrf_cookie(tls_server: RunningServer) -> None:
    context = _trusting_context(tls_server.files)

    async with httpx.AsyncClient(verify=context, timeout=_TIMEOUT_S) as client:
        response = await client.get(f"https://localhost:{tls_server.port}/healthz")

    assert "Secure" in response.headers["set-cookie"]


async def test_plain_http_on_the_tls_port_gets_no_response(tls_server: RunningServer) -> None:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", tls_server.port), _TIMEOUT_S
    )
    try:
        writer.write(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), _TIMEOUT_S)
        except ConnectionError:
            data = b""
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    assert not data.startswith(b"HTTP/")


def _legacy_client_context() -> ssl.SSLContext:
    """A client that only speaks TLS 1.0/1.1, if this OpenSSL can be talked into it."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ssl.SSLError, ValueError) as exc:
        pytest.skip(f"local OpenSSL cannot be configured for TLS 1.0/1.1 clients: {exc}")
    return context


async def _handshake(port: int, context: ssl.SSLContext) -> None:
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port, ssl=context, server_hostname="localhost"),
        _TIMEOUT_S,
    )
    writer.close()
    with contextlib.suppress(ssl.SSLError, ConnectionError):
        await writer.wait_closed()


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.*is deprecated:DeprecationWarning")
async def test_tls_below_1_2_is_rejected(tls_server: RunningServer, tmp_path: Path) -> None:
    legacy = _legacy_client_context()

    # Control: the same client must manage a handshake with a server that allows TLS 1.0/1.1,
    # otherwise a failure against Carchive would only show this OpenSSL's own limits.
    control_files = make_files(tmp_path, name="control")
    control_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    control_context.load_cert_chain(control_files.certfile, control_files.keyfile)
    try:
        control_context.set_ciphers("ALL:@SECLEVEL=0")
        control_context.minimum_version = ssl.TLSVersion.TLSv1
    except (ssl.SSLError, ValueError) as exc:
        pytest.skip(f"local OpenSSL cannot serve TLS 1.0/1.1: {exc}")

    async def _noop(_r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.close()

    control = await asyncio.start_server(_noop, "127.0.0.1", 0, ssl=control_context)
    control_port = control.sockets[0].getsockname()[1]
    try:
        try:
            await _handshake(control_port, legacy)
        except (ssl.SSLError, ConnectionError, OSError) as exc:
            pytest.skip(f"local OpenSSL cannot negotiate TLS 1.0/1.1 at all: {exc}")
    finally:
        control.close()
        await control.wait_closed()

    with pytest.raises((ssl.SSLError, ConnectionError)):
        await _handshake(tls_server.port, legacy)


# --- automatically generated certificate -------------------------------------------


async def _peer_fingerprint(port: int) -> str:
    """Return the SHA-256 fingerprint (upper-case hex with colons) of the served certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port, ssl=context), _TIMEOUT_S
    )
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
        with contextlib.suppress(ssl.SSLError, ConnectionError):
            await writer.wait_closed()
    return hashlib.sha256(der).digest().hex(":").upper()


_HOSTS = ("localhost", "127.0.0.1")


@pytest.fixture
async def selfsigned_server(
    tmp_path: Path, db: Database, accounts: AccountService
) -> AsyncGenerator[tuple[RunningServer, Settings, tls_selfsigned.SelfSignedCertificate]]:
    settings = Settings(data_dir=tmp_path / "ss-data", allowed_hosts=_HOSTS, tls_selfsigned=True)
    certificate = tls_selfsigned.ensure_selfsigned(
        settings.data_dir, settings.allowed_hosts, hostname="testbox"
    )
    files = TlsFiles(certificate.certfile, certificate.keyfile)
    app = create_app(build_services(db, FakeScheduler(), accounts), settings)
    async with _running(app, files) as running:
        yield running, settings, certificate


async def test_selfsigned_certificate_is_served_without_hsts(
    selfsigned_server: tuple[RunningServer, Settings, tls_selfsigned.SelfSignedCertificate],
) -> None:
    running, _settings, certificate = selfsigned_server

    async with httpx.AsyncClient(
        verify=_trusting_context(running.files), timeout=_TIMEOUT_S
    ) as client:
        response = await client.get(f"https://localhost:{running.port}/healthz")

    assert response.status_code == 200
    assert "strict-transport-security" not in response.headers
    assert "content-security-policy" in response.headers
    assert "Secure" in response.headers["set-cookie"]
    assert await _peer_fingerprint(running.port) == certificate.info.fingerprint


async def test_selfsigned_certificate_is_replaced_for_new_handshakes_without_restart(
    selfsigned_server: tuple[RunningServer, Settings, tls_selfsigned.SelfSignedCertificate],
) -> None:
    running, settings, certificate = selfsigned_server
    before = await _peer_fingerprint(running.port)
    renewed = asyncio.Event()
    calls = 0

    async def sleep(_seconds: float) -> None:
        nonlocal calls
        calls += 1
        if calls > 1:
            renewed.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(
        tls_selfsigned.run_renewal(
            running.context,
            settings.data_dir,
            (*settings.allowed_hosts, "added.lan.test"),
            loaded_fingerprint=certificate.info.fingerprint,
            hostname="testbox",
            sleep=sleep,
        )
    )
    try:
        async with asyncio.timeout(_TIMEOUT_S):
            await renewed.wait()
        after = await _peer_fingerprint(running.port)
    finally:
        task.cancel()
        async with asyncio.timeout(_TIMEOUT_S):
            await asyncio.wait({task})

    assert before == certificate.info.fingerprint
    assert after != before
    on_disk = tls_selfsigned.assess_selfsigned(
        settings.data_dir, (*settings.allowed_hosts, "added.lan.test"), hostname="testbox"
    )
    assert on_disk.info is not None
    assert after == on_disk.info.fingerprint
