"""Container-mode TLS defaults, the plain-HTTP opt-out and the `healthcheck` subcommand."""

from __future__ import annotations

import os
import ssl
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import carchive.cli as cli_module
from carchive.cli import main
from carchive.config import load_settings
from carchive.logging_setup import configure_logging
from tests.services.tls_fixtures import make_files


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    for name in ("CARCHIVE_CONFIG", "CARCHIVE_TLS_CERTFILE", "CARCHIVE_TLS_KEYFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("CARCHIVE_DATA_DIR", str(tmp_path / "data-dir"))
    configure_logging(verbose=False, fmt="json")
    original = os.umask(0)
    os.umask(original)
    yield
    os.umask(original)


class _StopError(Exception):
    pass


def _stop_before_serving(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fail(*_args: object, **_kwargs: object) -> None:
        raise _StopError

    monkeypatch.setattr(cli_module, "_serve", _fail)


def _container_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARCHIVE_CONTAINER", "1")
    monkeypatch.setenv("CARCHIVE_BIND_HOST", "0.0.0.0")


def test_container_serves_tls_by_default(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _container_env(monkeypatch)
    _stop_before_serving(monkeypatch)

    with caplog.at_level("INFO", logger="carchive.cli"), pytest.raises(_StopError):
        cli_module._run_serve()

    messages = [record.getMessage() for record in caplog.records]
    assert any("cli.serve_starting" in m and "https://" in m for m in messages)
    assert not any("tls.container_plaintext" in m for m in messages)


def test_container_opt_out_serves_plain_http_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _container_env(monkeypatch)
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "false")
    _stop_before_serving(monkeypatch)

    with caplog.at_level("INFO", logger="carchive.cli"), pytest.raises(_StopError):
        cli_module._run_serve()

    warnings = [r for r in caplog.records if "tls.container_plaintext" in r.getMessage()]
    assert len(warnings) == 1
    assert warnings[0].levelname == "WARNING"
    assert any(
        "cli.serve_starting" in r.getMessage() and "http://" in r.getMessage()
        for r in caplog.records
    )


def test_container_with_own_certificate_files_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    files = make_files(tmp_path)
    _container_env(monkeypatch)
    monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", str(files.certfile))
    monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", str(files.keyfile))
    _stop_before_serving(monkeypatch)

    with caplog.at_level("INFO", logger="carchive.cli"), pytest.raises(_StopError):
        cli_module._run_serve()

    messages = [record.getMessage() for record in caplog.records]
    assert not any("tls.container_plaintext" in m for m in messages)
    settings = load_settings()
    assert settings.tls_enabled
    assert not settings.tls_selfsigned_active


def test_check_reports_plain_http_container_as_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _container_env(monkeypatch)
    monkeypatch.setenv("CARCHIVE_TLS_SELFSIGNED", "false")

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert any(
        line.startswith("tls: warning: container serves plain HTTP") for line in out.splitlines()
    )


def test_check_container_default_reports_selfsigned_certificate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _container_env(monkeypatch)

    exit_code = main(["check"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert any(line.startswith("tls: ok (self-signed (automatic)") for line in out.splitlines())


# --- healthcheck ----------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self) -> None:
        self.send_response(type(self).status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


def _serve_in_thread(
    status: int, certfiles: tuple[Path, Path] | None = None
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    handler = type("_H", (_Handler,), {"status": status})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if certfiles is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfiles[0], certfiles[1])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_healthcheck_succeeds_over_plain_http(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    server, thread = _serve_in_thread(200)
    try:
        monkeypatch.setenv("CARCHIVE_PORT", str(server.server_address[1]))
        exit_code = main(["healthcheck"])
    finally:
        _stop(server, thread)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""


def test_healthcheck_uses_https_without_verifying_the_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = make_files(tmp_path, common_name="unrelated.example.org")
    server, thread = _serve_in_thread(200, (files.certfile, files.keyfile))
    try:
        monkeypatch.setenv("CARCHIVE_PORT", str(server.server_address[1]))
        monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", str(files.certfile))
        monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", str(files.keyfile))
        exit_code = main(["healthcheck"])
    finally:
        _stop(server, thread)

    assert exit_code == 0


def test_healthcheck_fails_when_tls_is_expected_but_server_speaks_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = make_files(tmp_path)
    server, thread = _serve_in_thread(200)
    try:
        monkeypatch.setenv("CARCHIVE_PORT", str(server.server_address[1]))
        monkeypatch.setenv("CARCHIVE_TLS_CERTFILE", str(files.certfile))
        monkeypatch.setenv("CARCHIVE_TLS_KEYFILE", str(files.keyfile))
        exit_code = main(["healthcheck"])
    finally:
        _stop(server, thread)

    assert exit_code == 1


def test_healthcheck_fails_on_unhealthy_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    server, thread = _serve_in_thread(503)
    try:
        monkeypatch.setenv("CARCHIVE_PORT", str(server.server_address[1]))
        exit_code = main(["healthcheck"])
    finally:
        _stop(server, thread)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == "" and captured.err == ""


def test_healthcheck_fails_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    server, thread = _serve_in_thread(200)
    port = server.server_address[1]
    _stop(server, thread)
    monkeypatch.setenv("CARCHIVE_PORT", str(port))

    assert main(["healthcheck"]) == 1


def test_healthcheck_fails_on_invalid_settings_without_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CARCHIVE_PORT", "not-a-port")

    assert main(["healthcheck"]) == 1
    assert capsys.readouterr().out == ""
