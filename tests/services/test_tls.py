"""Tests for `carchive.services.tls`."""

from __future__ import annotations

import os
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from carchive.services.tls import enforce_minimum_tls_version, inspect_tls, name_matches
from tests.services.tls_fixtures import make_files, new_key, write_key

LOOPBACK = ("localhost", "127.0.0.1", "[::1]")


def test_valid_certificate_is_reported_ok(tmp_path: Path) -> None:
    files = make_files(tmp_path, dns_names=("host.example.org", "LOCALHOST"))

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert report.errors == []
    assert report.warnings == []
    assert report.expiry_note is None
    assert not report.expired
    assert report.names == ("host.example.org", "localhost", "127.0.0.1")
    assert report.days_left is not None
    assert 87 <= report.days_left <= 90


def test_cn_is_used_when_there_is_no_san(tmp_path: Path) -> None:
    files = make_files(tmp_path, with_san=False, common_name="Legacy.Example.org")

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert report.names == ("legacy.example.org",)


def test_missing_files_are_errors(tmp_path: Path) -> None:
    report = inspect_tls(tmp_path / "no.pem", tmp_path / "no.key", LOOPBACK)

    assert len(report.errors) == 2
    assert all("does not exist" in error for error in report.errors)


def test_directory_instead_of_file_is_an_error(tmp_path: Path) -> None:
    files = make_files(tmp_path)
    directory = tmp_path / "dir"
    directory.mkdir()

    report = inspect_tls(directory, files.keyfile, LOOPBACK)

    assert report.errors == [f"certificate file {directory} is not a regular file"]


def test_unreadable_file_is_an_error(tmp_path: Path) -> None:
    files = make_files(tmp_path)
    files.certfile.chmod(0)
    try:
        if os.access(files.certfile, os.R_OK):
            pytest.skip("running with privileges that ignore file permissions")
        report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)
    finally:
        files.certfile.chmod(0o600)

    assert len(report.errors) == 1
    assert "not readable" in report.errors[0]


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_key_accessible_by_others_is_an_error(tmp_path: Path, mode: int) -> None:
    files = make_files(tmp_path, key_mode=mode)

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert len(report.errors) == 1
    assert "chmod 600" in report.errors[0]


def test_wrong_key_pair_is_an_error_without_file_contents(tmp_path: Path) -> None:
    files = make_files(tmp_path)
    write_key(files.keyfile, new_key())

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert len(report.errors) == 1
    assert "could not be loaded together" in report.errors[0]
    assert "BEGIN" not in report.errors[0]


def test_broken_certificate_pem_is_an_error(tmp_path: Path) -> None:
    files = make_files(tmp_path)
    files.certfile.write_text("-----BEGIN CERTIFICATE-----\nnot base64 at all\n")

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert len(report.errors) == 1
    assert "no valid PEM certificate" in report.errors[0]


def test_broken_key_pem_is_an_error(tmp_path: Path) -> None:
    files = make_files(tmp_path)
    files.keyfile.write_text("garbage")
    files.keyfile.chmod(0o600)

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert len(report.errors) == 1
    assert "could not be loaded together" in report.errors[0]


def test_oversized_file_is_an_error(tmp_path: Path) -> None:
    files = make_files(tmp_path)
    files.certfile.write_bytes(b"x" * 1_000_001)

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert any("unreasonably large" in error for error in report.errors)


def test_expired_certificate_is_flagged_but_not_an_error(tmp_path: Path) -> None:
    start = datetime.now(UTC) - timedelta(days=100)
    files = make_files(tmp_path, not_before=start, valid_for=timedelta(days=60))

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert report.errors == []
    assert report.expired
    assert report.days_left is None
    assert report.expiry_note is not None
    assert "expired 40 day(s) ago" in report.expiry_note


def test_soon_expiring_certificate_is_flagged(tmp_path: Path) -> None:
    files = make_files(tmp_path, valid_for=timedelta(days=10))

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert report.errors == []
    assert not report.expired
    assert report.expiry_note is not None
    assert "expires in" in report.expiry_note


def test_fourteen_days_left_is_not_flagged(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    files = make_files(tmp_path, not_before=now, valid_for=timedelta(days=14, hours=1))

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK, now=now)

    assert report.days_left == 14
    assert report.expiry_note is None


def test_certificate_not_yet_valid_warns(tmp_path: Path) -> None:
    start = datetime.now(UTC) + timedelta(days=2)
    files = make_files(tmp_path, not_before=start)

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert any("not valid yet" in warning for warning in report.warnings)


def test_allowed_host_missing_from_names_warns(tmp_path: Path) -> None:
    files = make_files(tmp_path, dns_names=("other.example.org",))

    report = inspect_tls(files.certfile, files.keyfile, (*LOOPBACK, "carchive.example.org"))

    assert report.errors == []
    assert any("allowed_hosts" in warning for warning in report.warnings)


def test_allowed_host_covered_by_wildcard_does_not_warn(tmp_path: Path) -> None:
    files = make_files(tmp_path, dns_names=("*.example.org",))

    report = inspect_tls(files.certfile, files.keyfile, (*LOOPBACK, "carchive.example.org"))

    assert report.warnings == []


def test_only_loopback_allowed_hosts_never_warn(tmp_path: Path) -> None:
    files = make_files(tmp_path, dns_names=("other.example.org",))

    report = inspect_tls(files.certfile, files.keyfile, LOOPBACK)

    assert report.warnings == []


@pytest.mark.parametrize(
    ("pattern", "host", "expected"),
    [
        ("a.example.org", "a.example.org", True),
        ("A.Example.org.", "a.example.org", True),
        ("*.example.org", "a.example.org", True),
        ("*.example.org", "example.org", False),
        ("*.example.org", "a.b.example.org", False),
        ("*.example.org", ".example.org", False),
        ("*.org", "example.org", False),
        ("a*.example.org", "ab.example.org", False),
        ("*.example.org", "evil-example.org", False),
        ("*.0.0.1", "127.0.0.1", False),
        ("127.0.0.1", "127.0.0.1", True),
        ("::1", "[::1]", True),
    ],
)
def test_name_matches(pattern: str, host: str, expected: bool) -> None:
    assert name_matches(pattern, host) is expected


def test_enforce_minimum_tls_version_raises_a_lower_floor() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

    enforce_minimum_tls_version(context)

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_enforce_minimum_tls_version_keeps_a_stricter_floor() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    enforce_minimum_tls_version(context)

    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
