"""Tests for `carchive.services.tls_selfsigned`; keys and certificates are generated per test."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from structlog.testing import capture_logs

from carchive.services import tls_selfsigned
from carchive.services.tls_selfsigned import (
    ReplacementReason,
    SelfSignedError,
    assess_selfsigned,
    ensure_selfsigned,
    required_names,
    run_renewal,
)
from tests.services.tls_fixtures import new_key, write_key

HOSTS = ("localhost", "127.0.0.1", "[::1]", "carchive.lan.test")
MACHINE = "buildbox"
NOW = datetime(2030, 1, 15, 12, 0, tzinfo=UTC)
PEM_FINGERPRINT = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")


def _ensure(
    data_dir: Path,
    hosts: tuple[str, ...] = HOSTS,
    *,
    now: datetime = NOW,
) -> tls_selfsigned.SelfSignedCertificate:
    return ensure_selfsigned(data_dir, hosts, hostname=MACHINE, clock=lambda: now)


def _certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_generated_certificate_has_the_required_content(tmp_path: Path) -> None:
    result = _ensure(tmp_path)

    cert = _certificate(result.certfile)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.DNSName)) == {
        "localhost",
        "carchive.lan.test",
        MACHINE,
    }
    assert set(san.get_values_for_type(x509.IPAddress)) == {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    }
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "carchive.lan.test"
    assert cert.issuer == cert.subject
    assert cert.not_valid_after_utc - NOW == timedelta(days=1095)
    assert NOW - cert.not_valid_before_utc == timedelta(days=1)
    key = cert.public_key()
    assert isinstance(key, ec.EllipticCurvePublicKey)
    assert key.curve.name == "secp256r1"
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.value.ca is False
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature
    assert not (usage.key_cert_sign or usage.key_encipherment or usage.crl_sign)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert result.replaced is ReplacementReason.MISSING


def test_common_name_falls_back_to_the_machine_name_without_a_remote_host(
    tmp_path: Path,
) -> None:
    result = _ensure(tmp_path, ("localhost", "127.0.0.1"))

    cert = _certificate(result.certfile)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == MACHINE


def test_info_reports_fingerprint_names_and_remaining_days(tmp_path: Path) -> None:
    result = _ensure(tmp_path)

    assert PEM_FINGERPRINT.match(result.info.fingerprint)
    assert result.info.names == tuple(
        sorted({"127.0.0.1", "::1", "localhost", "carchive.lan.test", MACHINE})
    )
    assert result.info.days_left == 1095


def test_files_are_owner_only_and_no_temp_files_remain(tmp_path: Path) -> None:
    result = _ensure(tmp_path)

    directory = tmp_path / "tls"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert result.keyfile.stat().st_mode & 0o777 == 0o600
    assert result.certfile.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in directory.iterdir()) == ["selfsigned.key", "selfsigned.pem"]


def test_generated_pair_loads_into_a_server_context(tmp_path: Path) -> None:
    result = _ensure(tmp_path)

    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(result.certfile, result.keyfile)


def test_no_key_material_is_logged(tmp_path: Path) -> None:
    with capture_logs() as logs:
        result = _ensure(tmp_path)

    body = result.keyfile.read_text().splitlines()[1]
    assert body not in str(logs)
    assert "PRIVATE KEY" not in str(logs)


def test_second_run_reuses_the_certificate(tmp_path: Path) -> None:
    first = _ensure(tmp_path)
    cert_bytes = first.certfile.read_bytes()
    key_bytes = first.keyfile.read_bytes()

    second = _ensure(tmp_path, now=NOW + timedelta(days=30))

    assert second.replaced is None
    assert second.info.fingerprint == first.info.fingerprint
    assert second.certfile.read_bytes() == cert_bytes
    assert second.keyfile.read_bytes() == key_bytes


def test_host_order_and_case_do_not_trigger_a_new_certificate(tmp_path: Path) -> None:
    first = _ensure(tmp_path)

    second = _ensure(tmp_path, ("CARCHIVE.lan.test.", "[::1]", "127.0.0.1", "localhost"))

    assert second.replaced is None
    assert second.info.fingerprint == first.info.fingerprint


def test_changed_allowed_hosts_replace_the_certificate(tmp_path: Path) -> None:
    first = _ensure(tmp_path)

    second = _ensure(tmp_path, (*HOSTS, "other.lan.test"))

    assert second.replaced is ReplacementReason.NAMES_CHANGED
    assert second.info.fingerprint != first.info.fingerprint
    assert "other.lan.test" in second.info.names


def test_removed_allowed_host_replaces_the_certificate(tmp_path: Path) -> None:
    _ensure(tmp_path)

    second = _ensure(tmp_path, ("localhost", "127.0.0.1", "[::1]"))

    assert second.replaced is ReplacementReason.NAMES_CHANGED


def test_renewal_threshold_is_thirty_days(tmp_path: Path) -> None:
    first = _ensure(tmp_path)

    still_fine = _ensure(tmp_path, now=NOW + timedelta(days=1095 - 31))
    assert still_fine.replaced is None
    assert still_fine.info.fingerprint == first.info.fingerprint

    late = NOW + timedelta(days=1095 - 29)
    renewed = _ensure(tmp_path, now=late)
    assert renewed.replaced is ReplacementReason.EXPIRING
    assert renewed.info.fingerprint != first.info.fingerprint
    assert renewed.info.days_left == 1095


def test_expired_certificate_is_replaced(tmp_path: Path) -> None:
    _ensure(tmp_path)

    renewed = _ensure(tmp_path, now=NOW + timedelta(days=2000))

    assert renewed.replaced is ReplacementReason.EXPIRING


def test_key_that_does_not_match_the_certificate_is_replaced(tmp_path: Path) -> None:
    first = _ensure(tmp_path)
    write_key(first.keyfile, new_key())

    second = _ensure(tmp_path)

    assert second.replaced is ReplacementReason.KEY_MISMATCH
    assert second.info.fingerprint != first.info.fingerprint
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(second.certfile, second.keyfile)


@pytest.mark.parametrize("victim", ["selfsigned.pem", "selfsigned.key"])
@pytest.mark.parametrize("damage", ["garbage", "empty", "oversized"])
def test_damaged_files_are_replaced(tmp_path: Path, victim: str, damage: str) -> None:
    first = _ensure(tmp_path)
    content = {"garbage": b"not a pem", "empty": b"", "oversized": b"A" * 70_000}[damage]
    (tmp_path / "tls" / victim).write_bytes(content)

    second = _ensure(tmp_path)

    assert second.replaced is ReplacementReason.UNUSABLE
    assert second.info.fingerprint != first.info.fingerprint
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(second.certfile, second.keyfile)


def test_only_one_missing_file_is_replaced_as_a_pair(tmp_path: Path) -> None:
    first = _ensure(tmp_path)
    first.keyfile.unlink()

    second = _ensure(tmp_path)

    assert second.replaced is ReplacementReason.UNUSABLE
    assert second.keyfile.exists()


def test_key_accessible_by_others_is_not_trusted(tmp_path: Path) -> None:
    first = _ensure(tmp_path)
    first.keyfile.chmod(0o640)

    second = _ensure(tmp_path)

    assert second.replaced is ReplacementReason.UNUSABLE
    assert second.keyfile.stat().st_mode & 0o777 == 0o600


def test_non_p256_key_is_replaced(tmp_path: Path) -> None:
    first = _ensure(tmp_path)
    other = ec.generate_private_key(ec.SECP384R1())
    write_key(first.keyfile, other)

    second = _ensure(tmp_path)

    assert second.replaced is ReplacementReason.UNUSABLE


def test_symlinked_key_is_not_followed(tmp_path: Path) -> None:
    first = _ensure(tmp_path)
    target = tmp_path / "elsewhere.key"
    target.write_bytes(first.keyfile.read_bytes())
    target.chmod(0o600)
    first.keyfile.unlink()
    first.keyfile.symlink_to(target)

    second = _ensure(tmp_path)

    assert second.replaced is ReplacementReason.UNUSABLE
    assert not second.keyfile.is_symlink()


def test_assess_does_not_write(tmp_path: Path) -> None:
    missing = assess_selfsigned(tmp_path, HOSTS, hostname=MACHINE, clock=lambda: NOW)

    assert missing.reason is ReplacementReason.MISSING
    assert missing.info is None
    assert not (tmp_path / "tls").exists()

    _ensure(tmp_path)
    changed = assess_selfsigned(tmp_path, ("example.test",), hostname=MACHINE, clock=lambda: NOW)
    assert changed.reason is ReplacementReason.NAMES_CHANGED
    assert changed.info is not None


def test_tls_path_that_is_a_file_is_a_clear_error(tmp_path: Path) -> None:
    (tmp_path / "tls").write_text("in the way")

    with pytest.raises(SelfSignedError, match="cannot store"):
        _ensure(tmp_path)


def test_tls_directory_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "tls").symlink_to(real)

    with pytest.raises(SelfSignedError, match="symbolic link"):
        _ensure(tmp_path)


def test_unwritable_parent_is_a_clear_error(tmp_path: Path) -> None:
    parent = tmp_path / "locked"
    parent.mkdir(mode=0o700)
    parent.chmod(0o500)
    try:
        if os.access(parent, os.W_OK):
            pytest.skip("running with privileges that ignore directory permissions")
        with pytest.raises(SelfSignedError, match="cannot store"):
            _ensure(parent / "data")
    finally:
        parent.chmod(0o700)


def test_required_names_normalises_and_deduplicates() -> None:
    names = required_names(
        ["Example.ORG.", "[::1]", "::1", "10.0.0.5", "*.lan.test", "*"], hostname="Box"
    )

    assert names == (
        ("dns", "example.org"),
        ("ip", "::1"),
        ("ip", "10.0.0.5"),
        ("dns", "*.lan.test"),
        ("dns", "box"),
        ("dns", "localhost"),
    )


@pytest.mark.parametrize("entry", ["bad host", "exa mple.org", "host:8470", "-lead.example", ""])
def test_unrepresentable_allowed_host_is_refused(entry: str) -> None:
    with pytest.raises(SelfSignedError, match="allowed_hosts entry"):
        required_names([entry], hostname=MACHINE)


@pytest.mark.parametrize("hostname", ["", "not a name", "ünicode"])
def test_unusable_machine_name_is_ignored(hostname: str) -> None:
    assert required_names(["example.org"], hostname=hostname) == (
        ("dns", "example.org"),
        ("dns", "localhost"),
    )


def test_machine_name_defaults_to_the_system_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: "Sysbox")

    assert ("dns", "sysbox") in required_names(["example.org"])


# --- run_renewal ------------------------------------------------------------------


class _Ticks:
    """A `sleep` replacement: returns immediately `count` times, then blocks until cancelled."""

    def __init__(self, count: int) -> None:
        self._remaining = count
        self.exhausted = asyncio.Event()
        self.intervals: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.intervals.append(seconds)
        if self._remaining == 0:
            self.exhausted.set()
            await asyncio.Event().wait()
        self._remaining -= 1


async def _stop(task: asyncio.Task[None]) -> None:
    task.cancel()
    async with asyncio.timeout(10):
        await asyncio.wait({task})


async def test_renewal_loads_a_new_certificate_into_the_context(tmp_path: Path) -> None:
    first = _ensure(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(first.certfile, first.keyfile)
    ticks = _Ticks(1)

    task = asyncio.create_task(
        run_renewal(
            context,
            tmp_path,
            (*HOSTS, "new.lan.test"),
            loaded_fingerprint=first.info.fingerprint,
            hostname=MACHINE,
            clock=lambda: NOW,
            sleep=ticks,
        )
    )
    async with asyncio.timeout(10):
        await ticks.exhausted.wait()
    await _stop(task)

    assert ticks.intervals[0] == tls_selfsigned.RENEWAL_CHECK_INTERVAL_S == 43_200
    current = assess_selfsigned(
        tmp_path, (*HOSTS, "new.lan.test"), hostname=MACHINE, clock=lambda: NOW
    )
    assert current.reason is None
    assert current.info is not None
    assert current.info.fingerprint != first.info.fingerprint


async def test_renewal_without_change_leaves_the_context_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _ensure(tmp_path)
    loads: list[object] = []
    monkeypatch.setattr(tls_selfsigned, "load_into_context", lambda *a: loads.append(a))
    ticks = _Ticks(3)

    task = asyncio.create_task(
        run_renewal(
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
            tmp_path,
            HOSTS,
            loaded_fingerprint=first.info.fingerprint,
            hostname=MACHINE,
            clock=lambda: NOW,
            sleep=ticks,
        )
    )
    async with asyncio.timeout(10):
        await ticks.exhausted.wait()
    await _stop(task)

    assert loads == []


async def test_renewal_survives_errors_and_keeps_trying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _ensure(tmp_path)
    real = tls_selfsigned.ensure_selfsigned
    calls = 0

    def flaky(*args: object, **kwargs: object) -> tls_selfsigned.SelfSignedCertificate:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise SelfSignedError("disk on fire")
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(tls_selfsigned, "ensure_selfsigned", flaky)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(first.certfile, first.keyfile)
    ticks = _Ticks(2)

    task = asyncio.create_task(
        run_renewal(
            context,
            tmp_path,
            (*HOSTS, "later.lan.test"),
            loaded_fingerprint=first.info.fingerprint,
            hostname=MACHINE,
            clock=lambda: NOW,
            sleep=ticks,
        )
    )
    with capture_logs() as logs:
        async with asyncio.timeout(10):
            await ticks.exhausted.wait()
        assert not task.done()
        await _stop(task)

    assert calls == 2
    failures = [entry for entry in logs if entry["event"] == "tls.selfsigned_renewal_failed"]
    assert len(failures) == 1
    assert "disk on fire" in failures[0]["error"]
    assert "later.lan.test" in _certificate(first.certfile).extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)


async def test_renewal_load_failure_is_logged_and_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _ensure(tmp_path)

    def broken_load(*_args: object) -> None:
        raise ssl.SSLError("pair rejected")

    monkeypatch.setattr(tls_selfsigned, "load_into_context", broken_load)
    ticks = _Ticks(1)

    task = asyncio.create_task(
        run_renewal(
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
            tmp_path,
            (*HOSTS, "x.lan.test"),
            loaded_fingerprint=first.info.fingerprint,
            hostname=MACHINE,
            clock=lambda: NOW,
            sleep=ticks,
        )
    )
    with capture_logs() as logs:
        async with asyncio.timeout(10):
            await ticks.exhausted.wait()
        assert not task.done()
        await _stop(task)

    assert [e["event"] for e in logs] == ["tls.selfsigned_renewal_failed"]


def test_load_into_context_rejects_a_mismatched_pair_before_touching_the_context(
    tmp_path: Path,
) -> None:
    good = _ensure(tmp_path / "a")
    bad = _ensure(tmp_path / "b")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(good.certfile, good.keyfile)
    mismatched = tls_selfsigned.SelfSignedCertificate(
        bad.certfile, good.keyfile, bad.info, ReplacementReason.MISSING
    )

    with pytest.raises(ssl.SSLError):
        tls_selfsigned.load_into_context(context, mismatched)
