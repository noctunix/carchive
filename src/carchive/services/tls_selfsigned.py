"""Automatically generated, self-signed server certificate with in-process renewal.

For a LAN deployment without a domain or CA of its own: Carchive creates an ECDSA P-256 key
and a three-year self-signed certificate under `<data_dir>/tls/`, reuses them across restarts
and replaces them before they expire or when the configured host names change. A running
server picks up the new certificate for new handshakes via `run_renewal`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import ssl
import stat
import tempfile
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import structlog
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from carchive.core.redact import redact

logger = structlog.get_logger(__name__)

VALIDITY_DAYS = 1095
RENEW_BEFORE_DAYS = 30
RENEWAL_CHECK_INTERVAL_S = 12 * 60 * 60
TLS_SUBDIR = "tls"
CERT_FILENAME = "selfsigned.pem"
KEY_FILENAME = "selfsigned.key"

# Tolerates a server clock that runs slightly behind the clients'.
_BACKDATE = timedelta(days=1)
_MAX_PEM_BYTES = 64 * 1024
_MAX_CN_LENGTH = 64
_DNS_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_DNS_NAME = re.compile(rf"^(?:\*\.)?{_DNS_LABEL}(?:\.{_DNS_LABEL})*$")

Clock = Callable[[], datetime]
Sleep = Callable[[float], Awaitable[None]]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SelfSignedError(RuntimeError):
    """The self-signed certificate cannot be generated or stored."""


class ReplacementReason(StrEnum):
    """Why an existing certificate is not reused."""

    MISSING = "missing"
    UNUSABLE = "unusable"
    KEY_MISMATCH = "key_mismatch"
    NAMES_CHANGED = "names_changed"
    EXPIRING = "expiring"


@dataclass(frozen=True)
class CertificateInfo:
    """Public facts about the certificate on disk, safe to print.

    Attributes:
        fingerprint: SHA-256 of the DER certificate as upper-case hex with colons, the form
            browsers show in their certificate dialog.
        names: DNS names and IP addresses in the SAN extension, sorted.
        not_after: end of validity (UTC).
        days_left: whole days until `not_after`, 0 if already past.
    """

    fingerprint: str
    names: tuple[str, ...]
    not_after: datetime
    days_left: int


@dataclass(frozen=True)
class Assessment:
    """Result of `assess_selfsigned`.

    Attributes:
        reason: why the certificate must be replaced, `None` if it can be reused as is.
        info: the certificate currently on disk, `None` if there is none that could be parsed.
    """

    reason: ReplacementReason | None
    info: CertificateInfo | None


@dataclass(frozen=True)
class SelfSignedCertificate:
    """The certificate `ensure_selfsigned` settled on.

    Attributes:
        certfile: PEM certificate path.
        keyfile: PEM private key path (owner-only).
        info: the certificate's public facts.
        replaced: why a new certificate was generated, `None` if the existing one was reused.
    """

    certfile: Path
    keyfile: Path
    info: CertificateInfo
    replaced: ReplacementReason | None


def tls_directory(data_dir: Path) -> Path:
    """Return the directory holding the generated certificate and key."""
    return data_dir / TLS_SUBDIR


def _normalise_entry(entry: str) -> str:
    return entry.strip().strip("[]").rstrip(".").lower()


def _is_loopback_name(name: str) -> bool:
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _classify(name: str) -> tuple[str, str] | None:
    """Return `("ip", canonical)` or `("dns", name)`, or `None` if `name` is neither."""
    try:
        return "ip", str(ipaddress.ip_address(name))
    except ValueError:
        pass
    if len(name) <= 253 and _DNS_NAME.fullmatch(name):
        return "dns", name
    return None


def required_names(
    allowed_hosts: Iterable[str], hostname: str | None = None
) -> tuple[tuple[str, str], ...]:
    """Return the SAN entries the certificate must carry, in a stable order.

    Args:
        allowed_hosts: the configured host allowlist (DNS names, wildcards, IPs, `[::1]`).
            A bare `*` cannot be expressed in a certificate and is skipped.
        hostname: this machine's name; defaults to `socket.gethostname()`. Ignored if it is
            not a valid DNS name.

    Returns:
        Unique `(kind, value)` pairs, `kind` being `"dns"` or `"ip"`; configured entries
        first, then the machine name, then `localhost`.

    Raises:
        SelfSignedError: if an `allowed_hosts` entry is neither a valid DNS name nor an IP.
    """
    result: dict[tuple[str, str], None] = {}
    for entry in allowed_hosts:
        name = _normalise_entry(entry)
        if name == "*":
            continue
        classified = _classify(name)
        if classified is None:
            raise SelfSignedError(
                f"allowed_hosts entry {entry!r} cannot be put into a certificate: "
                "it is neither a valid host name nor an IP address"
            )
        result[classified] = None
    machine = _normalise_entry(hostname if hostname is not None else socket.gethostname())
    if machine and (classified := _classify(machine)) is not None and classified[0] == "dns":
        result[classified] = None
    result[("dns", "localhost")] = None
    return tuple(result)


def _common_name(names: tuple[tuple[str, str], ...]) -> str:
    for kind, value in names:
        if kind == "dns" and not _is_loopback_name(value) and len(value) <= _MAX_CN_LENGTH:
            return value
    return "localhost"


def _san_set(cert: x509.Certificate) -> set[tuple[str, str]] | None:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    found = {("dns", name.lower()) for name in san.get_values_for_type(x509.DNSName)}
    found.update(("ip", str(address)) for address in san.get_values_for_type(x509.IPAddress))
    return found


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def _info(cert: x509.Certificate, now: datetime) -> CertificateInfo:
    names = _san_set(cert) or set()
    remaining = cert.not_valid_after_utc - now
    return CertificateInfo(
        fingerprint=_fingerprint(cert),
        names=tuple(sorted(value for _kind, value in names)),
        not_after=cert.not_valid_after_utc,
        days_left=max(remaining.days, 0),
    )


def _read_pem(path: Path, *, owner_only: bool) -> bytes | None:
    """Read a small regular file, `None` if it is absent, not plain or (if asked) too open."""
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PEM_BYTES:
            return None
        if owner_only and info.st_mode & 0o077:
            return None
        return path.read_bytes()
    except OSError:
        return None


def _load_pair(
    certfile: Path, keyfile: Path
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None:
    cert_pem = _read_pem(certfile, owner_only=False)
    key_pem = _read_pem(keyfile, owner_only=True)
    if cert_pem is None or key_pem is None:
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        return None
    return cert, key


def _public_key_der(key: PublicKeyTypes) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def assess_selfsigned(
    data_dir: Path,
    allowed_hosts: Iterable[str],
    *,
    hostname: str | None = None,
    clock: Clock = _utc_now,
) -> Assessment:
    """Decide whether the stored certificate can be reused, without writing anything.

    Args:
        data_dir: the data directory; the files live in its `tls/` subdirectory.
        allowed_hosts: the configured host allowlist.
        hostname: this machine's name; defaults to `socket.gethostname()`.
        clock: returns the current UTC time.

    Returns:
        The replacement reason (`None` to reuse) and what is currently on disk.

    Raises:
        SelfSignedError: if an `allowed_hosts` entry cannot be put into a certificate.
    """
    wanted = set(required_names(allowed_hosts, hostname))
    directory = tls_directory(data_dir)
    certfile, keyfile = directory / CERT_FILENAME, directory / KEY_FILENAME
    now = clock()

    if not certfile.exists() and not keyfile.exists():
        return Assessment(ReplacementReason.MISSING, None)
    pair = _load_pair(certfile, keyfile)
    if pair is None:
        return Assessment(ReplacementReason.UNUSABLE, None)
    cert, key = pair
    info = _info(cert, now)
    if _public_key_der(cert.public_key()) != _public_key_der(key.public_key()):
        return Assessment(ReplacementReason.KEY_MISMATCH, info)
    if _san_set(cert) != wanted:
        return Assessment(ReplacementReason.NAMES_CHANGED, info)
    if cert.not_valid_after_utc - now < timedelta(days=RENEW_BEFORE_DAYS):
        return Assessment(ReplacementReason.EXPIRING, info)
    return Assessment(None, info)


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomically(path: Path, data: bytes) -> None:
    """Write `data` to `path` as an owner-only file via temp file, fsync and rename."""
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".tmp-{path.name}-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _generate(
    directory: Path, names: tuple[tuple[str, str], ...], now: datetime
) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _common_name(names))])
    general_names: list[x509.GeneralName] = [
        x509.DNSName(value) if kind == "dns" else x509.IPAddress(ipaddress.ip_address(value))
        for kind, value in names
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(general_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    # A crash between the two renames leaves a mismatched pair, which the next run replaces.
    _write_atomically(
        directory / KEY_FILENAME,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_atomically(directory / CERT_FILENAME, cert.public_bytes(serialization.Encoding.PEM))
    _fsync_directory(directory)
    return cert


def ensure_selfsigned(
    data_dir: Path,
    allowed_hosts: Iterable[str],
    *,
    hostname: str | None = None,
    clock: Clock = _utc_now,
) -> SelfSignedCertificate:
    """Return a usable self-signed certificate, generating one if needed.

    An existing certificate is reused unchanged unless it is missing or unusable, its key
    does not match, its names differ from the required set or it expires within
    `RENEW_BEFORE_DAYS`. Running it again therefore never changes a healthy certificate.

    Args:
        data_dir: the data directory; the files live in its `tls/` subdirectory (mode 0700).
        allowed_hosts: the configured host allowlist; every entry becomes a SAN entry.
        hostname: this machine's name; defaults to `socket.gethostname()`.
        clock: returns the current UTC time.

    Returns:
        The certificate to serve and whether it was just generated.

    Raises:
        SelfSignedError: if an `allowed_hosts` entry cannot be put into a certificate or the
            files cannot be written.
    """
    assessment = assess_selfsigned(data_dir, allowed_hosts, hostname=hostname, clock=clock)
    directory = tls_directory(data_dir)
    certfile, keyfile = directory / CERT_FILENAME, directory / KEY_FILENAME
    if assessment.reason is None and assessment.info is not None:
        return SelfSignedCertificate(certfile, keyfile, assessment.info, None)

    names = required_names(allowed_hosts, hostname)
    now = clock()
    try:
        if directory.is_symlink():
            raise SelfSignedError(f"{directory} must be a real directory, not a symbolic link")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        cert = _generate(directory, names, now)
    except OSError as exc:
        reason = exc.strerror or "OS error"
        raise SelfSignedError(
            f"cannot store the self-signed certificate in {directory} ({reason})"
        ) from exc
    replaced = assessment.reason or ReplacementReason.MISSING
    return SelfSignedCertificate(certfile, keyfile, _info(cert, now), replaced)


def load_into_context(context: ssl.SSLContext, certificate: SelfSignedCertificate) -> None:
    """Load `certificate` into a live server context without leaving it half-updated.

    The pair is first loaded into a throwaway context, because a failure halfway through
    `load_cert_chain` could leave the live context with the new certificate and the old key.

    Args:
        context: the context uvicorn serves with; new handshakes use the new certificate.
        certificate: the certificate and key to load.

    Raises:
        ssl.SSLError: if the pair cannot be loaded.
        OSError: if a file cannot be read.
    """
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
        certificate.certfile, certificate.keyfile
    )
    context.load_cert_chain(certificate.certfile, certificate.keyfile)


async def run_renewal(
    context: ssl.SSLContext,
    data_dir: Path,
    allowed_hosts: tuple[str, ...],
    *,
    loaded_fingerprint: str,
    interval_s: float = RENEWAL_CHECK_INTERVAL_S,
    hostname: str | None = None,
    clock: Clock = _utc_now,
    sleep: Sleep = asyncio.sleep,
) -> None:
    """Re-check the certificate every `interval_s` seconds and hot-load a replacement.

    The caller has already run `ensure_selfsigned` once and loaded the result. A failing
    check is logged and retried at the next interval, leaving the previously loaded
    certificate in service. Runs until cancelled.

    Args:
        context: the live server context to update.
        data_dir: the data directory holding `tls/`.
        allowed_hosts: the configured host allowlist.
        loaded_fingerprint: fingerprint of the certificate currently loaded in `context`.
        interval_s: seconds between checks.
        hostname: this machine's name; defaults to `socket.gethostname()`.
        clock: returns the current UTC time.
        sleep: the awaitable used to wait between checks.
    """
    loaded = loaded_fingerprint
    while True:
        await sleep(interval_s)
        try:
            certificate = await asyncio.to_thread(
                ensure_selfsigned, data_dir, allowed_hosts, hostname=hostname, clock=clock
            )
            if certificate.info.fingerprint != loaded:
                load_into_context(context, certificate)
                loaded = certificate.info.fingerprint
                logger.info(
                    "tls.selfsigned_renewed",
                    reason=str(certificate.replaced) if certificate.replaced else "external",
                    fingerprint=loaded,
                    days_left=certificate.info.days_left,
                )
        except Exception as exc:
            logger.error("tls.selfsigned_renewal_failed", error=redact(str(exc)))
