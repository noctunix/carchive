"""Offline checks of the configured TLS certificate and key, run before `serve` starts.

Validates the certificate and key files the operator provides and reports problems without
touching the network or echoing file contents. The automatically generated certificate lives
in `tls_selfsigned`.
"""

from __future__ import annotations

import ipaddress
import ssl
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

EXPIRY_WARNING_DAYS = 14
_MAX_PEM_BYTES = 1_000_000
_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class TlsReport:
    """Outcome of `inspect_tls`.

    Attributes:
        errors: problems that make the files unusable; `serve` must refuse to start.
        warnings: non-blocking findings (name mismatch, certificate not yet valid).
        expiry_note: set when the certificate is expired or expires within
            `EXPIRY_WARNING_DAYS`; never blocks startup.
        expired: whether the certificate's validity has ended.
        names: DNS names and IP addresses the certificate is valid for.
        days_left: whole days until expiry, `None` if the certificate could not be read
            or is already expired.
    """

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    expiry_note: str | None = None
    expired: bool = False
    names: tuple[str, ...] = ()
    days_left: int | None = None


def _read_regular_file(path: Path, label: str, errors: list[str]) -> bytes | None:
    """Read a bounded regular file, appending a problem to `errors` on failure."""
    try:
        info = path.stat()
    except FileNotFoundError:
        errors.append(f"{label} {path} does not exist")
        return None
    except OSError as exc:
        errors.append(f"{label} {path} is not accessible ({exc.strerror or 'OS error'})")
        return None
    if not stat.S_ISREG(info.st_mode):
        errors.append(f"{label} {path} is not a regular file")
        return None
    if info.st_size > _MAX_PEM_BYTES:
        errors.append(f"{label} {path} is unreasonably large")
        return None
    try:
        return path.read_bytes()
    except OSError as exc:
        errors.append(f"{label} {path} is not readable ({exc.strerror or 'OS error'})")
        return None


def _certificate_names(cert: x509.Certificate) -> tuple[str, ...]:
    """Return the SAN DNS/IP names, or the subject CN if the certificate has no SAN."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return tuple(
            str(attribute.value).lower()
            for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        )
    names = [name.lower() for name in san.get_values_for_type(x509.DNSName)]
    names.extend(str(address) for address in san.get_values_for_type(x509.IPAddress))
    return tuple(names)


def _normalise_host(host: str) -> str:
    return host.strip().strip("[]").rstrip(".").lower()


def name_matches(pattern: str, host: str) -> bool:
    """Return whether a certificate name covers `host`.

    A wildcard is honoured only as the whole left-most label and stands for exactly one
    label (`*.example.org` covers `a.example.org`, not `example.org` or `a.b.example.org`);
    it never applies to IP addresses and needs at least two labels after the wildcard.

    Args:
        pattern: a DNS name (possibly wildcarded) or IP address from the certificate.
        host: the host name or IP address to test.

    Returns:
        Whether `pattern` covers `host`.
    """
    pattern = _normalise_host(pattern)
    host = _normalise_host(host)
    if pattern == host:
        return True
    if not pattern.startswith("*."):
        return False
    remainder = pattern[2:]
    if "." not in remainder or "*" in remainder:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return False
    label, dot, rest = host.partition(".")
    return bool(label) and bool(dot) and rest == remainder


def _uncovered_hosts(names: Iterable[str], allowed_hosts: Iterable[str]) -> bool:
    """Return whether non-loopback hosts are allowed but none is covered by `names`."""
    names = tuple(names)
    remote = [h for h in allowed_hosts if _normalise_host(h) not in _LOOPBACK_NAMES]
    if not remote:
        return False
    return not any(name_matches(name, host) for host in remote for name in names)


def inspect_tls(
    certfile: Path,
    keyfile: Path,
    allowed_hosts: Iterable[str],
    *,
    now: datetime | None = None,
) -> TlsReport:
    """Check that the certificate and key can serve HTTPS and describe the certificate.

    Performs no network access. Messages never contain file contents.

    Args:
        certfile: PEM certificate (chain, leaf first).
        keyfile: PEM private key, which must not be accessible to group or others.
        allowed_hosts: the configured host allowlist, compared with the certificate names.
        now: the reference time (UTC); defaults to the current time.

    Returns:
        A `TlsReport`; empty `errors` means the files are usable.
    """
    errors: list[str] = []
    warnings: list[str] = []
    reference = now or datetime.now(UTC)

    cert_pem = _read_regular_file(certfile, "certificate file", errors)
    key_pem = _read_regular_file(keyfile, "key file", errors)
    if key_pem is not None:
        mode = keyfile.stat().st_mode
        if mode & 0o077:
            errors.append(
                f"key file {keyfile} is accessible by group or others; fix with: "
                f"chmod 600 {keyfile}"
            )
    if cert_pem is None or key_pem is None or errors:
        return TlsReport(errors=errors)

    try:
        certificates = x509.load_pem_x509_certificates(cert_pem)
    except ValueError:
        certificates = []
    if not certificates:
        return TlsReport(errors=[f"certificate file {certfile} contains no valid PEM certificate"])
    leaf = certificates[0]

    # The password callback keeps OpenSSL from prompting on the terminal for an encrypted key.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile, keyfile, password=lambda: b"")
    except (ssl.SSLError, OSError, ValueError):
        return TlsReport(
            errors=[
                "certificate and key could not be loaded together: the key is not a valid "
                "unencrypted PEM key or does not belong to the certificate"
            ]
        )

    names = _certificate_names(leaf)
    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc

    expiry_note: str | None = None
    days_left: int | None = None
    expired = reference >= not_after
    if expired:
        expiry_note = f"certificate expired {(reference - not_after).days} day(s) ago"
    else:
        days_left = (not_after - reference).days
        if days_left < EXPIRY_WARNING_DAYS:
            expiry_note = f"certificate expires in {days_left} day(s)"
    if reference < not_before:
        warnings.append("certificate is not valid yet (check the system clock)")
    if _uncovered_hosts(names, allowed_hosts):
        warnings.append("none of the allowed_hosts entries is covered by the certificate names")

    return TlsReport(
        errors=errors,
        warnings=warnings,
        expiry_note=expiry_note,
        expired=expired,
        names=names,
        days_left=days_left,
    )


def enforce_minimum_tls_version(context: ssl.SSLContext) -> ssl.SSLContext:
    """Make sure `context` never negotiates below TLS 1.2, keeping a stricter setting.

    Args:
        context: the server context to harden in place.

    Returns:
        `context`, for chaining.
    """
    if context.minimum_version < ssl.TLSVersion.TLSv1_2:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
