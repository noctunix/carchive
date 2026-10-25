"""Synthetic certificates and keys generated at test time; nothing here is a real credential."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class TlsFiles:
    """Paths of a generated certificate and its key."""

    certfile: Path
    keyfile: Path


def new_key() -> ec.EllipticCurvePrivateKey:
    """Return a fresh P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def write_key(path: Path, key: ec.EllipticCurvePrivateKey, *, mode: int = 0o600) -> None:
    """Write `key` as unencrypted PEM with the given file mode."""
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(mode)


def make_files(
    directory: Path,
    *,
    dns_names: tuple[str, ...] = ("localhost",),
    ip_names: tuple[str, ...] = ("127.0.0.1",),
    common_name: str = "carchive-test",
    with_san: bool = True,
    valid_for: timedelta = timedelta(days=90),
    not_before: datetime | None = None,
    key_mode: int = 0o600,
    name: str = "server",
) -> TlsFiles:
    """Create a self-signed certificate and key in `directory`.

    Args:
        directory: existing directory to write `<name>.pem` and `<name>.key` into.
        dns_names: DNS names for the SAN extension.
        ip_names: IP addresses for the SAN extension.
        common_name: subject CN.
        with_san: whether to include a SAN extension at all.
        valid_for: validity period, counted from `not_before`.
        not_before: start of validity; defaults to one day ago.
        key_mode: file mode for the key.
        name: file name stem.

    Returns:
        The written paths.
    """
    key = new_key()
    start = not_before or (datetime.now(UTC) - timedelta(days=1))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + valid_for)
    )
    if with_san:
        general_names: list[x509.GeneralName] = [x509.DNSName(n) for n in dns_names]
        general_names.extend(x509.IPAddress(ipaddress.ip_address(a)) for a in ip_names)
        builder = builder.add_extension(x509.SubjectAlternativeName(general_names), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    certfile = directory / f"{name}.pem"
    keyfile = directory / f"{name}.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    write_key(keyfile, key, mode=key_mode)
    return TlsFiles(certfile, keyfile)
