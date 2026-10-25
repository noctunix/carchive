"""Authenticated encryption of single secret strings (AES-256-GCM).

A sealed value reads `enc:v2:<base64url(nonce || ciphertext || tag)>`; the version in the
prefix leaves room for a later format change, and other versions are refused. Each value gets
a fresh random nonce, and the credential reference and field name it belongs to are bound as
associated data (length-prefixed, so the pair is unambiguous), so a value copied under
another reference or into another field fails to decrypt. Key storage is the caller's
business; this module does no I/O.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEALED_MARKER = "enc:"
SEALED_PREFIX = "enc:v2:"
KEY_LENGTH = 32
_NONCE_LENGTH = 12
_TAG_LENGTH = 16


class VaultError(ValueError):
    """Raised when a value cannot be sealed or unsealed. Messages never carry values."""


def generate_key() -> bytes:
    """Return a fresh random key.

    Returns:
        `KEY_LENGTH` random bytes.
    """
    return secrets.token_bytes(KEY_LENGTH)


def is_sealed(value: str) -> bool:
    """Return whether `value` carries the sealed-value marker, of any format version.

    Args:
        value: a stored string.

    Returns:
        `True` if `value` starts with `enc:`; `unseal` rejects versions other than the
        current one.
    """
    return value.startswith(SEALED_MARKER)


def _associated_data(ref: str, field: str) -> bytes:
    ref_bytes = ref.encode("utf-8")
    return struct.pack(">I", len(ref_bytes)) + ref_bytes + field.encode("utf-8")


def _aesgcm(key: bytes) -> AESGCM:
    if len(key) != KEY_LENGTH:
        raise VaultError(f"key must be exactly {KEY_LENGTH} bytes")
    return AESGCM(key)


def seal(key: bytes, ref: str, field: str, plaintext: str) -> str:
    """Encrypt `plaintext` for one field of the credential reference `ref`.

    Args:
        key: the `KEY_LENGTH`-byte key.
        ref: the credential reference; bound to the ciphertext as associated data.
        field: the field name within `ref`; bound to the ciphertext as associated data.
        plaintext: the value to protect.

    Returns:
        The sealed string, different on every call because of the random nonce.

    Raises:
        VaultError: if `key` has the wrong length.
    """
    nonce = os.urandom(_NONCE_LENGTH)
    ciphertext = _aesgcm(key).encrypt(
        nonce, plaintext.encode("utf-8"), _associated_data(ref, field)
    )
    encoded = base64.urlsafe_b64encode(nonce + ciphertext).rstrip(b"=").decode("ascii")
    return SEALED_PREFIX + encoded


def unseal(key: bytes, ref: str, field: str, token: str) -> str:
    """Decrypt a value produced by `seal`.

    Args:
        key: the `KEY_LENGTH`-byte key.
        ref: the credential reference the value must belong to.
        field: the field name the value must belong to.
        token: the sealed string.

    Returns:
        The original plaintext.

    Raises:
        VaultError: if `key` has the wrong length, `token` is malformed or of an
            unsupported format version, or authentication fails (wrong key, wrong `ref` or
            `field`, or tampered data).
    """
    aesgcm = _aesgcm(key)
    if not is_sealed(token):
        raise VaultError("value is not a sealed value")
    if not token.startswith(SEALED_PREFIX):
        raise VaultError(
            f"unsupported sealed-value format (expected {SEALED_PREFIX!r}); "
            "the password must be entered again"
        )
    body = token[len(SEALED_PREFIX) :]
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise VaultError("sealed value is not valid base64") from None
    if len(raw) < _NONCE_LENGTH + _TAG_LENGTH:
        raise VaultError("sealed value is too short")
    try:
        plaintext = aesgcm.decrypt(
            raw[:_NONCE_LENGTH], raw[_NONCE_LENGTH:], _associated_data(ref, field)
        )
    except InvalidTag:
        raise VaultError("authentication failed: wrong key or altered value") from None
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise VaultError("decrypted value is not valid UTF-8") from None
