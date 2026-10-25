"""Encrypted backup container format: header layout and per-block AES-256-GCM.

Layout of an encrypted backup (all integers big-endian)::

    magic            10 bytes   b"CARCHIVEBK"
    version           1 byte    1
    salt             16 bytes   Argon2id salt
    time_cost         4 bytes   Argon2id iterations
    memory_cost       4 bytes   Argon2id memory in KiB
    parallelism       4 bytes   Argon2id lanes
    nonce_prefix      7 bytes   random per file
    blocks            ...       AES-256-GCM, each `BLOCK_SIZE` plaintext bytes + 16-byte tag

The key is the 32-byte Argon2id output for the passphrase. The payload is encrypted in the
STREAM construction: block `i` uses the nonce `nonce_prefix || i (4 bytes) || last (1 byte)`
with `last` = 1 only on the final block, and the whole header as associated data. A wrong
counter (reordered or dropped blocks), a missing final block (truncation), data after the
final block and a changed header all fail authentication. Only the last block may be shorter
than `BLOCK_SIZE`; it is never empty unless the whole payload is. This module does no I/O.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CARCHIVEBK"
VERSION = 1
SALT_LENGTH = 16
NONCE_PREFIX_LENGTH = 7
KEY_LENGTH = 32
BLOCK_SIZE = 64 * 1024
TAG_LENGTH = 16
ENCRYPTED_BLOCK_SIZE = BLOCK_SIZE + TAG_LENGTH

_PARAMS = struct.Struct(">III")
HEADER_LENGTH = len(MAGIC) + 1 + SALT_LENGTH + _PARAMS.size + NONCE_PREFIX_LENGTH

# The header is unauthenticated until the first block decrypts, so the parameters it asks
# the key derivation to spend are bounded here instead of trusted.
MAX_TIME_COST = 10
MAX_MEMORY_COST_KIB = 1024 * 1024
MAX_PARALLELISM = 16
_MIN_MEMORY_PER_LANE_KIB = 8

_MAX_BLOCKS = 2**32


class BackupFormatError(ValueError):
    """Raised when data is not a supported encrypted backup container."""


class DecryptionError(ValueError):
    """Raised when a block fails authentication.

    A wrong passphrase and damaged or manipulated data are indistinguishable by design; the
    message carries no information about the content.
    """


@dataclass(frozen=True, slots=True)
class Header:
    """Parsed container header.

    Attributes:
        salt: Argon2id salt.
        time_cost: Argon2id iteration count.
        memory_cost: Argon2id memory in KiB.
        parallelism: Argon2id lane count.
        nonce_prefix: random prefix shared by all block nonces of this file.
        raw: the exact header bytes, used as associated data for every block.
    """

    salt: bytes
    time_cost: int
    memory_cost: int
    parallelism: int
    nonce_prefix: bytes
    raw: bytes


def is_encrypted_prefix(data: bytes) -> bool:
    """Return whether `data` starts with the container magic.

    Args:
        data: the first bytes of a file (at least `len(MAGIC)` to be conclusive).

    Returns:
        `True` if `data` begins with the container magic.
    """
    return data.startswith(MAGIC)


def build_header(
    salt: bytes, time_cost: int, memory_cost: int, parallelism: int, nonce_prefix: bytes
) -> bytes:
    """Serialize a container header.

    Args:
        salt: `SALT_LENGTH` random bytes.
        time_cost: Argon2id iteration count.
        memory_cost: Argon2id memory in KiB.
        parallelism: Argon2id lane count.
        nonce_prefix: `NONCE_PREFIX_LENGTH` random bytes.

    Returns:
        The `HEADER_LENGTH` header bytes.

    Raises:
        BackupFormatError: if a length is wrong or a cost parameter is out of range.
    """
    if len(salt) != SALT_LENGTH or len(nonce_prefix) != NONCE_PREFIX_LENGTH:
        raise BackupFormatError("invalid salt or nonce prefix length")
    _check_cost(time_cost, memory_cost, parallelism)
    return (
        MAGIC
        + bytes([VERSION])
        + salt
        + _PARAMS.pack(time_cost, memory_cost, parallelism)
        + nonce_prefix
    )


def parse_header(data: bytes) -> Header:
    """Parse and range-check the container header at the start of `data`.

    Args:
        data: at least `HEADER_LENGTH` bytes from the start of the file.

    Returns:
        The parsed header.

    Raises:
        BackupFormatError: if the magic or version is not recognized, the data is too
            short, or the key derivation parameters are outside the accepted range.
    """
    if len(data) < HEADER_LENGTH or not data.startswith(MAGIC):
        raise BackupFormatError("not an encrypted Carchive backup")
    if data[len(MAGIC)] != VERSION:
        raise BackupFormatError("unsupported encrypted backup version")
    offset = len(MAGIC) + 1
    salt = data[offset : offset + SALT_LENGTH]
    offset += SALT_LENGTH
    time_cost, memory_cost, parallelism = _PARAMS.unpack_from(data, offset)
    offset += _PARAMS.size
    nonce_prefix = data[offset : offset + NONCE_PREFIX_LENGTH]
    _check_cost(time_cost, memory_cost, parallelism)
    return Header(salt, time_cost, memory_cost, parallelism, nonce_prefix, data[:HEADER_LENGTH])


def _check_cost(time_cost: int, memory_cost: int, parallelism: int) -> None:
    if not 1 <= time_cost <= MAX_TIME_COST:
        raise BackupFormatError("key derivation time cost out of range")
    if not 1 <= parallelism <= MAX_PARALLELISM:
        raise BackupFormatError("key derivation parallelism out of range")
    if not _MIN_MEMORY_PER_LANE_KIB * parallelism <= memory_cost <= MAX_MEMORY_COST_KIB:
        raise BackupFormatError("key derivation memory cost out of range")


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


class BlockEncryptor:
    """Encrypts consecutive payload blocks under one key and header.

    Args:
        key: the `KEY_LENGTH`-byte derived key.
        header: the parsed header whose bytes are bound to every block.

    Raises:
        BackupFormatError: if `key` has the wrong length.
    """

    def __init__(self, key: bytes, header: Header) -> None:
        if len(key) != KEY_LENGTH:
            raise BackupFormatError("invalid key length")
        self._aead = AESGCM(key)
        self._header = header
        self._counter = 0
        self._finished = False

    def encrypt(self, plaintext: bytes, *, last: bool) -> bytes:
        """Encrypt the next block.

        Args:
            plaintext: the block; exactly `BLOCK_SIZE` bytes unless `last` is set.
            last: whether this is the final block of the payload.

        Returns:
            The ciphertext including the authentication tag.

        Raises:
            BackupFormatError: if the block size is wrong, a block follows the final one,
                or the block counter is exhausted.
        """
        if self._finished:
            raise BackupFormatError("block after the final block")
        if len(plaintext) > BLOCK_SIZE or (not last and len(plaintext) != BLOCK_SIZE):
            raise BackupFormatError("invalid block size")
        if self._counter >= _MAX_BLOCKS:
            raise BackupFormatError("payload too large")
        nonce = _nonce(self._header.nonce_prefix, self._counter, last)
        self._counter += 1
        self._finished = last
        return self._aead.encrypt(nonce, plaintext, self._header.raw)


class BlockDecryptor:
    """Decrypts consecutive payload blocks under one key and header.

    Args:
        key: the `KEY_LENGTH`-byte derived key.
        header: the parsed header whose bytes are bound to every block.

    Raises:
        BackupFormatError: if `key` has the wrong length.
    """

    def __init__(self, key: bytes, header: Header) -> None:
        if len(key) != KEY_LENGTH:
            raise BackupFormatError("invalid key length")
        self._aead = AESGCM(key)
        self._header = header
        self._counter = 0
        self._finished = False

    def decrypt(self, block: bytes, *, last: bool) -> bytes:
        """Decrypt and authenticate the next block.

        Args:
            block: the ciphertext including its tag.
            last: whether the reader found this block at the end of the file.

        Returns:
            The plaintext.

        Raises:
            DecryptionError: if authentication fails (wrong key, damaged, truncated,
                reordered or extended data) or the block has an impossible size.
            BackupFormatError: if a block follows the final one or the counter is
                exhausted.
        """
        if self._finished:
            raise BackupFormatError("block after the final block")
        if self._counter >= _MAX_BLOCKS:
            raise BackupFormatError("payload too large")
        if len(block) < TAG_LENGTH or len(block) > ENCRYPTED_BLOCK_SIZE:
            raise DecryptionError("decryption failed: wrong passphrase or damaged data")
        if not last and len(block) != ENCRYPTED_BLOCK_SIZE:
            raise DecryptionError("decryption failed: wrong passphrase or damaged data")
        nonce = _nonce(self._header.nonce_prefix, self._counter, last)
        try:
            plaintext = self._aead.decrypt(nonce, block, self._header.raw)
        except InvalidTag:
            raise DecryptionError("decryption failed: wrong passphrase or damaged data") from None
        self._counter += 1
        self._finished = last
        return plaintext
