"""Tests for `carchive.core.backup_crypto`."""

from __future__ import annotations

import pytest

from carchive.core import backup_crypto as bc

_KEY = bytes(range(32))
_SALT = b"s" * bc.SALT_LENGTH
_PREFIX = b"p" * bc.NONCE_PREFIX_LENGTH


def _header(time_cost: int = 3, memory_cost: int = 64, parallelism: int = 1) -> bc.Header:
    return bc.parse_header(bc.build_header(_SALT, time_cost, memory_cost, parallelism, _PREFIX))


def _encrypt_all(payload: bytes, header: bc.Header | None = None) -> list[bytes]:
    header = header or _header()
    encryptor = bc.BlockEncryptor(_KEY, header)
    chunks = [payload[i : i + bc.BLOCK_SIZE] for i in range(0, len(payload), bc.BLOCK_SIZE)]
    chunks = chunks or [b""]
    return [encryptor.encrypt(chunk, last=i == len(chunks) - 1) for i, chunk in enumerate(chunks)]


def _decrypt_all(blocks: list[bytes], header: bc.Header | None = None) -> bytes:
    decryptor = bc.BlockDecryptor(_KEY, header or _header())
    return b"".join(
        decryptor.decrypt(block, last=i == len(blocks) - 1) for i, block in enumerate(blocks)
    )


def test_header_roundtrip() -> None:
    raw = bc.build_header(_SALT, 3, 65536, 4, _PREFIX)

    header = bc.parse_header(raw + b"payload")

    assert len(raw) == bc.HEADER_LENGTH
    assert (header.salt, header.time_cost, header.memory_cost, header.parallelism) == (
        _SALT,
        3,
        65536,
        4,
    )
    assert header.nonce_prefix == _PREFIX
    assert header.raw == raw
    assert bc.is_encrypted_prefix(raw)
    assert not bc.is_encrypted_prefix(b"\x1f\x8b\x08")


@pytest.mark.parametrize(
    "payload_len", [0, 1, bc.BLOCK_SIZE - 1, bc.BLOCK_SIZE, 3 * bc.BLOCK_SIZE + 5]
)
def test_payload_roundtrip_at_block_boundaries(payload_len: int) -> None:
    payload = bytes(i % 251 for i in range(payload_len))

    assert _decrypt_all(_encrypt_all(payload)) == payload


def test_block_sizes_on_the_wire() -> None:
    blocks = _encrypt_all(b"x" * (2 * bc.BLOCK_SIZE + 10))

    assert [len(b) for b in blocks] == [bc.ENCRYPTED_BLOCK_SIZE] * 2 + [10 + bc.TAG_LENGTH]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: b"X" + raw[1:],
        lambda raw: raw[: len(bc.MAGIC)] + b"\x02" + raw[len(bc.MAGIC) + 1 :],
        lambda raw: raw[:20],
    ],
)
def test_parse_header_rejects_foreign_data(mutate) -> None:  # type: ignore[no-untyped-def]
    raw = bc.build_header(_SALT, 3, 64, 1, _PREFIX)

    with pytest.raises(bc.BackupFormatError):
        bc.parse_header(mutate(raw))


@pytest.mark.parametrize(
    ("time_cost", "memory_cost", "parallelism"),
    [
        (0, 64, 1),
        (bc.MAX_TIME_COST + 1, 64, 1),
        (3, bc.MAX_MEMORY_COST_KIB + 1, 1),
        (3, 4, 1),
        (3, 64, 0),
        (3, 64, bc.MAX_PARALLELISM + 1),
        (3, 8, 2),
    ],
)
def test_parse_header_bounds_key_derivation_cost(
    time_cost: int, memory_cost: int, parallelism: int
) -> None:
    raw = bc.MAGIC + bytes([bc.VERSION]) + _SALT
    raw += time_cost.to_bytes(4, "big") + memory_cost.to_bytes(4, "big")
    raw += parallelism.to_bytes(4, "big") + _PREFIX

    with pytest.raises(bc.BackupFormatError):
        bc.parse_header(raw)


def test_flipped_bit_in_a_block_fails() -> None:
    blocks = _encrypt_all(b"x" * (3 * bc.BLOCK_SIZE))
    blocks[1] = blocks[1][:100] + bytes([blocks[1][100] ^ 1]) + blocks[1][101:]

    with pytest.raises(bc.DecryptionError):
        _decrypt_all(blocks)


def test_truncation_at_a_block_boundary_fails() -> None:
    blocks = _encrypt_all(b"x" * (3 * bc.BLOCK_SIZE))

    with pytest.raises(bc.DecryptionError):
        _decrypt_all(blocks[:2])


def test_swapped_blocks_fail() -> None:
    blocks = _encrypt_all(b"x" * (3 * bc.BLOCK_SIZE))
    blocks[0], blocks[1] = blocks[1], blocks[0]

    with pytest.raises(bc.DecryptionError):
        _decrypt_all(blocks)


def test_appended_block_fails() -> None:
    blocks = _encrypt_all(b"x" * (2 * bc.BLOCK_SIZE))
    blocks.append(blocks[0])

    with pytest.raises(bc.DecryptionError):
        _decrypt_all(blocks)


def test_wrong_key_fails_with_a_generic_message() -> None:
    blocks = _encrypt_all(b"secret payload")
    decryptor = bc.BlockDecryptor(bytes(32), _header())

    with pytest.raises(bc.DecryptionError) as info:
        decryptor.decrypt(blocks[0], last=True)

    assert "secret" not in str(info.value)


def test_header_is_bound_to_every_block() -> None:
    blocks = _encrypt_all(b"payload")
    other = _header(time_cost=4)

    with pytest.raises(bc.DecryptionError):
        _decrypt_all(blocks, other)


def test_encryptor_rejects_misuse() -> None:
    encryptor = bc.BlockEncryptor(_KEY, _header())
    with pytest.raises(bc.BackupFormatError):
        encryptor.encrypt(b"short", last=False)
    with pytest.raises(bc.BackupFormatError):
        encryptor.encrypt(b"x" * (bc.BLOCK_SIZE + 1), last=True)
    encryptor.encrypt(b"final", last=True)
    with pytest.raises(bc.BackupFormatError):
        encryptor.encrypt(b"more", last=True)
    with pytest.raises(bc.BackupFormatError):
        bc.BlockEncryptor(b"short", _header())


def test_decryptor_rejects_blocks_after_the_final_one_and_bad_sizes() -> None:
    blocks = _encrypt_all(b"payload")
    decryptor = bc.BlockDecryptor(_KEY, _header())
    decryptor.decrypt(blocks[0], last=True)
    with pytest.raises(bc.BackupFormatError):
        decryptor.decrypt(blocks[0], last=True)
    with pytest.raises(bc.DecryptionError):
        bc.BlockDecryptor(_KEY, _header()).decrypt(b"tiny", last=True)
    with pytest.raises(bc.DecryptionError):
        bc.BlockDecryptor(_KEY, _header()).decrypt(blocks[0], last=False)
