"""Tests for the file-level encryption helpers in `carchive.services.backup`."""

from __future__ import annotations

from pathlib import Path

import pytest

from carchive.core import backup_crypto as bc
from carchive.services import backup as backup_module
from carchive.services.backup import BackupError, decrypt_file, encrypt_file

_PASSPHRASE = "correct horse battery staple"


@pytest.fixture(autouse=True)
def _cheap_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup_module, "DEFAULT_TIME_COST", 1)
    monkeypatch.setattr(backup_module, "DEFAULT_MEMORY_COST", 64)
    monkeypatch.setattr(backup_module, "DEFAULT_PARALLELISM", 1)


def _encrypted(tmp_path: Path, payload: bytes) -> Path:
    src = tmp_path / "plain.bin"
    src.write_bytes(payload)
    dest = tmp_path / "plain.bin.enc"
    encrypt_file(src, dest, _PASSPHRASE)
    return dest


def _decrypt(enc: Path, tmp_path: Path, passphrase: str = _PASSPHRASE) -> bytes:
    out = tmp_path / "out.bin"
    decrypt_file(enc, out, passphrase)
    return out.read_bytes()


@pytest.mark.parametrize("size", [0, 1, bc.BLOCK_SIZE, 2 * bc.BLOCK_SIZE + 3])
def test_file_roundtrip(tmp_path: Path, size: int) -> None:
    payload = bytes(i % 253 for i in range(size))

    assert _decrypt(_encrypted(tmp_path, payload), tmp_path) == payload


def test_ciphertext_does_not_contain_the_plaintext(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"SQLite format 3\x00 marker " * 100)

    assert b"marker" not in enc.read_bytes()
    assert enc.read_bytes().startswith(bc.MAGIC + bytes([bc.VERSION]))


def test_two_encryptions_of_the_same_file_differ(tmp_path: Path) -> None:
    first = _encrypted(tmp_path, b"same").read_bytes()
    second = _encrypted(tmp_path, b"same").read_bytes()

    assert first != second


def test_default_key_derivation_parameters_are_written_to_the_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.undo()
    src = tmp_path / "plain.bin"
    src.write_bytes(b"x")
    dest = tmp_path / "plain.bin.enc"

    encrypt_file(src, dest, _PASSPHRASE)

    header = bc.parse_header(dest.read_bytes())
    assert (header.time_cost, header.memory_cost, header.parallelism) == (3, 65536, 4)


def test_wrong_passphrase_fails_without_leaking_it(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"payload")

    with pytest.raises(BackupError) as info:
        _decrypt(enc, tmp_path, "not the passphrase")

    assert "not the passphrase" not in str(info.value)
    assert "payload" not in str(info.value)


def test_tampered_block_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"x" * (3 * bc.BLOCK_SIZE))
    data = bytearray(enc.read_bytes())
    data[bc.HEADER_LENGTH + bc.ENCRYPTED_BLOCK_SIZE + 10] ^= 0x01
    enc.write_bytes(bytes(data))

    with pytest.raises(BackupError):
        _decrypt(enc, tmp_path)


def test_tampered_header_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"payload")
    data = bytearray(enc.read_bytes())
    data[-bc.NONCE_PREFIX_LENGTH - 1] ^= 0x01
    enc.write_bytes(bytes(data))

    with pytest.raises(BackupError):
        _decrypt(enc, tmp_path)


@pytest.mark.parametrize(
    "keep",
    [
        bc.HEADER_LENGTH + 2 * bc.ENCRYPTED_BLOCK_SIZE,
        bc.HEADER_LENGTH + bc.ENCRYPTED_BLOCK_SIZE + 5,
        bc.HEADER_LENGTH + 3 * bc.ENCRYPTED_BLOCK_SIZE - 1,
        bc.HEADER_LENGTH - 1,
    ],
)
def test_truncated_file_fails(tmp_path: Path, keep: int) -> None:
    enc = _encrypted(tmp_path, b"x" * (3 * bc.BLOCK_SIZE))
    enc.write_bytes(enc.read_bytes()[:keep])

    with pytest.raises(BackupError):
        _decrypt(enc, tmp_path)


def test_header_only_file_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"payload")
    enc.write_bytes(enc.read_bytes()[: bc.HEADER_LENGTH])

    with pytest.raises(BackupError):
        _decrypt(enc, tmp_path)


def test_swapped_blocks_fail(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"x" * (3 * bc.BLOCK_SIZE))
    data = enc.read_bytes()
    body = data[bc.HEADER_LENGTH :]
    size = bc.ENCRYPTED_BLOCK_SIZE
    swapped = body[size : 2 * size] + body[:size] + body[2 * size :]
    enc.write_bytes(data[: bc.HEADER_LENGTH] + swapped)

    with pytest.raises(BackupError):
        _decrypt(enc, tmp_path)


def test_appended_data_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"payload")
    enc.write_bytes(enc.read_bytes() + b"\x00" * 40)

    with pytest.raises(BackupError):
        _decrypt(enc, tmp_path)


def test_foreign_file_is_not_a_container(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign.enc"
    foreign.write_bytes(b"not a backup at all, just some bytes" * 5)

    with pytest.raises(BackupError, match="not an encrypted"):
        _decrypt(foreign, tmp_path)
