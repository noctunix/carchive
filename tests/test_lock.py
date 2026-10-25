"""Tests for carchive.services.lock."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from carchive.services.lock import AlreadyRunningError, DataDirLock


def test_lock_creates_data_dir_with_restrictive_mode(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    with DataDirLock(data_dir):
        assert data_dir.is_dir()
        assert (data_dir.stat().st_mode & 0o777) == 0o700


def test_second_lock_on_same_dir_raises_with_pid(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    with (
        DataDirLock(data_dir),
        pytest.raises(AlreadyRunningError) as exc_info,
        DataDirLock(data_dir),
    ):
        pass

    assert str(os.getpid()) in str(exc_info.value)


def test_lock_can_be_reacquired_after_release(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    with DataDirLock(data_dir):
        pass

    with DataDirLock(data_dir):
        pass


def test_lock_file_holds_pid(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    with DataDirLock(data_dir):
        lock_file = data_dir / "carchive.lock"
        assert lock_file.read_text().strip() == str(os.getpid())


def test_lock_file_is_owner_only(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    with DataDirLock(data_dir):
        lock_file = data_dir / "carchive.lock"
        assert (lock_file.stat().st_mode & 0o777) == 0o600
