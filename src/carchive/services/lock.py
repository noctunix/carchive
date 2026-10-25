"""Inter-process lock on the data directory, so CLI commands never race a running server."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from types import TracebackType
from typing import IO

from carchive.storage.db import ensure_owner_only_file


class AlreadyRunningError(RuntimeError):
    """Raised when the data directory is already locked by another process."""


class DataDirLock:
    """Exclusive, non-blocking lock on `<data_dir>/carchive.lock`.

    Args:
        data_dir: the data directory to lock. Created with mode `0o700` if
            it does not exist yet.
    """

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._lock_path = data_dir / "carchive.lock"
        self._file: IO[str] | None = None

    def __enter__(self) -> DataDirLock:
        """Acquire the lock.

        Returns:
            This `DataDirLock`.

        Raises:
            AlreadyRunningError: if another process already holds the lock.
                The message includes the holder's PID when the lock file is
                readable.
        """
        if not self._data_dir.exists():
            self._data_dir.mkdir(parents=True)
            self._data_dir.chmod(0o700)

        ensure_owner_only_file(self._lock_path)
        handle = self._lock_path.open("a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.seek(0)
            holder_pid = handle.read().strip()
            handle.close()
            detail = f" (held by PID {holder_pid})" if holder_pid else ""
            raise AlreadyRunningError(f"{self._lock_path} is already locked{detail}") from None

        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        self._file = handle
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release the lock."""
        if self._file is not None:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            self._file.close()
            self._file = None
