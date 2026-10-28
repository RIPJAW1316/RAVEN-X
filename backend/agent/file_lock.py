"""Process-exclusive lock held through an operating-system file lock.

Ownership is the open handle, not file contents or timestamps: the kernel
releases the lock when the owning handle is closed, including when the owning
process is terminated. The lock file itself is never deleted, so a releasing
process can never remove a lock that another process has since acquired, and
no wall-clock "stale" heuristic exists to reclaim a live owner's lock.
"""

from __future__ import annotations

import os
from pathlib import Path


class FileLockBusyError(RuntimeError):
    """Another handle (in this or another process) currently holds the lock."""


class ExclusiveFileLock:
    """Non-blocking exclusive lock on byte 0 of an existing lock file."""

    def __init__(self, path):
        self.path = Path(path)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        if self._fd is not None:
            raise RuntimeError("this lock object already holds the lock")
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        fd = os.open(self.path, flags)
        try:
            # msvcrt.locking requires a byte range that exists. Pad an empty
            # leftover file before locking; this does not claim ownership.
            if os.fstat(fd).st_size < 1:
                os.write(fd, b"\x00")
            _lock(fd)
        except OSError as error:
            os.close(fd)
            raise FileLockBusyError("lock is held by another owner") from error
        self._fd = fd

    def release(self) -> None:
        """Release only the lock this object holds; repeated calls are no-ops."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            _unlock(fd)
        finally:
            os.close(fd)

    def __enter__(self) -> "ExclusiveFileLock":
        self.acquire()
        return self

    def __exit__(self, *_exc) -> None:
        self.release()


if os.name == "nt":
    import msvcrt

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
