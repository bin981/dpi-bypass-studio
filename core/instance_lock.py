"""Tek örnek kilidi. İçe aktarma kilidi almaz."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path


class SingleInstance:
    def __init__(self, name: str = "Local\\DPIBypassEncryptedDNSStudio") -> None:
        self._name = name
        self._handle = None
        self._file = None

    def acquire(self) -> bool:
        if sys.platform == "win32":
            import ctypes

            kernel = ctypes.windll.kernel32
            handle = kernel.CreateMutexW(None, False, self._name)
            self._handle = handle
            if not handle:
                return False
            return kernel.GetLastError() != 183
        import fcntl

        path = Path(tempfile.gettempdir()) / "dpi-bypass-encrypted-dns-studio.lock"
        handle = path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        self._file = handle
        return True

    def release(self) -> None:
        if self._file is not None:
            import fcntl

            try:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            self._file.close()
            self._file = None
        if self._handle is not None and sys.platform == "win32":
            import ctypes

            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None
