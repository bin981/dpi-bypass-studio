"""Arayüzün ana iş parçacığına aktardığı sınırlı günlük."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class LogBus:
    def __init__(self, maxlen: int = 1000) -> None:
        self._lines: deque[str] = deque(maxlen=maxlen)
        self._subs: list[Callable[[str], None]] = []
        self._lock = threading.Lock()

    def publish(self, level: str, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"{stamp}  {level:<5}  {message}"
        with self._lock:
            self._lines.append(line)
            listeners = list(self._subs)
        for listener in listeners:
            try:
                listener(line)
            except Exception:
                continue

    def subscribe(self, listener: Callable[[str], None]) -> None:
        with self._lock:
            self._subs.append(listener)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self._lines)
