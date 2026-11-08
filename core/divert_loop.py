"""pydivert.WinDivert yakalama döngüsü.

Sürücü yalnızca start() içinde ve yalnızca Windows'ta açılır. recv paketi yığından
çıkardığı için hata yolunda özgün paket geri gönderilir; sessizce düşürülmez.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from typing import Any

from core.errors import PlatformError

# WinDivert: yüksek değer önce işlenir. En düşük öncelik, gönderdiğimiz paketin
# daha düşük öncelikli başka bir tutamaç tarafından yeniden yakalanmamasını sağlar.
WINDIVERT_PRIORITY = -30000

PacketHandler = Callable[[Any, Any], None]


class DivertLoop:
    def __init__(self, name: str, filt: str, handler: PacketHandler, log: Callable[[str, str], None]) -> None:
        self.name = name
        self.filter = filt
        self._handler = handler
        self._log = log
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._handle: Any = None
        self._error: BaseException | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._error is None and not self._stop.is_set()

    def start(self) -> None:
        if sys.platform != "win32":
            raise PlatformError(
                "Paket yakalama yalnızca Windows'ta WinDivert ile çalışır. "
                "Bu ortamda sürücü açılmadı ve hiçbir paket yönlendirilmedi."
            )
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError(f"{self.name} zaten çalışıyor")
        self._stop.clear()
        self._ready.clear()
        self._error = None
        self._thread = threading.Thread(target=self._run, name=self.name, daemon=True)
        self._thread.start()
        if not self._ready.wait(8):
            self.stop()
            raise TimeoutError("WinDivert tutamacı zamanında açılmadı")
        if self._error is not None:
            error = self._error
            self.stop()
            raise error

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout)
            if thread.is_alive():
                handle = self._handle
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
                thread.join(2)
        self._thread = None

    def _run(self) -> None:
        handle = None
        try:
            import pydivert

            handle = pydivert.WinDivert(
                self.filter,
                layer=pydivert.Layer.NETWORK,
                priority=WINDIVERT_PRIORITY,
                flags=pydivert.Flag.DEFAULT,
            )
            handle.open()
            self._handle = handle
        except Exception as exc:
            self._error = exc
            self._ready.set()
            return
        self._ready.set()
        try:
            while not self._stop.is_set():
                try:
                    packet = handle.recv(timeout=0.4)
                except TimeoutError:
                    continue
                if self._stop.is_set():
                    self._rescue(handle, packet)
                    break
                try:
                    self._handler(handle, packet)
                except Exception as exc:
                    self._log("hata", f"{self.name} paket işleyicisi hata verdi, özgün paket geri veriliyor: {exc}")
                    self._rescue(handle, packet)
        except Exception as exc:
            if not self._stop.is_set():
                self._error = exc
                self._log("hata", f"{self.name} döngüsü durdu: {exc}")
        finally:
            self._handle = None
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass

    @staticmethod
    def _rescue(handle: Any, packet: Any) -> None:
        try:
            handle.send(packet, recalculate_checksum=True)
        except Exception:
            return
