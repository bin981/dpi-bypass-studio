"""DPI Bypass & Şifreli DNS Stüdyosu giriş noktası.

Pencereyi açmak ağ ayarını değiştirmez. --recover açık bir geri yükleme komutudur
ve Windows dışında hiçbir ayar yazmaz.
"""

from __future__ import annotations

import argparse
import sys
from tkinter import messagebox

import customtkinter as ctk

from core import __version__
from core.dns_proxy import DnsProxy
from core.dpi_engine import DpiEngine, PrivacySwitch
from core.errors import PlatformError
from core.http_mangle import HttpCaseEngine
from core.instance_lock import SingleInstance
from core.lifecycle import LINUX_START_MESSAGE, Controller
from core.logbus import LogBus
from core.system_net import SystemDnsManager, WindowsNetworkBackend, default_journal_path
from ui.app_window import AppWindow
from ui.strings import APP_TITLE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=APP_TITLE)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--recover",
        action="store_true",
        help="Kayıtlı DNS ayarlarını geri yükleyip çıkar. Pencere açılmaz.",
    )
    args = parser.parse_args(argv)
    if args.recover:
        return _recover_cli()
    lock = SingleInstance()
    if not lock.acquire():
        _say_already_running()
        return 2
    try:
        privacy = PrivacySwitch()
        log = LogBus()
        controller = Controller(
            net=SystemDnsManager(WindowsNetworkBackend(), default_journal_path()),
            dns=DnsProxy(log=log.publish),
            dpi=DpiEngine(log.publish, privacy),
            http=HttpCaseEngine(log.publish, privacy),
            log=log,
            require_windows=True,
        )
        window = AppWindow(controller, enable_tray=True)
        window.mainloop()
        return 0
    finally:
        lock.release()


def _recover_cli() -> int:
    if sys.platform != "win32":
        print(LINUX_START_MESSAGE, file=sys.stderr)
        return 2
    manager = SystemDnsManager(WindowsNetworkBackend(), default_journal_path())
    if not manager.is_admin():
        print("Kurtarma için yönetici hakları gerekir.", file=sys.stderr)
        return 3
    if not manager.has_dirty_journal():
        print("Geri yüklenecek kayıt yok.")
        return 0
    try:
        manager.restore()
    except PlatformError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Geri yükleme başarısız: {exc}", file=sys.stderr)
        return 1
    print("Kayıtlı DNS ayarları geri yüklendi.")
    return 0


def _say_already_running() -> None:
    try:
        ctk.set_appearance_mode("dark")
        root = ctk.CTk()
        root.withdraw()
        messagebox.showerror(APP_TITLE, "Uygulama zaten çalışıyor.")
        root.destroy()
    except Exception:
        print("Uygulama zaten çalışıyor.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
