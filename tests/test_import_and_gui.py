"""İçe aktarma yan etkisi ve pencerenin ağa dokunmaması."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.dpi_engine import PrivacySwitch
from core.lifecycle import Controller
from core.logbus import LogBus
from core.system_net import SystemDnsManager
from tests.fakes import FakeBackend
from ui.app_window import AppWindow


def test_import_does_not_open_pydivert_or_subprocess() -> None:
    script = """
import customtkinter, httpx, dns
import subprocess, sys, traceback
def fail(*args, **kwargs):
    traceback.print_stack()
    raise SystemExit('subprocess called')
subprocess.run = fail
subprocess.Popen = fail
import main
import core.dpi_engine
import core.dns_proxy
import core.system_net
import ui.app_window
assert 'pydivert' not in sys.modules
print('ok')
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ok" in completed.stdout


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="ekran yok")
def test_window_open_and_start_do_not_touch_backend(tmp_path: Path) -> None:
    backend = FakeBackend(adapters=[])

    class Bomb(FakeBackend):
        def is_admin(self) -> bool:
            raise AssertionError("yönetici sorgusu")

        def list_default_adapters(self):
            raise AssertionError("bağdaştırıcı listesi")

        def set_static(self, *args, **kwargs):
            raise AssertionError("dns yazıldı")

        def set_dhcp(self, *args, **kwargs):
            raise AssertionError("dhcp yazıldı")

        def flush_cache(self) -> None:
            raise AssertionError("önbellek")

    net = SystemDnsManager(Bomb([]), tmp_path / "journal.json")

    class Silent:
        def __init__(self) -> None:
            self.privacy = PrivacySwitch()
            self.ipv6_listening = False
            self.port = None

        def bootstrap(self, provider) -> None:
            raise AssertionError("bootstrap")

        def start(self, options=None) -> None:
            raise AssertionError("start")

        def stop(self) -> None:
            return None

        def stats(self):
            from core.dpi_engine import EngineStats

            return EngineStats()

    controller = Controller(net, Silent(), Silent(), Silent(), LogBus(), require_windows=True)
    window = AppWindow(controller, enable_tray=False, prefs_path=tmp_path / "prefs.json")
    try:
        window.update()
        assert "değiştirilmedi" in window.state_label.cget("text")
        window._on_start()
        deadline = time.time() + 5
        while time.time() < deadline:
            window.update()
            if "Başlatılamadı" in window.state_label.cget("text"):
                break
            time.sleep(0.05)
        assert "Başlatılamadı" in window.state_label.cget("text")
        assert "Windows" in window.banner_label.cget("text")
        assert backend.calls == []
    finally:
        window._destroyed = True
        window.destroy()
