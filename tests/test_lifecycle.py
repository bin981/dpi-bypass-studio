"""Başlatma sırası, geri alma ve Linux'ta ağın hiç sorgulanmaması."""

from __future__ import annotations

import sys

import pytest

from core.dpi_engine import EngineStats, PrivacySwitch
from core.errors import DnsRestoreError, PlatformError
from core.lifecycle import Controller
from core.logbus import LogBus
from core.profiles import StartConfig
from core.system_net import SystemDnsManager
from tests.fakes import Adapter, FakeBackend, RecordingService


def _config(**kwargs) -> StartConfig:
    values = dict(
        profile_id="standard",
        provider="cloudflare",
        risk_accepted=False,
        fake_ttl_enabled=False,
        fake_ttl=1,
        shrink_enabled=False,
        shrink_window=4,
        http_host_case=False,
    )
    values.update(kwargs)
    return StartConfig(**values)


def _controller(tmp_path, *, admin=True, require_windows=False):
    order: list[str] = []
    backend = FakeBackend(adapters=[Adapter(1, "dhcp", ("192.168.1.1",), "dhcp", ())])
    backend.admin = admin
    net = SystemDnsManager(backend, tmp_path / "journal.json")
    dns = RecordingService("dns", order)
    dpi = RecordingService("dpi", order)
    http = RecordingService("http", order)
    controller = Controller(net, dns, dpi, http, LogBus(), require_windows=require_windows)
    return controller, backend, dns, order


def test_start_order_and_stop_restores_before_proxy_stops(tmp_path) -> None:
    controller, backend, dns, order = _controller(tmp_path)
    controller.start(_config(http_host_case=True, risk_accepted=True))
    assert order == ["dns-bootstrap", "dns-start", "dpi-start", "http-start"]
    assert backend.calls[0][0] == "list"
    assert ("static", 1, "ipv4", ("127.0.0.1",)) in backend.calls
    assert controller.state == "running"
    controller.stop()
    assert order.index("dns-stop") > len(order) - 4
    restore_at = next(i for i, call in enumerate(backend.calls) if call[0] == "dhcp")
    assert restore_at < len(backend.calls)
    assert order[-3:] == ["http-stop", "dpi-stop", "dns-stop"]
    assert controller.state == "idle"
    assert not controller.net_applied


def test_dpi_failure_does_not_redirect_dns(tmp_path) -> None:
    controller, backend, dns, order = _controller(tmp_path)
    controller.dpi.fail = "start"
    with pytest.raises(RuntimeError):
        controller.start(_config())
    assert "dpi-start" in order
    assert "dns-stop" in order
    assert not any(call[0] == "static" for call in backend.calls)
    assert controller.dns_running is False


def test_restore_failure_keeps_proxy(tmp_path) -> None:
    controller, backend, _dns, order = _controller(tmp_path)
    controller.start(_config())
    backend.fail_dhcp = True
    with pytest.raises(DnsRestoreError):
        controller.stop()
    assert "dns-stop" not in order
    assert controller.dns_running is True
    assert controller.state == "error"
    backend.fail_dhcp = False
    controller.stop()
    assert "dns-stop" in order
    assert controller.state == "idle"


def test_linux_start_does_not_touch_services() -> None:
    if sys.platform == "win32":
        pytest.skip("Windows")
    from pathlib import Path

    order: list[str] = []
    backend = FakeBackend(adapters=[Adapter(1, "dhcp", (), "dhcp", ())])
    net = SystemDnsManager(backend, Path("/tmp/should-not-be-required.json"))
    dns = RecordingService("dns", order)
    controller = Controller(net, dns, RecordingService("dpi", order), RecordingService("http", order), LogBus())
    with pytest.raises(PlatformError):
        controller.start(_config())
    assert order == []
    assert backend.calls == []


def test_not_admin_stops_before_bootstrap(tmp_path) -> None:
    controller, backend, _dns, order = _controller(tmp_path, admin=False)
    with pytest.raises(Exception):
        controller.start(_config())
    assert order == []
    assert backend.calls == []


def test_privacy_switch_and_empty_stats() -> None:
    privacy = PrivacySwitch()
    privacy.set_hide(True)
    assert privacy.mask("discord.com") == "<gizli 11 bayt>"
    privacy.set_hide(False)
    assert privacy.mask("discord.com") == "discord.com"
    assert EngineStats().split == 0
