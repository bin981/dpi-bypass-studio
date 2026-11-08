"""DNS anlık görüntüsü, kısmi geri alma ve çökme günlüğü."""

from __future__ import annotations

import base64
import json

import pytest

from core.errors import NetworkRollbackError, PlatformError, StudioError
from core.system_net import (
    _SCRIPT_SET,
    SystemDnsManager,
    WindowsNetworkBackend,
    build_dns_invocation,
    build_flush_command,
    classify_name_server,
    select_default_adapters,
)
from tests.fakes import Adapter, FakeBackend


def test_classify_dhcp_versus_static() -> None:
    assert classify_name_server("", "192.168.1.1").mode == "dhcp"
    assert classify_name_server(None, "192.168.1.1").servers == ("192.168.1.1",)
    static = classify_name_server("1.1.1.1, 8.8.8.8", "192.168.1.1")
    assert static.mode == "static"
    assert static.servers == ("1.1.1.1", "8.8.8.8")
    with pytest.raises(StudioError):
        classify_name_server("1.1.1.1; Remove-Item C:\\", None)


def test_command_builder_has_no_injection_surface() -> None:
    command, env = build_dns_invocation(12, "ipv4", "static", ("127.0.0.1",))
    assert command[0] == "powershell.exe"
    assert "-EncodedCommand" in command
    decoded = base64.b64decode(command[command.index("-EncodedCommand") + 1]).decode("utf-16le")
    assert decoded == _SCRIPT_SET
    assert "127.0.0.1" not in decoded
    assert env["DPI_SERVERS"] == "127.0.0.1"
    assert env["DPI_IFINDEX"] == "12"
    with pytest.raises(StudioError):
        build_dns_invocation(4, "ipv4", "static", ("127.0.0.1;Remove-Item",))
    flush = build_flush_command()
    assert flush == ["ipconfig", "/flushdns"]


def test_adapter_selection_parses_single_object_and_routes() -> None:
    payload = {
        "adapters": {"Name": "Wi-Fi", "InterfaceIndex": 12, "Status": "Up", "InterfaceGuid": "{ABC}"},
        "routes4": {"InterfaceIndex": 12, "RouteMetric": 25},
        "routes6": [{"InterfaceIndex": 4, "RouteMetric": 10, "InterfaceAlias": "Ethernet"}],
    }
    # IPv6 route alone does not select an adapter that is absent from the adapter list.
    chosen = select_default_adapters(payload)
    assert [item["Name"] for item in chosen] == ["Wi-Fi"]
    down = {
        "adapters": [
            {"Name": "Down", "InterfaceIndex": 3, "Status": "Disconnected"},
            {"Name": "Up", "InterfaceIndex": 3, "Status": "Up"},
        ],
        "routes4": [{"InterfaceIndex": 3, "RouteMetric": 5}],
        "routes6": [],
    }
    assert [item["Name"] for item in select_default_adapters(down)] == ["Up"]


def test_redirect_restores_dhcp_exactly_and_rolls_back(tmp_path) -> None:
    backend = FakeBackend(
        adapters=[
            Adapter(1, "dhcp", (), "dhcp", ()),
            Adapter(2, "static", ("9.9.9.9",), "dhcp", ("2001:db8::53",)),
        ]
    )
    manager = SystemDnsManager(backend, tmp_path / "journal.json")
    journal = manager.redirect(("127.0.0.1",), ("::1",))
    assert journal.state == "applied"
    assert ("static", 1, "ipv4", ("127.0.0.1",)) in backend.calls
    assert ("static", 1, "ipv6", ("::1",)) in backend.calls
    assert manager.journal_path.exists()
    text_before_apply = None
    # Günlük, ilk değişimden önce yazılmıştı; şimdi geri yükleme DHCP'ye döner.
    manager.restore()
    dhcp_calls = [call for call in backend.calls if call[0] == "dhcp"]
    assert ("dhcp", 1, "ipv4") in dhcp_calls
    assert ("dhcp", 1, "ipv6") in dhcp_calls
    assert ("dhcp", 2, "ipv4") not in dhcp_calls
    static_restores = [call for call in backend.calls if call[0] == "static" and call[3] == ("9.9.9.9",)]
    assert static_restores[-1] == ("static", 2, "ipv4", ("9.9.9.9",))
    assert ("static", 2, "ipv6", ("2001:db8::53",)) not in backend.calls
    assert not manager.journal_path.exists()
    del text_before_apply


def test_partial_failure_rolls_back_and_crash_journal_recovers(tmp_path) -> None:
    backend = FakeBackend(adapters=[Adapter(1, "dhcp", ("192.168.0.1",), "dhcp", ()), Adapter(2, "static", ("9.9.9.9",), "static", ("2001:db8::1",))])
    backend.fail_at = (2, "ipv4")
    manager = SystemDnsManager(backend, tmp_path / "journal.json")
    with pytest.raises(StudioError):
        manager.redirect(("127.0.0.1",), None)
    assert ("dhcp", 1, "ipv4") in backend.calls
    assert not any(call[0] == "static" and call[3] == ("192.168.0.1",) for call in backend.calls)
    assert not manager.has_dirty_journal()

    backend.fail_at = None
    backend.calls.clear()
    dirty = {
        "version": 1,
        "state": "applied",
        "created_at": "2026-01-01T00:00:00+00:00",
        "adapters": [
            {
                "index": 7,
                "guid": "{AA}",
                "alias": "Ethernet",
                "ipv4": {"mode": "dhcp", "servers": ["192.168.1.1"]},
                "ipv6": {"mode": "static", "servers": ["2001:db8::9"]},
            }
        ],
        "applied": [{"index": 7, "family": "ipv4"}, {"index": 7, "family": "ipv6"}],
        "ipv4_target": ["127.0.0.1"],
        "ipv6_target": ["::1"],
        "warnings": [],
    }
    path = tmp_path / "crash.json"
    path.write_text(json.dumps(dirty), encoding="utf-8")
    recovered = SystemDnsManager(backend, path)
    assert recovered.has_dirty_journal()
    assert backend.calls == []
    recovered.restore()
    assert ("dhcp", 7, "ipv4") in backend.calls
    assert ("static", 7, "ipv6", ("2001:db8::9",)) in backend.calls
    assert not path.exists()


def test_tampered_journal_does_not_run_commands(tmp_path) -> None:
    backend = FakeBackend(adapters=[])
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "state": "applied",
                "created_at": "now",
                "adapters": [
                    {
                        "index": 1,
                        "guid": "x",
                        "alias": "x",
                        "ipv4": {"mode": "static", "servers": ["127.0.0.1;calc"]},
                        "ipv6": {"mode": "dhcp", "servers": []},
                    }
                ],
                "applied": [{"index": 1, "family": "ipv4"}],
                "ipv4_target": ["127.0.0.1"],
                "ipv6_target": None,
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )
    manager = SystemDnsManager(backend, path)
    with pytest.raises(StudioError):
        manager.restore()
    assert backend.calls == []


def test_rollback_failure_keeps_journal(tmp_path) -> None:
    backend = FakeBackend(adapters=[Adapter(1, "dhcp", (), "dhcp", ())])
    backend.fail_on_second_static = True
    backend.fail_dhcp = True
    manager = SystemDnsManager(backend, tmp_path / "journal.json")
    with pytest.raises(NetworkRollbackError):
        manager.redirect(("127.0.0.1",), ("::1",))
    assert manager.has_dirty_journal()
    assert ("dhcp", 1, "ipv4") in backend.calls


def test_windows_backend_does_not_run_off_windows() -> None:
    calls = []

    def runner(*args, **kwargs):
        calls.append(args)
        raise AssertionError("komut çalıştı")

    backend = WindowsNetworkBackend(runner=runner)
    if __import__("sys").platform == "win32":
        pytest.skip("Windows üzerinde sahte çalıştırıcı yine de çağrılabilir")
    with pytest.raises(PlatformError):
        backend.list_default_adapters()
    with pytest.raises(PlatformError):
        backend.set_static(1, "ipv4", ("127.0.0.1",))
    assert calls == []
    with pytest.raises(StudioError):
        SystemDnsManager(backend, __import__("pathlib").Path("unused")).redirect(("1.1.1.1",), None)


def test_import_manager_does_not_touch_backend(tmp_path) -> None:
    backend = FakeBackend(adapters=[])
    SystemDnsManager(backend, tmp_path / "j.json")
    assert backend.calls == []
