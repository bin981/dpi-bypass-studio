"""Yaşam döngüsü testleri için sahte ağ ve hizmetler."""

from __future__ import annotations

from dataclasses import dataclass

from core.system_net import AdapterSnapshot, FamilyDns


@dataclass
class Adapter:
    index: int
    ipv4_mode: str
    ipv4_servers: tuple[str, ...]
    ipv6_mode: str
    ipv6_servers: tuple[str, ...]
    alias: str = "Ethernet"
    guid: str = "{GUID}"


class FakeBackend:
    def __init__(self, adapters: list[Adapter]) -> None:
        self.adapters = adapters
        self.calls: list[tuple] = []
        self.fail_at: tuple[int, str] | None = None
        self.fail_dhcp = False
        self.fail_on_second_static = False
        self._static_count = 0
        self.admin = True

    def is_admin(self) -> bool:
        return self.admin

    def list_default_adapters(self) -> list[AdapterSnapshot]:
        self.calls.append(("list",))
        return [
            AdapterSnapshot(
                index=item.index,
                guid=item.guid,
                alias=item.alias,
                ipv4=FamilyDns(item.ipv4_mode, item.ipv4_servers),
                ipv6=FamilyDns(item.ipv6_mode, item.ipv6_servers),
            )
            for item in self.adapters
        ]

    def set_static(self, index: int, family: str, servers: tuple[str, ...]) -> None:
        self._static_count += 1
        self.calls.append(("static", index, family, servers))
        if self.fail_at == (index, family):
            raise OSError("reddedildi")
        if self.fail_on_second_static and self._static_count == 2:
            raise OSError("ikinci yazım")

    def set_dhcp(self, index: int, family: str) -> None:
        self.calls.append(("dhcp", index, family))
        if self.fail_dhcp:
            raise OSError("dhcp geri alınamadı")

    def flush_cache(self) -> None:
        self.calls.append(("flush",))


class RecordingService:
    def __init__(self, name: str, order: list[str]) -> None:
        self.name = name
        self.order = order
        self.ipv6_listening = True
        self.port = 53
        self.fail = None

    def bootstrap(self, provider) -> str:
        self.order.append(f"{self.name}-bootstrap")
        if self.fail == "bootstrap":
            raise RuntimeError("bootstrap")
        return "127.0.0.1"

    def start(self, options=None) -> None:
        self.order.append(f"{self.name}-start")
        if self.fail == "start":
            raise RuntimeError("start")

    def stop(self) -> None:
        self.order.append(f"{self.name}-stop")
        if self.fail == "stop":
            raise RuntimeError("stop")
