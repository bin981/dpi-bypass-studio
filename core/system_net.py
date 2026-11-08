"""Windows DNS ayarının anlık görüntüsü, günlüğü ve geri alınması.

İçe aktarma hiçbir komut çalıştırmaz. Değişiklik yalnızca redirect() veya
restore() ile olur. Geri yükleme, özgün kip DHCP ise DHCP'ye döner; statik
adres listesini DHCP sanıp yazmaz. Komutlar kabuk dizisi olarak değil, sabit
PowerShell betiği ve doğrulanmış ortam değişkenleriyle kurulur.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from core.errors import NetworkRollbackError, PlatformError, RecoveryRequired, StudioError

Runner = Callable[..., subprocess.CompletedProcess[str]]

_SCRIPT_SET = """
$ErrorActionPreference = 'Stop'
$index = [int]$env:DPI_IFINDEX
$family = $env:DPI_FAMILY
$mode = $env:DPI_MODE
if ($family -ne 'IPv4' -and $family -ne 'IPv6') { Write-Error 'family'; exit 2 }
if ($mode -eq 'dhcp') {
  Set-DnsClientServerAddress -InterfaceIndex $index -AddressFamily $family -ResetServerAddresses -Confirm:$false
  if (-not $?) { exit 1 }
  exit 0
}
if ($mode -eq 'static') {
  $servers = @($env:DPI_SERVERS -split ';' | Where-Object { $_ -ne '' })
  if ($servers.Count -lt 1) { Write-Error 'servers'; exit 2 }
  Set-DnsClientServerAddress -InterfaceIndex $index -AddressFamily $family -ServerAddresses $servers -Validate:$false -Confirm:$false
  if (-not $?) { exit 1 }
  exit 0
}
Write-Error 'mode'
exit 2
""".strip()

_SCRIPT_LIST = """
$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter | Select-Object Name, InterfaceIndex, InterfaceGuid, Status, HardwareInterface, MacAddress)
$routes4 = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object InterfaceIndex, InterfaceAlias, RouteMetric, NextHop)
$routes6 = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Select-Object InterfaceIndex, InterfaceAlias, RouteMetric, NextHop)
[pscustomobject]@{ adapters = $adapters; routes4 = $routes4; routes6 = $routes6 } | ConvertTo-Json -Depth 5 -Compress
""".strip()


@dataclass(frozen=True)
class FamilyDns:
    mode: str
    servers: tuple[str, ...]


@dataclass(frozen=True)
class AdapterSnapshot:
    index: int
    guid: str
    alias: str
    ipv4: FamilyDns
    ipv6: FamilyDns


@dataclass(frozen=True)
class AppliedChange:
    index: int
    family: str


@dataclass
class Journal:
    version: int
    state: str
    created_at: str
    adapters: list[AdapterSnapshot]
    applied: list[AppliedChange]
    ipv4_target: tuple[str, ...]
    ipv6_target: tuple[str, ...] | None
    warnings: list[str]


def default_journal_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "DPIBypassStudio" / "recovery_journal.json"


def build_dns_invocation(
    index: int,
    family: str,
    mode: str,
    servers: tuple[str, ...] = (),
) -> tuple[list[str], dict[str, str]]:
    if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index > 0xFFFFFFFF:
        raise StudioError("Bağdaştırıcı dizini geçersiz.")
    if family not in {"ipv4", "ipv6"}:
        raise StudioError("Adres ailesi geçersiz.")
    if mode not in {"static", "dhcp"}:
        raise StudioError("DNS kipi geçersiz.")
    clean: list[str] = []
    if mode == "static":
        if not servers:
            raise StudioError("Statik DNS listesi boş olamaz.")
        expected = 4 if family == "ipv4" else 6
        for server in servers:
            try:
                parsed = ipaddress.ip_address(str(server).strip())
            except ValueError as exc:
                raise StudioError(f"DNS adresi geçersiz: {server}") from exc
            if parsed.version != expected:
                raise StudioError(f"{family} için uygun olmayan adres: {server}")
            clean.append(parsed.compressed)
    encoded = base64.b64encode(_SCRIPT_SET.encode("utf-16le")).decode("ascii")
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]
    env = {
        "DPI_IFINDEX": str(index),
        "DPI_FAMILY": "IPv4" if family == "ipv4" else "IPv6",
        "DPI_MODE": mode,
        "DPI_SERVERS": ";".join(clean),
    }
    return command, env


def build_list_command() -> list[str]:
    encoded = base64.b64encode(_SCRIPT_LIST.encode("utf-16le")).decode("ascii")
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]


def build_flush_command() -> list[str]:
    return ["ipconfig", "/flushdns"]


def classify_name_server(name_server: str | None, dhcp_name_server: str | None = None) -> FamilyDns:
    configured = _split_servers(name_server)
    if configured:
        return FamilyDns("static", configured)
    return FamilyDns("dhcp", _split_servers(dhcp_name_server))


def _split_servers(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    text = str(raw).strip()
    if not text:
        return ()
    parts = [part for part in _tokenize(text) if part]
    servers: list[str] = []
    for part in parts:
        try:
            servers.append(ipaddress.ip_address(part).compressed)
        except ValueError as exc:
            raise StudioError(f"Kayıttaki DNS adresi okunamadı: {part}") from exc
    return tuple(servers)


def _tokenize(text: str) -> list[str]:
    token = []
    items: list[str] = []
    for char in text.replace(",", " ").replace(";", " "):
        if char.isspace():
            if token:
                items.append("".join(token))
                token = []
        else:
            token.append(char)
    if token:
        items.append("".join(token))
    return items


def select_default_adapters(payload: dict[str, Any]) -> list[dict[str, Any]]:
    adapters = _as_list(payload.get("adapters"))
    routes = _as_list(payload.get("routes4")) + _as_list(payload.get("routes6"))
    metrics: dict[int, int] = {}
    for route in routes:
        try:
            index = int(route["InterfaceIndex"])
            metric = int(route.get("RouteMetric") or 0)
        except (KeyError, TypeError, ValueError):
            continue
        metrics[index] = min(metrics.get(index, metric), metric)
    chosen: list[dict[str, Any]] = []
    for adapter in adapters:
        try:
            index = int(adapter["InterfaceIndex"])
        except (KeyError, TypeError, ValueError):
            continue
        if index not in metrics:
            continue
        status = str(adapter.get("Status") or "")
        if status and status.lower() not in {"up", "1"}:
            continue
        alias = str(adapter.get("Name") or "")
        if "loopback" in alias.lower():
            continue
        chosen.append(adapter)
    chosen.sort(key=lambda item: metrics[int(item["InterfaceIndex"])])
    return chosen


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def describe_journal(journal: Journal) -> str:
    lines = [
        f"Durum: {journal.state}",
        f"Oluşturulma: {journal.created_at}",
        f"Hedef IPv4: {', '.join(journal.ipv4_target) or '-'}",
        f"Hedef IPv6: {', '.join(journal.ipv6_target) if journal.ipv6_target else 'değiştirilmedi'}",
    ]
    for adapter in journal.adapters:
        lines.append(
            f"{adapter.alias} (#{adapter.index}) IPv4 {adapter.ipv4.mode}"
            f" [{', '.join(adapter.ipv4.servers) or '-'}],"
            f" IPv6 {adapter.ipv6.mode} [{', '.join(adapter.ipv6.servers) or '-'}]"
        )
    if journal.warnings:
        lines.append("Uyarılar: " + " | ".join(journal.warnings))
    return "\n".join(lines)


def _assert_loopback_targets(servers: tuple[str, ...]) -> None:
    if not servers:
        raise StudioError("Yönlendirme adresi boş.")
    for server in servers:
        try:
            parsed = ipaddress.ip_address(server)
        except ValueError as exc:
            raise StudioError(f"Yönlendirme adresi geçersiz: {server}") from exc
        if not parsed.is_loopback:
            raise StudioError("DNS yalnızca geri döngü adresine yönlendirilebilir.")


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _journal_to_json(journal: Journal) -> str:
    payload = asdict(journal)
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _journal_from_json(text: str) -> Journal:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StudioError("Kurtarma günlüğü bozuk. Otomatik değişiklik yapılmadı.") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise StudioError("Kurtarma günlüğü sürümü tanınmıyor. Otomatik değişiklik yapılmadı.")
    if data.get("state") not in {"pending", "applied", "restored"}:
        raise StudioError("Kurtarma günlüğünün durumu geçersiz.")
    adapters: list[AdapterSnapshot] = []
    for item in data.get("adapters", []):
        adapters.append(
            AdapterSnapshot(
                index=_plain_int(item.get("index"), "bağdaştırıcı"),
                guid=str(item.get("guid") or ""),
                alias=str(item.get("alias") or ""),
                ipv4=_family_from_dict(item.get("ipv4"), "ipv4"),
                ipv6=_family_from_dict(item.get("ipv6"), "ipv6"),
            )
        )
    applied: list[AppliedChange] = []
    for item in data.get("applied", []):
        family = item.get("family")
        if family not in {"ipv4", "ipv6"}:
            raise StudioError("Kurtarma günlüğünde geçersiz adres ailesi var.")
        applied.append(AppliedChange(_plain_int(item.get("index"), "uygulanan"), family))
    ipv4_target = tuple(_validated_target(data.get("ipv4_target"), 4))
    raw_v6 = data.get("ipv6_target")
    ipv6_target = None if raw_v6 is None else tuple(_validated_target(raw_v6, 6))
    warnings = [str(item) for item in data.get("warnings", [])]
    return Journal(
        version=1,
        state=str(data["state"]),
        created_at=str(data.get("created_at") or ""),
        adapters=adapters,
        applied=applied,
        ipv4_target=ipv4_target,
        ipv6_target=ipv6_target,
        warnings=warnings,
    )


def _plain_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StudioError(f"Kurtarma günlüğünde {label} dizini bozuk.")
    if value < 0:
        raise StudioError(f"Kurtarma günlüğünde {label} dizini negatif.")
    return value


def _family_from_dict(value: Any, family: str) -> FamilyDns:
    if not isinstance(value, dict):
        raise StudioError("Kurtarma günlüğünde DNS ailesi eksik.")
    mode = value.get("mode")
    if mode not in {"dhcp", "static"}:
        raise StudioError("Kurtarma günlüğünde DNS kipi geçersiz.")
    servers = _validated_target(value.get("servers") or [], 4 if family == "ipv4" else 6, allow_empty=True)
    if mode == "static" and not servers:
        raise StudioError("Statik DNS kaydının adres listesi boş.")
    return FamilyDns(mode, tuple(servers))


def _validated_target(value: Any, version: int, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise StudioError("DNS adres listesi bozuk.")
    if not value and not allow_empty:
        raise StudioError("DNS adres listesi boş.")
    result: list[str] = []
    for item in value:
        try:
            parsed = ipaddress.ip_address(str(item))
        except ValueError as exc:
            raise StudioError("Kurtarma günlüğündeki adres geçersiz. Komut çalıştırılmadı.") from exc
        if parsed.version != version:
            raise StudioError("Kurtarma günlüğündeki adres ailesi uyuşmuyor.")
        result.append(parsed.compressed)
    return result


class NetworkBackend:
    def is_admin(self) -> bool:
        raise NotImplementedError

    def list_default_adapters(self) -> list[AdapterSnapshot]:
        raise NotImplementedError

    def set_static(self, index: int, family: str, servers: tuple[str, ...]) -> None:
        raise NotImplementedError

    def set_dhcp(self, index: int, family: str) -> None:
        raise NotImplementedError

    def flush_cache(self) -> None:
        raise NotImplementedError


class WindowsNetworkBackend(NetworkBackend):
    def __init__(self, runner: Runner | None = None, registry: Any = None) -> None:
        self._runner = runner or _default_runner
        self._registry = registry

    def is_admin(self) -> bool:
        if sys.platform != "win32":
            return False
        import ctypes

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def list_default_adapters(self) -> list[AdapterSnapshot]:
        self._require_windows()
        command = build_list_command()
        completed = self._runner(command, env=None, timeout=40)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise StudioError(f"Bağdaştırıcılar okunamadı: {detail}")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise StudioError("Bağdaştırıcı listesi ayrıştırılamadı.") from exc
        selected = select_default_adapters(payload)
        if not selected:
            raise StudioError("Varsayılan yolu olan etkin bağdaştırıcı bulunamadı.")
        registry = self._registry or WinregDnsReader()
        snapshots: list[AdapterSnapshot] = []
        for adapter in selected:
            guid = str(adapter.get("InterfaceGuid") or "")
            ipv4, ipv6 = registry.read(guid)
            snapshots.append(
                AdapterSnapshot(
                    index=int(adapter["InterfaceIndex"]),
                    guid=guid,
                    alias=str(adapter.get("Name") or adapter["InterfaceIndex"]),
                    ipv4=ipv4,
                    ipv6=ipv6,
                )
            )
        return snapshots

    def set_static(self, index: int, family: str, servers: tuple[str, ...]) -> None:
        self._require_windows()
        self._invoke(index, family, "static", servers)

    def set_dhcp(self, index: int, family: str) -> None:
        self._require_windows()
        self._invoke(index, family, "dhcp", ())

    def flush_cache(self) -> None:
        self._require_windows()
        completed = self._runner(build_flush_command(), env=None, timeout=20)
        if completed.returncode != 0:
            raise StudioError("DNS önbelleği temizlenemedi.")

    def _invoke(self, index: int, family: str, mode: str, servers: tuple[str, ...]) -> None:
        command, env = build_dns_invocation(index, family, mode, servers)
        completed = self._runner(command, env=env, timeout=40)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise StudioError(f"DNS ayarı uygulanamadı ({family}, {mode}): {detail}")

    @staticmethod
    def _require_windows() -> None:
        if sys.platform != "win32":
            raise PlatformError("Ağ ayarı değişikliği yalnızca Windows'ta yapılır. Bu çağrı hiçbir komut çalıştırmadı.")


class WinregDnsReader:
    def read(self, guid: str) -> tuple[FamilyDns, FamilyDns]:
        if sys.platform != "win32":
            raise PlatformError("Kayıt defteri yalnızca Windows'ta okunur.")
        import winreg

        ipv4 = _read_key(winreg, "Tcpip", guid)
        ipv6 = _read_key(winreg, "Tcpip6", guid)
        return ipv4, ipv6


def _read_key(winreg: Any, service: str, guid: str) -> FamilyDns:
    normalized = guid.strip().strip("{}")
    path = rf"SYSTEM\CurrentControlSet\Services\{service}\Parameters\Interfaces\{{{normalized}}}"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    except FileNotFoundError:
        return FamilyDns("dhcp", ())
    try:
        name_server = _query_string(winreg, key, "NameServer")
        dhcp_name_server = _query_string(winreg, key, "DhcpNameServer")
    finally:
        winreg.CloseKey(key)
    return classify_name_server(name_server, dhcp_name_server)


def _query_string(winreg: Any, key: Any, name: str) -> str | None:
    try:
        value, _kind = winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return None
    if isinstance(value, str):
        return value
    return None


def _default_runner(
    command: list[str],
    env: dict[str, str] | None,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    creationflags = 0
    if sys.platform == "win32":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        command,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged,
        check=False,
        creationflags=creationflags,
    )


class SystemDnsManager:
    def __init__(self, backend: NetworkBackend, journal_path: Path) -> None:
        self.backend = backend
        self.journal_path = journal_path

    def is_admin(self) -> bool:
        return self.backend.is_admin()

    def has_dirty_journal(self) -> bool:
        journal = self._peek()
        return journal is not None and journal.state in {"pending", "applied"}

    def read_journal(self) -> Journal | None:
        return self._peek()

    def describe(self) -> str:
        journal = self._peek()
        if journal is None:
            return "Kayıtlı kurtarma günlüğü yok."
        return describe_journal(journal)

    def redirect(self, ipv4: tuple[str, ...], ipv6: tuple[str, ...] | None) -> Journal:
        _assert_loopback_targets(ipv4)
        if ipv6 is not None:
            _assert_loopback_targets(ipv6)
        if self.has_dirty_journal():
            raise RecoveryRequired("Önceki DNS değişikliği geri yüklenmeden yeni yönlendirme yapılmaz.")
        adapters = self.backend.list_default_adapters()
        if not adapters:
            raise StudioError("Değiştirilecek bağdaştırıcı yok.")
        journal = Journal(
            version=1,
            state="pending",
            created_at=datetime.now(timezone.utc).isoformat(),
            adapters=list(adapters),
            applied=[],
            ipv4_target=tuple(ipv4),
            ipv6_target=None if ipv6 is None else tuple(ipv6),
            warnings=[],
        )
        self._save(journal)
        try:
            for adapter in adapters:
                self.backend.set_static(adapter.index, "ipv4", tuple(ipv4))
                journal.applied.append(AppliedChange(adapter.index, "ipv4"))
                journal.state = "applied"
                self._save(journal)
                if ipv6 is not None:
                    self.backend.set_static(adapter.index, "ipv6", tuple(ipv6))
                    journal.applied.append(AppliedChange(adapter.index, "ipv6"))
                    self._save(journal)
            try:
                self.backend.flush_cache()
            except Exception as exc:
                journal.warnings.append(f"DNS önbelleği temizlenemedi: {exc}")
                self._save(journal)
            return journal
        except Exception as exc:
            try:
                self.restore()
            except Exception as rollback_exc:
                raise NetworkRollbackError(
                    "DNS yönlendirmesi yarım kaldı ve geri alma da başarısız oldu. "
                    f"İlk hata: {exc}. Geri alma: {rollback_exc}. Vekil çalışır durumda bırakılmalı."
                ) from exc
            raise StudioError(f"DNS yönlendirmesi uygulanamadı ve önceki ayarlar geri yüklendi: {exc}") from exc

    def restore(self) -> None:
        journal = self._peek()
        if journal is None or journal.state == "restored":
            return
        errors: list[str] = []
        by_index = {adapter.index: adapter for adapter in journal.adapters}
        for change in reversed(journal.applied):
            adapter = by_index.get(change.index)
            if adapter is None:
                errors.append(f"Bağdaştırıcı {change.index} görüntüde yok.")
                continue
            family = adapter.ipv4 if change.family == "ipv4" else adapter.ipv6
            try:
                if family.mode == "dhcp":
                    self.backend.set_dhcp(change.index, change.family)
                else:
                    self.backend.set_static(change.index, change.family, family.servers)
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise NetworkRollbackError(
                "Bazı DNS ayarları geri alınamadı. Günlük yerinde bırakıldı: " + " | ".join(errors)
            )
        if journal.applied:
            try:
                self.backend.flush_cache()
            except Exception as exc:
                journal.warnings.append(f"Geri yükleme sonrası önbellek temizlenemedi: {exc}")
        journal.state = "restored"
        self._save(journal)
        try:
            self.journal_path.unlink()
        except FileNotFoundError:
            pass

    def _peek(self) -> Journal | None:
        if not self.journal_path.exists():
            return None
        return _journal_from_json(self.journal_path.read_text(encoding="utf-8"))

    def _save(self, journal: Journal) -> None:
        _atomic_write(self.journal_path, _journal_to_json(journal))
