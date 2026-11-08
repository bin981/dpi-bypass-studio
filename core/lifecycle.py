"""Başlatma ve durdurma sırası.

Vekil dinlemeden DNS yönlendirilmez. Durdururken önce eski DNS geri gelir;
geri yükleme başarısızsa vekil kapatılmaz. GUI açılışı bu sınıfın start()
metodunu kendiliğinden çağırmaz.
"""

from __future__ import annotations

import sys
import threading

from core.dns_proxy import DnsProxy
from core.doh import PROVIDERS
from core.dpi_engine import DpiEngine, TlsOptions
from core.errors import (
    AdminRequired,
    ConfigError,
    DnsRestoreError,
    NetworkRollbackError,
    PlatformError,
    RecoveryRequired,
    StudioError,
)
from core.http_mangle import HttpCaseEngine, HttpOptions
from core.logbus import LogBus
from core.profiles import StartConfig, validate_config
from core.system_net import SystemDnsManager

LINUX_START_MESSAGE = (
    "Bu uygulama paket yakalama ve DNS yönlendirmesini yalnızca Windows'ta yapar. "
    "Başlatma bu işletim sisteminde ağ sorgusu göndermeden durdu."
)


class Controller:
    def __init__(
        self,
        net: SystemDnsManager,
        dns: DnsProxy,
        dpi: DpiEngine,
        http: HttpCaseEngine,
        log: LogBus,
        *,
        require_windows: bool = True,
    ) -> None:
        self.net = net
        self.dns = dns
        self.dpi = dpi
        self.http = http
        self.log = log
        self.require_windows = require_windows
        self._lock = threading.Lock()
        self._state = "idle"
        self._net_applied = False
        self._dns_on = False
        self._dpi_on = False
        self._http_on = False
        self._provider = "cloudflare"

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def net_applied(self) -> bool:
        return self._net_applied

    @property
    def dns_running(self) -> bool:
        return self._dns_on

    @property
    def dns_port(self) -> int | None:
        return self.dns.port

    @property
    def provider(self) -> str:
        return self._provider

    def stats_line(self) -> str:
        stats = self.dpi.stats()
        ipv6 = "IPv6 dinleyici açık" if self.dns.ipv6_listening else "IPv6 dinleyici yok"
        return (
            f"Paket {stats.seen} · parçalanan {stats.split} · geçirilen {stats.passed} · "
            f"sahte {stats.fake} · hata {stats.errors} · döngü {stats.loops} · {ipv6}"
        )

    def start(self, config: StartConfig) -> None:
        with self._lock:
            if self._state in {"starting", "running", "stopping"}:
                raise StudioError("Başka bir geçiş sürüyor.")
            self._state = "starting"
        self._provider = config.provider
        try:
            self._start_body(config)
        except Exception:
            with self._lock:
                if self._state == "starting":
                    self._state = "error" if self._net_applied or self._dns_on else "idle"
            raise
        else:
            with self._lock:
                self._state = "running"

    def stop(self) -> None:
        with self._lock:
            if self._state == "idle" and not self._dns_on and not self._net_applied:
                return
            if self._state in {"starting", "stopping"}:
                raise StudioError("Geçiş sürüyor; bitmesini bekleyin.")
            self._state = "stopping"
        try:
            self._stop_body()
        except Exception:
            with self._lock:
                self._state = "error"
            raise
        else:
            with self._lock:
                self._state = "idle"

    def recover(self) -> None:
        if self.require_windows and sys.platform != "win32":
            raise PlatformError(LINUX_START_MESSAGE)
        if not self.net.is_admin():
            raise AdminRequired("Geri yükleme için yönetici hakları gerekir. packaging\\yonetici_olarak_baslat.ps1 kullanın.")
        self.net.restore()
        self._net_applied = False
        self.log.publish("bilgi", "Kayıtlı DNS ayarları geri yüklendi.")
        with self._lock:
            if not self._dns_on:
                self._state = "idle"

    def _start_body(self, config: StartConfig) -> None:
        if self.require_windows and sys.platform != "win32":
            raise PlatformError(LINUX_START_MESSAGE)
        if not self.net.is_admin():
            raise AdminRequired(
                "Başlatmak için yönetici hakları gerekir. packaging\\yonetici_olarak_baslat.ps1 ile açın."
            )
        if self.net.has_dirty_journal():
            raise RecoveryRequired("Çökme günlüğü duruyor. Önce kayıtlı DNS ayarlarını geri yükleyin.")
        try:
            validate_config(config, known_providers=set(PROVIDERS))
        except ConfigError:
            raise
        provider = PROVIDERS[config.provider]
        self.log.publish("bilgi", "DoH önyüklemesi başlıyor. Sistem DNS'i kullanılmayacak.")
        self.dns.bootstrap(provider)
        self.dns.start()
        self._dns_on = True
        self.log.publish("bilgi", "DNS vekili dinliyor. Sistem DNS'i henüz değiştirilmedi.")
        try:
            self.dpi.start(
                TlsOptions(
                    allowlist=config.allowlist(),
                    fake_ttl=config.fake_ttl if config.fake_ttl_enabled else None,
                    shrink_window=config.shrink_window if config.shrink_enabled else None,
                )
            )
            self._dpi_on = True
            if config.http_host_case:
                self.http.start(HttpOptions(allowlist=config.allowlist()))
                self._http_on = True
            ipv6 = ("::1",) if self.dns.ipv6_listening else None
            if ipv6 is None:
                self.log.publish(
                    "uyari",
                    "IPv6 DNS dinleyicisi yok. IPv6 DNS sunucuları değiştirilmeyecek. "
                    "IPv6 sorguları ISS çözümleyicisine gidebilir. DNS sızıntısı olmadığı iddia edilmez.",
                )
            try:
                self.net.redirect(("127.0.0.1",), ipv6)
            except NetworkRollbackError:
                self._net_applied = True
                raise
            self._net_applied = True
        except Exception:
            if not self._net_applied:
                self._shutdown_services()
            raise
        self.log.publish(
            "bilgi",
            "Çalışıyor. Bu bir VPN değildir ve ISS engelinin kalktığı garanti edilmez. "
            "Hız kaybı olmayacağı da iddia edilmez.",
        )

    def _stop_body(self) -> None:
        if self._net_applied or self.net.has_dirty_journal():
            try:
                self.net.restore()
            except Exception as exc:
                self.log.publish(
                    "hata",
                    "DNS geri yüklenemedi. Yerel vekil kapatılmadı; aksi halde bu makinenin DNS'i kalmayabilirdi. "
                    f"{exc}",
                )
                raise DnsRestoreError(str(exc)) from exc
            self._net_applied = False
            self.log.publish("bilgi", "Önceki DNS ayarları geri yüklendi. Vekil şimdi kapatılacak.")
        self._shutdown_services()
        self.log.publish("bilgi", "Durduruldu. Ağ ayarları geri yükleme adımından geçti.")

    def _shutdown_services(self) -> None:
        errors: list[str] = []
        if self._http_on:
            try:
                self.http.stop()
            except Exception as exc:
                errors.append(str(exc))
            else:
                self._http_on = False
        if self._dpi_on:
            try:
                self.dpi.stop()
            except Exception as exc:
                errors.append(str(exc))
            else:
                self._dpi_on = False
        if self._dns_on:
            try:
                self.dns.stop()
            except Exception as exc:
                errors.append(str(exc))
            else:
                self._dns_on = False
        if errors:
            raise StudioError("Kapatma sırasında hata: " + " | ".join(errors))
