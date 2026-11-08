"""DNS-over-HTTPS istemcisi.

Sistem çözümleyicisi kullanılmaz. Adres, sayısal önyükleme çözümleyicilerine
doğrudan UDP sorgusuyla bulunur; TLS sertifikası URL'deki ana makine adına göre
doğrulanır. httpx bağlantı havuzu bu sabit IP'ye bağlanır.
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass
from typing import Any, Callable

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import httpcore
import httpx

from core.errors import DohError

QueryUdp = Callable[[dns.message.Message, str, float, int], dns.message.Message]


@dataclass(frozen=True)
class DohProvider:
    id: str
    label: str
    url: str
    hostname: str
    fallback_ips: tuple[str, ...]
    bootstrap_resolvers: tuple[str, ...]


PROVIDERS: dict[str, DohProvider] = {
    "cloudflare": DohProvider(
        id="cloudflare",
        label="Cloudflare",
        url="https://cloudflare-dns.com/dns-query",
        hostname="cloudflare-dns.com",
        fallback_ips=("1.1.1.1", "1.0.0.1"),
        bootstrap_resolvers=("1.1.1.1", "8.8.8.8"),
    ),
    "google": DohProvider(
        id="google",
        label="Google",
        url="https://dns.google/dns-query",
        hostname="dns.google",
        fallback_ips=("8.8.8.8", "8.8.4.4"),
        bootstrap_resolvers=("8.8.8.8", "1.1.1.1"),
    ),
}


def default_query_udp(message: dns.message.Message, address: str, timeout: float, port: int) -> dns.message.Message:
    # dns.query.udp sayısal adrese gider; sistem DNS çözümleyicisini çağırmaz.
    return dns.query.udp(message, address, timeout=timeout, port=port)


def _reject_bootstrap_resolver(address: str, *, allow_loopback: bool) -> None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise DohError(f"Önyükleme çözümleyicisi sayısal IP değil: {address}") from exc
    if parsed.is_unspecified or parsed.is_multicast or parsed.is_link_local or parsed.is_reserved:
        raise DohError(f"Önyükleme çözümleyicisi kullanılamaz: {address}")
    if parsed.is_loopback and not allow_loopback:
        raise DohError(
            "Önyükleme çözümleyicisi geri döngü adresi olamaz. "
            "Sistem DNS'i 127.0.0.1 olduktan sonra DoH kendi vekiline soramaz."
        )
    if parsed.is_private and not allow_loopback:
        raise DohError(f"Önyükleme çözümleyicisi özel ağda: {address}")


def _safe_destination(address: str, *, allow_loopback: bool) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if allow_loopback and parsed.is_loopback:
        return True
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def resolve_direct(
    hostname: str,
    resolvers: tuple[str, ...],
    *,
    timeout: float = 2.0,
    port: int = 53,
    allow_loopback: bool = False,
    query_udp: QueryUdp = default_query_udp,
) -> list[str]:
    if not resolvers:
        raise DohError("Önyükleme çözümleyicisi yok.")
    found: list[str] = []
    for resolver in resolvers:
        _reject_bootstrap_resolver(resolver, allow_loopback=allow_loopback)
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            question = dns.message.make_query(hostname, rdtype)
            try:
                response = query_udp(question, resolver, timeout, port)
            except Exception:
                continue
            if response.rcode() != dns.rcode.NOERROR:
                continue
            for rrset in response.answer:
                if rrset.rdtype != rdtype:
                    continue
                for record in rrset:
                    address = getattr(record, "address", None)
                    if address and address not in found and _safe_destination(address, allow_loopback=allow_loopback):
                        found.append(address)
        if any(ipaddress.ip_address(item).version == 4 for item in found):
            break
    v4 = [item for item in found if ipaddress.ip_address(item).version == 4]
    v6 = [item for item in found if ipaddress.ip_address(item).version == 6]
    return v4 + v6


class _PinnedBackend:
    """TCP hedefini sabit IP yapar. TLS server_hostname URL'den gelmeye devam eder."""

    def __init__(self, ip: str, inner: httpcore.NetworkBackend) -> None:
        self._ip = ip
        self._inner = inner

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> Any:
        del host
        return self._inner.connect_tcp(
            self._ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: Any = None) -> Any:
        return self._inner.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class DohClient:
    def __init__(
        self,
        provider: DohProvider,
        ip: str,
        *,
        timeout: float = 5.0,
        verify: ssl.SSLContext | bool = True,
        http2: bool = True,
    ) -> None:
        if not _safe_destination(ip, allow_loopback=True):
            raise DohError(f"DoH hedefi geçersiz: {ip}")
        limits = httpx.Limits(max_connections=32, max_keepalive_connections=8, keepalive_expiry=30.0)
        transport = httpx.HTTPTransport(
            verify=verify,
            trust_env=False,
            retries=0,
            http2=http2,
            limits=limits,
        )
        inner = transport._pool._network_backend
        transport._pool._network_backend = _PinnedBackend(ip, inner)
        self.provider = provider
        self.ip = ip
        self._client = httpx.Client(
            transport=transport,
            trust_env=False,
            timeout=httpx.Timeout(timeout, connect=min(3.0, timeout)),
            follow_redirects=False,
            headers={
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message",
                "User-Agent": "DPIBypassStudio/1.0",
            },
        )

    def resolve_wire(self, query: bytes) -> bytes:
        try:
            response = self._client.post(self.provider.url, content=query)
        except httpx.HTTPError as exc:
            raise DohError(f"DoH isteği başarısız: {exc}") from exc
        content_type = response.headers.get("content-type", "")
        if response.status_code != 200:
            raise DohError(f"DoH HTTP {response.status_code}")
        if "dns-message" not in content_type.lower():
            raise DohError(f"DoH içerik türü beklenmiyor: {content_type or 'yok'}")
        if not response.content:
            raise DohError("DoH yanıtı boş")
        return bytes(response.content)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> DohClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class DohSession:
    def __init__(
        self,
        *,
        timeout: float = 5.0,
        allow_loopback_bootstrap: bool = False,
        verify: ssl.SSLContext | bool = True,
        query_udp: QueryUdp = default_query_udp,
        http2: bool = True,
    ) -> None:
        self._timeout = timeout
        self._allow_loopback = allow_loopback_bootstrap
        self._verify = verify
        self._query_udp = query_udp
        self._http2 = http2
        self.client: DohClient | None = None
        self.pinned_ip: str | None = None

    def bootstrap(self, provider: DohProvider) -> str:
        self.close()
        discovered = resolve_direct(
            provider.hostname,
            provider.bootstrap_resolvers,
            timeout=min(2.0, self._timeout),
            allow_loopback=self._allow_loopback,
            query_udp=self._query_udp,
        )
        candidates = [ip for ip in discovered if _safe_destination(ip, allow_loopback=self._allow_loopback)]
        if not candidates:
            candidates = [ip for ip in provider.fallback_ips if _safe_destination(ip, allow_loopback=self._allow_loopback)]
        if not candidates:
            raise DohError(f"{provider.hostname} için doğrulanabilir DoH adresi bulunamadı.")
        probe = dns.message.make_query(provider.hostname, dns.rdatatype.A)
        last_error: Exception | None = None
        for ip in candidates:
            client = DohClient(
                provider,
                ip,
                timeout=self._timeout,
                verify=self._verify,
                http2=self._http2,
            )
            try:
                wire = client.resolve_wire(probe.to_wire())
                parsed = dns.message.from_wire(wire)
                if parsed.id != probe.id:
                    raise DohError("DoH yanıt kimliği uyuşmuyor")
            except Exception as exc:
                client.close()
                last_error = exc
                continue
            self.client = client
            self.pinned_ip = ip
            return ip
        raise DohError(f"DoH uç noktası hazır değil: {last_error}")

    def resolve_wire(self, query: bytes) -> bytes:
        if self.client is None:
            raise DohError("DoH oturumu hazır değil")
        return self.client.resolve_wire(query)

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None
            self.pinned_ip = None

