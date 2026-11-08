"""Gerçek DNS, TCP ve TLS ölçümü.

Başarılı bir TLS el sıkışması sansürün aşıldığını göstermez. Ölçülemeyen
gecikme uydurulmaz.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

TARGETS: tuple[tuple[str, str, int], ...] = (
    ("Discord", "discord.com", 443),
    ("Discord Gateway", "gateway.discord.gg", 443),
    ("Roblox", "www.roblox.com", 443),
    ("Google", "www.google.com", 443),
    ("YouTube", "www.youtube.com", 443),
    ("Vikipedi", "tr.wikipedia.org", 443),
    ("GitHub", "github.com", 443),
    ("Cloudflare", "www.cloudflare.com", 443),
)


@dataclass
class ProbeResult:
    name: str
    host: str
    port: int
    dns_path: str
    dns_ok: bool
    dns_ms: float | None
    dns_error: str | None
    addresses: tuple[str, ...]
    tcp_ok: bool
    tcp_ms: float | None
    tcp_error: str | None
    tcp_address: str | None
    tls_ok: bool
    tls_ms: float | None
    tls_error: str | None
    tls_version: str | None
    cert_subject: str | None
    interpretation: str


def interpret(result: ProbeResult) -> str:
    if not result.dns_ok:
        return (
            f"DNS ölçümü başarısız: {result.dns_error}. Gecikme uydurulmadı. "
            "Bu tek başına bir sansür teşhisi değildir."
        )
    addresses = ", ".join(result.addresses) if result.addresses else "adres yok"
    if not result.tcp_ok:
        return (
            f"DNS {result.dns_ms:.0f} ms sürdü ({addresses}). "
            f"TCP bağlantısı kurulamadı: {result.tcp_error}. TLS denenmedi. "
            "Başarısızlık DPI, güvenlik duvarı veya hedefin kendisi olabilir; "
            "bunu tek bir nedene bağlamayın."
        )
    if not result.tls_ok:
        return (
            f"TCP {result.tcp_ms:.0f} ms sürdü ({result.tcp_address}). "
            f"TLS el sıkışması tamamlanmadı: {result.tls_error}. "
            "Bu sonuç engelin aşıldığını göstermez."
        )
    subject = result.cert_subject or "sertifika konusu yok"
    version = result.tls_version or "sürüm yok"
    return (
        f"DNS {result.dns_ms:.0f} ms, TCP {result.tcp_ms:.0f} ms, TLS {result.tls_ms:.0f} ms "
        f"({version}, {subject}). TLS el sıkışması tamamlandı. Bu, sansürün aşıldığını veya "
        "DPI bypass'in çalıştığını göstermez; yalnızca bu hedefe TCP üzerinden TLS kurulabildiğini gösterir."
    )


def run_probes(
    *,
    dns_server: str,
    dns_port: int,
    dns_path: str,
    timeout: float = 3.0,
    cancel: Callable[[], bool] | None = None,
    targets: tuple[tuple[str, str, int], ...] = TARGETS,
) -> Iterator[ProbeResult]:
    for name, host, port in targets:
        if cancel is not None and cancel():
            return
        result = probe_one(
            name=name,
            host=host,
            port=port,
            dns_server=dns_server,
            dns_port=dns_port,
            dns_path=dns_path,
            timeout=timeout,
        )
        result.interpretation = interpret(result)
        yield result


def probe_one(
    *,
    name: str,
    host: str,
    port: int,
    dns_server: str,
    dns_port: int,
    dns_path: str,
    timeout: float,
) -> ProbeResult:
    dns_ok, dns_ms, dns_error, addresses = _resolve(host, dns_server, dns_port, timeout)
    tcp_ok = False
    tcp_ms = None
    tcp_error = None
    tcp_address = None
    tls_ok = False
    tls_ms = None
    tls_error = None
    tls_version = None
    cert_subject = None
    if dns_ok and addresses:
        tcp_ok, tcp_ms, tcp_error, tcp_address, tls_ok, tls_ms, tls_error, tls_version, cert_subject = _connect(
            host, port, addresses, timeout
        )
    elif dns_ok:
        tcp_error = "DNS adres döndürmedi"
    base = ProbeResult(
        name=name,
        host=host,
        port=port,
        dns_path=dns_path,
        dns_ok=dns_ok,
        dns_ms=dns_ms,
        dns_error=dns_error,
        addresses=tuple(addresses),
        tcp_ok=tcp_ok,
        tcp_ms=tcp_ms,
        tcp_error=tcp_error,
        tcp_address=tcp_address,
        tls_ok=tls_ok,
        tls_ms=tls_ms,
        tls_error=tls_error,
        tls_version=tls_version,
        cert_subject=cert_subject,
        interpretation="",
    )
    base.interpretation = interpret(base)
    return base


def _resolve(host: str, server: str, port: int, timeout: float) -> tuple[bool, float | None, str | None, list[str]]:
    started = time.perf_counter()
    addresses: list[str] = []
    try:
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            query = dns.message.make_query(host, rdtype)
            response = dns.query.udp(query, server, port=port, timeout=timeout)
            if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                elapsed = (time.perf_counter() - started) * 1000
                return False, elapsed, f"DNS rcode {dns.rcode.to_text(response.rcode())}", []
            if response.rcode() == dns.rcode.NXDOMAIN:
                elapsed = (time.perf_counter() - started) * 1000
                return False, elapsed, "NXDOMAIN", []
            for rrset in response.answer:
                if rrset.rdtype != rdtype:
                    continue
                for record in rrset:
                    address = getattr(record, "address", None)
                    if address and address not in addresses:
                        addresses.append(address)
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return False, elapsed, str(exc), []
    elapsed = (time.perf_counter() - started) * 1000
    if not addresses:
        return False, elapsed, "Kayıt yok", []
    return True, elapsed, None, addresses


def _connect(
    host: str,
    port: int,
    addresses: list[str],
    timeout: float,
) -> tuple[bool, float | None, str | None, str | None, bool, float | None, str | None, str | None, str | None]:
    last_tcp = "bağlantı denenmedi"
    for address in addresses[:3]:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.connect((address, port))
        except Exception as exc:
            last_tcp = str(exc)
            sock.close()
            continue
        tcp_ms = (time.perf_counter() - started) * 1000
        tls_started = time.perf_counter()
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=host) as secure:
                tls_ms = (time.perf_counter() - tls_started) * 1000
                cert = secure.getpeercert()
                return (
                    True,
                    tcp_ms,
                    None,
                    address,
                    True,
                    tls_ms,
                    None,
                    secure.version(),
                    _subject(cert),
                )
        except Exception as exc:
            return True, tcp_ms, None, address, False, None, str(exc), None, None
    return False, None, last_tcp, None, False, None, None, None, None


def _subject(cert: dict | None) -> str | None:
    if not cert:
        return None
    parts: list[str] = []
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or None
