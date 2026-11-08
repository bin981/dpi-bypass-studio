"""127.0.0.1 üzerinde UDP ve TCP DNS vekili.

Sorgular DNS tel biçimindedir ve DNS-over-HTTPS ile iletilir. Önbellek, yanıt
TTL değerini ve olumsuz önbelleklemede SOA minimumunu kullanır. Vekil yalnızca
geri döngü adresine bağlanır.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdatatype

from core.doh import DohProvider, DohSession
from core.errors import DohError, StudioError

Clock = Callable[[], float]


@dataclass
class CacheEntry:
    wire: bytes
    expires_at: float


class TtlCache:
    def __init__(self, max_entries: int = 1024, clock: Clock | None = None) -> None:
        self._max = max_entries
        self._clock = clock or time.monotonic
        self._items: OrderedDict[tuple, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple) -> dns.message.Message | None:
        now = self._clock()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            if now >= item.expires_at:
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            wire = item.wire
        return dns.message.from_wire(wire)

    def put(self, key: tuple, message: dns.message.Message, ttl: int) -> None:
        if ttl <= 0:
            return
        expires = self._clock() + min(int(ttl), 3600)
        wire = message.to_wire()
        if len(wire) > 4096:
            return
        with self._lock:
            self._items[key] = CacheEntry(wire, expires)
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)


def cache_key(message: dns.message.Message) -> tuple:
    question = message.question[0]
    return (question.name.to_text().lower(), question.rdtype, question.rdclass)


def cache_ttl(message: dns.message.Message) -> int:
    if message.flags & dns.flags.CD:
        return 0
    rcode = message.rcode()
    if rcode == dns.rcode.NOERROR and message.answer:
        ttls = [int(rrset.ttl) for rrset in message.answer]
        ttl = min(ttls) if ttls else 0
    elif rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) and not message.answer:
        ttl = _negative_ttl(message)
    else:
        return 0
    if ttl <= 0:
        return 0
    return min(ttl, 3600)


def _negative_ttl(message: dns.message.Message) -> int:
    for rrset in message.authority:
        if rrset.rdtype != dns.rdatatype.SOA or len(rrset) == 0:
            continue
        minimum = int(getattr(rrset[0], "minimum", 0))
        return max(0, min(int(rrset.ttl), minimum))
    return 0


def _require_loopback(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise StudioError(f"DNS vekili adresi geçersiz: {host}") from exc
    if not address.is_loopback:
        raise StudioError("DNS vekili yalnızca geri döngü adresine bağlanır.")


class DnsProxy:
    def __init__(
        self,
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 53,
        ipv6_host: str = "::1",
        enable_ipv6: bool = True,
        timeout: float = 5.0,
        max_inflight: int = 32,
        cache_entries: int = 1024,
        clock: Clock | None = None,
        session: DohSession | None = None,
        log: Callable[[str, str], None] | None = None,
    ) -> None:
        _require_loopback(bind_host)
        if enable_ipv6:
            _require_loopback(ipv6_host)
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.ipv6_host = ipv6_host
        self.enable_ipv6 = enable_ipv6
        self.timeout = timeout
        self.max_inflight = max_inflight
        self._log = log or (lambda level, message: None)
        self.session = session or DohSession(timeout=timeout)
        self.cache = TtlCache(cache_entries, clock)
        self.port: int | None = None
        self.ipv6_listening = False
        self._stop = threading.Event()
        self._inflight = threading.BoundedSemaphore(max_inflight)
        self._tcp_slots = threading.BoundedSemaphore(max_inflight)
        self._executor: ThreadPoolExecutor | None = None
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._started = False

    @property
    def pinned_ip(self) -> str | None:
        return self.session.pinned_ip

    def bootstrap(self, provider: DohProvider) -> str:
        ip = self.session.bootstrap(provider)
        self._log("bilgi", f"DoH {provider.hostname} adresi {ip} olarak sabitlendi. Sistem DNS'i kullanılmadı.")
        return ip

    def start(self) -> None:
        if self._started:
            raise StudioError("DNS vekili zaten çalışıyor.")
        if self.session.client is None:
            raise StudioError("DNS vekili başlatılmadan önce DoH önyüklemesi gerekli.")
        self._stop.clear()
        udp_v4 = self._bind_udp(socket.AF_INET, self.bind_host, self.bind_port)
        self.port = udp_v4.getsockname()[1]
        tcp_v4 = self._bind_tcp(socket.AF_INET, self.bind_host, self.port)
        sockets = [udp_v4, tcp_v4]
        threads = [
            threading.Thread(target=self._serve_udp, args=(udp_v4,), name="dns-udp4", daemon=True),
            threading.Thread(target=self._serve_tcp, args=(tcp_v4,), name="dns-tcp4", daemon=True),
        ]
        self.ipv6_listening = False
        if self.enable_ipv6:
            try:
                udp_v6 = self._bind_udp(socket.AF_INET6, self.ipv6_host, self.port)
                tcp_v6 = self._bind_tcp(socket.AF_INET6, self.ipv6_host, self.port)
            except OSError as exc:
                self.ipv6_listening = False
                self._log("uyari", f"IPv6 DNS dinleyicisi açılmadı ({exc}). IPv6 sorguları kapsanmaz.")
            else:
                sockets.extend([udp_v6, tcp_v6])
                threads.append(threading.Thread(target=self._serve_udp, args=(udp_v6,), name="dns-udp6", daemon=True))
                threads.append(threading.Thread(target=self._serve_tcp, args=(tcp_v6,), name="dns-tcp6", daemon=True))
                self.ipv6_listening = True
        self._executor = ThreadPoolExecutor(max_workers=self.max_inflight, thread_name_prefix="dns-doh")
        self._sockets = sockets
        self._threads = threads
        self._started = True
        for thread in threads:
            thread.start()
        family = " ve ::1" if self.ipv6_listening else ""
        self._log("bilgi", f"DNS vekili {self.bind_host}:{self.port}{family} üzerinde dinliyor.")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        for sock in list(self._sockets):
            try:
                sock.close()
            except OSError:
                pass
        executor = self._executor
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None
        for thread in self._threads:
            thread.join(timeout)
        self._threads.clear()
        self._sockets.clear()
        self.session.close()
        self._started = False
        self.ipv6_listening = False

    def _bind_udp(self, family: int, host: str, port: int) -> socket.socket:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.settimeout(0.4)
            sock.bind((host, port))
        except Exception:
            sock.close()
            raise
        return sock

    def _bind_tcp(self, family: int, host: str, port: int) -> socket.socket:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.4)
            sock.bind((host, port))
            sock.listen(64)
        except Exception:
            sock.close()
            raise
        return sock

    def _serve_udp(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            executor = self._executor
            if executor is None:
                break
            try:
                executor.submit(self._handle_udp, sock, data, addr)
            except RuntimeError:
                break

    def _handle_udp(self, sock: socket.socket, data: bytes, addr: tuple) -> None:
        if self._stop.is_set():
            return
        wire = self._answer(data, udp=True)
        if not wire:
            return
        try:
            sock.sendto(wire, addr)
        except OSError:
            return

    def _serve_tcp(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._tcp_slots.acquire(blocking=False):
                conn.close()
                continue
            executor = self._executor
            if executor is None:
                conn.close()
                self._tcp_slots.release()
                break
            try:
                executor.submit(self._handle_tcp, conn)
            except RuntimeError:
                conn.close()
                self._tcp_slots.release()
                break

    def _handle_tcp(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(self.timeout)
            while not self._stop.is_set():
                header = _read_exact(conn, 2)
                if header is None:
                    break
                length = struct.unpack("!H", header)[0]
                if length == 0 or length > 16384:
                    break
                body = _read_exact(conn, length)
                if body is None:
                    break
                wire = self._answer(body, udp=False)
                if wire is None:
                    break
                if len(wire) > 65535:
                    break
                conn.sendall(struct.pack("!H", len(wire)) + wire)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._tcp_slots.release()

    def _answer(self, data: bytes, *, udp: bool) -> bytes | None:
        parsed = _parse_query(data)
        if parsed is None:
            return None
        if isinstance(parsed, bytes):
            return parsed
        key = cache_key(parsed)
        cached = self.cache.get(key)
        if cached is not None:
            return _render(cached, parsed, udp=udp)
        if not self._inflight.acquire(timeout=self.timeout):
            return _error_wire(parsed, dns.rcode.SERVFAIL, udp=udp)
        try:
            if self._stop.is_set():
                return _error_wire(parsed, dns.rcode.SERVFAIL, udp=udp)
            try:
                wire = self.session.resolve_wire(parsed.to_wire())
                response = dns.message.from_wire(wire)
            except (DohError, dns.exception.DNSException, OSError):
                return _error_wire(parsed, dns.rcode.SERVFAIL, udp=udp)
        finally:
            self._inflight.release()
        if not _matches_question(response, parsed):
            return _error_wire(parsed, dns.rcode.SERVFAIL, udp=udp)
        ttl = cache_ttl(response)
        if ttl > 0 and not (parsed.flags & dns.flags.CD):
            self.cache.put(key, response, ttl)
        return _render(response, parsed, udp=udp)


def _parse_query(data: bytes) -> dns.message.Message | bytes | None:
    if len(data) < 12 or len(data) > 4096:
        return None
    try:
        message = dns.message.from_wire(data)
    except Exception:
        return None
    if message.flags & dns.flags.QR:
        return None
    if message.opcode() != dns.opcode.QUERY:
        return _error_wire(message, dns.rcode.NOTIMP, udp=True)
    if len(message.question) != 1:
        return _error_wire(message, dns.rcode.FORMERR, udp=True)
    return message


def _matches_question(response: dns.message.Message, query: dns.message.Message) -> bool:
    if len(response.question) != 1 or len(query.question) != 1:
        return False
    left = response.question[0]
    right = query.question[0]
    return left.name == right.name and left.rdtype == right.rdtype and left.rdclass == right.rdclass


def _error_wire(query: dns.message.Message, rcode: int, *, udp: bool) -> bytes:
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    return _render(response, query, udp=udp)


def _render(response: dns.message.Message, query: dns.message.Message, *, udp: bool) -> bytes:
    response.id = query.id
    if not udp:
        return response.to_wire()
    limit = 512
    if query.edns >= 0 and query.payload:
        limit = max(512, min(int(query.payload), 4096))
    try:
        return response.to_wire(max_size=limit)
    except Exception:
        bare = dns.message.make_response(query)
        bare.set_rcode(dns.rcode.SERVFAIL)
        bare.flags |= dns.flags.TC
        return bare.to_wire()


def _read_exact(conn: socket.socket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        try:
            piece = conn.recv(size - len(chunks))
        except socket.timeout:
            return None
        if not piece:
            return None
        chunks.extend(piece)
    return bytes(chunks)
