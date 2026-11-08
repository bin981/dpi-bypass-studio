"""DoH önyüklemesi, vekil, önbellek ve sertifika doğrulaması."""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import pytest

from core.dns_proxy import DnsProxy, TtlCache, cache_ttl
from core.doh import DohError, DohProvider, DohSession, resolve_direct
from core.errors import StudioError


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class DohHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        server = self.server
        server.current += 1
        server.peak = max(server.peak, server.current)
        server.hits += 1
        if server.delay:
            time.sleep(server.delay)
        try:
            query = dns.message.from_wire(body)
            mode = server.modes.get(str(query.question[0].name), "ok")
            response = dns.message.make_response(query)
            if mode == "nxdomain":
                response.set_rcode(dns.rcode.NXDOMAIN)
                response.authority.append(
                    dns.rrset.from_text(query.question[0].name, 100, "IN", "SOA", "ns.example. host.example. 1 1 1 1 30")
                )
            elif mode == "servfail":
                response.set_rcode(dns.rcode.SERVFAIL)
            elif mode == "ok":
                response.answer.append(dns.rrset.from_text(query.question[0].name, server.ttl, "IN", "A", "192.0.2.10"))
            wire = response.to_wire()
        finally:
            server.current -= 1
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)

    def log_message(self, fmt: str, *args: object) -> None:
        return


class TlsHTTPServer(ThreadingHTTPServer):
    def __init__(self, address, handler, cert: Path, key: Path) -> None:
        super().__init__(address, handler)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(cert, key)
        self.hits = 0
        self.current = 0
        self.peak = 0
        self.delay = 0.0
        self.ttl = 60
        self.modes: dict[str, str] = {}

    def get_request(self):
        conn, addr = super().get_request()
        try:
            tls = self.ssl_context.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            conn.close()
            raise
        return tls, addr


@pytest.fixture(scope="module")
def identity(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    folder = tmp_path_factory.mktemp("doh-cert")
    cert = folder / "cert.pem"
    key = folder / "key.pem"
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=doh.test.local",
            "-addext",
            "subjectAltName=DNS:doh.test.local",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


@pytest.fixture()
def doh_server(identity: tuple[Path, Path]):
    cert, key = identity
    server = TlsHTTPServer(("127.0.0.1", 0), DohHandler, cert, key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _provider(port: int) -> DohProvider:
    return DohProvider(
        id="local",
        label="Yerel",
        url=f"https://doh.test.local:{port}/dns-query",
        hostname="doh.test.local",
        fallback_ips=("127.0.0.1",),
        bootstrap_resolvers=("127.0.0.1",),
    )


def _query_udp_factory(address: str):
    def query_udp(message, resolver, timeout, port):
        del resolver, timeout, port
        if message.question[0].rdtype == dns.rdatatype.A:
            response = dns.message.make_response(message)
            response.answer.append(dns.rrset.from_text(message.question[0].name, 60, "IN", "A", address))
            return response
        response = dns.message.make_response(message)
        response.set_rcode(dns.rcode.NOERROR)
        return response

    return query_udp


def test_bootstrap_rejects_loopback_and_private_answers() -> None:
    with pytest.raises(DohError):
        resolve_direct("doh.test.local", ("127.0.0.1",), allow_loopback=False, query_udp=_query_udp_factory("1.1.1.1"))

    def poisoned(message, resolver, timeout, port):
        del resolver, timeout, port
        response = dns.message.make_response(message)
        if message.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(message.question[0].name, 30, "IN", "A", "10.1.1.1"))
            response.answer.append(dns.rrset.from_text(message.question[0].name, 30, "IN", "A", "127.0.0.1"))
        return response

    assert resolve_direct("cloudflare-dns.com", ("1.1.1.1",), allow_loopback=False, query_udp=poisoned) == []


def test_pinned_tls_does_not_use_system_dns(doh_server, identity, monkeypatch: pytest.MonkeyPatch) -> None:
    cert, _key = identity
    context = ssl.create_default_context()
    context.load_verify_locations(cert)
    real_getaddrinfo = socket.getaddrinfo

    def guarded(host, *args, **kwargs):
        if isinstance(host, str) and host == "doh.test.local":
            raise AssertionError("sistem DNS çözümlemesi çağrıldı")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)
    session = DohSession(
        allow_loopback_bootstrap=True,
        verify=context,
        query_udp=_query_udp_factory("127.0.0.1"),
        http2=True,
    )
    ip = session.bootstrap(_provider(doh_server.server_address[1]))
    assert ip == "127.0.0.1"
    bad = ssl.create_default_context()
    bad.load_verify_locations(cert)
    wrong = DohProvider(
        id="wrong",
        label="Yanlış",
        url=f"https://wrong.test:{doh_server.server_address[1]}/dns-query",
        hostname="wrong.test",
        fallback_ips=("127.0.0.1",),
        bootstrap_resolvers=("127.0.0.1",),
    )
    failed = DohSession(allow_loopback_bootstrap=True, verify=bad, query_udp=_query_udp_factory("127.0.0.1"))
    with pytest.raises(DohError):
        failed.bootstrap(wrong)
    session.close()


def test_proxy_udp_tcp_cache_errors_and_limit(doh_server, identity) -> None:
    cert, _key = identity
    context = ssl.create_default_context()
    context.load_verify_locations(cert)
    clock = _Clock()
    session = DohSession(
        allow_loopback_bootstrap=True,
        verify=context,
        query_udp=_query_udp_factory("127.0.0.1"),
    )
    session.bootstrap(_provider(doh_server.server_address[1]))
    proxy = DnsProxy(bind_host="127.0.0.1", bind_port=0, enable_ipv6=True, max_inflight=4, session=session, clock=clock)
    proxy.start()
    assert proxy.port not in (None, 0)
    try:
        query = dns.message.make_query("cache.example", "A")
        first = dns.query.udp(query, "127.0.0.1", port=proxy.port, timeout=3)
        assert first.rcode() == dns.rcode.NOERROR
        assert first.answer[0][0].address == "192.0.2.10"
        hits = doh_server.hits
        second = dns.query.udp(query, "127.0.0.1", port=proxy.port, timeout=3)
        assert second.answer[0][0].address == "192.0.2.10"
        assert doh_server.hits == hits
        clock.now = 120
        dns.query.udp(query, "127.0.0.1", port=proxy.port, timeout=3)
        assert doh_server.hits == hits + 1
        tcp_answer = dns.query.tcp(dns.message.make_query("tcp.example", "A"), "127.0.0.1", port=proxy.port, timeout=3)
        assert tcp_answer.rcode() == dns.rcode.NOERROR
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"\x00\x01", ("127.0.0.1", proxy.port))
        sock.close()
        still = dns.query.udp(dns.message.make_query("afterbad.example", "A"), "127.0.0.1", port=proxy.port, timeout=3)
        assert still.rcode() == dns.rcode.NOERROR
        doh_server.modes["nx.example."] = "nxdomain"
        negative = dns.query.udp(dns.message.make_query("nx.example", "A"), "127.0.0.1", port=proxy.port, timeout=3)
        assert negative.rcode() == dns.rcode.NXDOMAIN
        negative_hits = doh_server.hits
        dns.query.udp(dns.message.make_query("nx.example", "A"), "127.0.0.1", port=proxy.port, timeout=3)
        assert doh_server.hits == negative_hits
        doh_server.modes["fail.example."] = "servfail"
        failed = dns.query.udp(dns.message.make_query("fail.example", "A"), "127.0.0.1", port=proxy.port, timeout=3)
        assert failed.rcode() == dns.rcode.SERVFAIL
        fail_hits = doh_server.hits
        dns.query.udp(dns.message.make_query("fail.example", "A"), "127.0.0.1", port=proxy.port, timeout=3)
        assert doh_server.hits == fail_hits + 1
        doh_server.delay = 0.08
        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(lambda i: dns.query.udp(dns.message.make_query(f"c{i}.example", "A"), "127.0.0.1", port=proxy.port, timeout=3), range(12)))
        assert doh_server.peak <= 4
    finally:
        proxy.stop()
    rebound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rebound.bind(("127.0.0.1", proxy.port))
    rebound.close()


def test_proxy_refuses_non_loopback() -> None:
    with pytest.raises(StudioError):
        DnsProxy(bind_host="0.0.0.0", bind_port=0)


def test_negative_ttl_helper() -> None:
    query = dns.message.make_query("nx.example", "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.authority.append(dns.rrset.from_text("nx.example.", 100, "IN", "SOA", "ns.example. host.example. 1 1 1 1 30"))
    assert cache_ttl(response) == 30
    response.set_rcode(dns.rcode.SERVFAIL)
    response.authority = []
    response.answer = []
    assert cache_ttl(response) == 0
    cache = TtlCache(max_entries=1, clock=_Clock())
    key = ("example.", 1, 1)
    positive = dns.message.make_response(dns.message.make_query("example", "A"))
    cache.put(key, positive, 0)
    assert cache.get(key) is None
