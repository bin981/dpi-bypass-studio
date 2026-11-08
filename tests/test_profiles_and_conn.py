"""Profil doğrulaması ve bağlantı ölçümünün yorumu."""

from __future__ import annotations

import socket
import threading

import dns.message
import dns.rdatatype
import pytest

from core.conn_test import interpret, probe_one
from core.doh import PROVIDERS
from core.errors import ConfigError
from core.profiles import DISCORD_GAME_HOSTS, StartConfig, host_matches, validate_config


def _config(**kwargs) -> StartConfig:
    base = dict(
        profile_id="standard",
        provider="cloudflare",
        risk_accepted=False,
        fake_ttl_enabled=False,
        fake_ttl=1,
        shrink_enabled=False,
        shrink_window=4,
        http_host_case=False,
    )
    base.update(kwargs)
    return StartConfig(**base)


def test_host_match_boundaries() -> None:
    assert host_matches("cdn.discord.com", DISCORD_GAME_HOSTS)
    assert host_matches("discord.com", DISCORD_GAME_HOSTS)
    assert not host_matches("notdiscord.com", DISCORD_GAME_HOSTS)
    assert not host_matches("evil-discord.com", DISCORD_GAME_HOSTS)


def test_rejected_combinations() -> None:
    validate_config(_config(), known_providers=set(PROVIDERS))
    with pytest.raises(ConfigError):
        validate_config(_config(profile_id="aggressive"), known_providers=set(PROVIDERS))
    validate_config(_config(profile_id="aggressive", risk_accepted=True, fake_ttl_enabled=True), known_providers=set(PROVIDERS))
    with pytest.raises(ConfigError):
        validate_config(_config(fake_ttl_enabled=True, fake_ttl=0, risk_accepted=True), known_providers=set(PROVIDERS))
    with pytest.raises(ConfigError):
        validate_config(_config(shrink_enabled=True, shrink_window=0, risk_accepted=True), known_providers=set(PROVIDERS))
    with pytest.raises(ConfigError):
        validate_config(
            _config(profile_id="discord", fake_ttl_enabled=True, shrink_enabled=True, risk_accepted=True),
            known_providers=set(PROVIDERS),
        )
    with pytest.raises(ConfigError):
        validate_config(
            _config(fake_ttl_enabled=True, shrink_enabled=True, shrink_window=1, risk_accepted=True),
            known_providers=set(PROVIDERS),
        )


def test_interpretation_does_not_claim_bypass() -> None:
    from core.conn_test import ProbeResult

    success = ProbeResult(
        name="Discord",
        host="discord.com",
        port=443,
        dns_path="yerel",
        dns_ok=True,
        dns_ms=12,
        dns_error=None,
        addresses=("1.2.3.4",),
        tcp_ok=True,
        tcp_ms=20,
        tcp_error=None,
        tcp_address="1.2.3.4",
        tls_ok=True,
        tls_ms=30,
        tls_error=None,
        tls_version="TLSv1.3",
        cert_subject="CN=discord.com",
        interpretation="",
    )
    text = interpret(success)
    assert "göstermez" in text
    assert "bypass başarılı" not in text.lower()
    assert "engel aşıldı" not in text.lower()
    failed = ProbeResult(
        name="Roblox",
        host="www.roblox.com",
        port=443,
        dns_path="yerel",
        dns_ok=False,
        dns_ms=4,
        dns_error="zaman aşımı",
        addresses=(),
        tcp_ok=False,
        tcp_ms=None,
        tcp_error=None,
        tcp_address=None,
        tls_ok=False,
        tls_ms=None,
        tls_error=None,
        tls_version=None,
        cert_subject=None,
        interpretation="",
    )
    assert "uydurulmadı" in interpret(failed)


class _UdpDns(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stopping = False

    def run(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stopping:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            query = dns.message.from_wire(data)
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.NXDOMAIN)
            self.sock.sendto(response.to_wire(), addr)

    def close(self) -> None:
        self._stopping = True
        self.join(1)
        self.sock.close()


def test_probe_uses_real_dns_failure_without_inventing_success() -> None:
    server = _UdpDns()
    server.start()
    try:
        result = probe_one(
            name="Yerel",
            host="does-not-exist.example",
            port=443,
            dns_server="127.0.0.1",
            dns_port=server.port,
            dns_path="test",
            timeout=1,
        )
    finally:
        server.close()
    assert result.dns_ok is False
    assert result.tls_ok is False
    assert result.tcp_ok is False
    assert "uydurulmadı" in result.interpretation
    assert result.tls_ms is None
