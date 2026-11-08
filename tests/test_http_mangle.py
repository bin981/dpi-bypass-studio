"""HTTP Host karıştırma gerçekten HTTP'ye bakar, TLS'ye bakmaz."""

from __future__ import annotations

from core.http_mangle import HTTP_FILTER, mangle_http_payload, mix_alpha, rewrite_http_packet
from core.ip_tcp import parse_tcp_packet, tcp_checksum_ok
from core.profiles import DISCORD_GAME_HOSTS
from tests.packet_factory import build_client_hello, build_tcp_packet


def test_mix_is_deterministic_and_idempotent() -> None:
    assert mix_alpha("Host") == "HoSt"
    assert mix_alpha("discord.com") == "DiScOrD.cOm"
    assert mix_alpha(mix_alpha("discord.com")) == mix_alpha("discord.com")


def test_http_request_is_rewritten_once() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: discord.com\r\nUser-Agent: x\r\n\r\n"
    updated, host = mangle_http_payload(payload, None)
    assert host == "discord.com"
    assert b"HoSt: DiScOrD.cOm\r\n" in updated
    assert len(updated) == len(payload)
    again, host_again = mangle_http_payload(updated, None)
    assert again == updated
    assert host_again is None
    raw = build_tcp_packet(payload, dport=80, sport=1234)
    rewritten, seen = rewrite_http_packet(raw, None)
    parsed = parse_tcp_packet(rewritten)
    assert seen == "discord.com"
    assert b"HoSt: DiScOrD.cOm" in parsed.payload
    assert tcp_checksum_ok(parsed.src, parsed.dst, parsed.raw[parsed.tcp_offset :], 4)
    assert HTTP_FILTER.count("80") == 1
    assert "443" not in HTTP_FILTER


def test_tls_and_partial_http_are_not_modified() -> None:
    tls = build_client_hello("example.com")
    assert mangle_http_payload(tls, None) == (tls, None)
    raw = build_tcp_packet(tls, dport=443)
    assert rewrite_http_packet(raw, None) == (raw, None)
    partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n"
    assert mangle_http_payload(partial, None)[0] == partial


def test_allowlist_skips_other_hosts() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert mangle_http_payload(payload, DISCORD_GAME_HOSTS)[0] == payload
    discord = b"POST /api HTTP/1.1\r\nHost: gateway.discord.gg\r\n\r\n"
    updated, host = mangle_http_payload(discord, DISCORD_GAME_HOSTS)
    assert host == "gateway.discord.gg"
    assert b"HoSt:" in updated
