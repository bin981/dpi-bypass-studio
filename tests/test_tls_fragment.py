"""TLS ayrıştırma, SNI orta nokta bölmesi, sıra sarması ve checksum."""

from __future__ import annotations

import pydivert

from core.dpi_engine import TlsOptions, plan_tls_packets
from core.ip_tcp import ipv4_checksum_ok, parse_tcp_packet, tcp_checksum_ok
from core.tls_hello import parse_sni
from tests.packet_factory import build_client_hello, build_tcp_packet

PREFIX = b"\x00\x2b\x00\x03\x02\x03\x04"


def _split(payload: bytes, **packet_kwargs):
    raw = build_tcp_packet(payload, **packet_kwargs)
    options = packet_kwargs.pop("options", TlsOptions())
    return raw, plan_tls_packets(raw, options)


def test_sni_midpoint_and_reassembly() -> None:
    payload = build_client_hello("abcd.example", prefix_extension=PREFIX, extra=b"\x16\x03\x03\x00\x01\xaa")
    info = parse_sni(payload)
    assert info.status == "ok"
    assert info.hostname == "abcd.example"
    assert payload[info.start : info.end] == b"abcd.example"
    raw, plan = _split(payload, seq=0xFFFFFFF0, window=40000)
    assert plan.action == "split"
    kinds = [item.kind for item in plan.packets]
    assert kinds == ["seg1", "seg2"]
    parsed = [parse_tcp_packet(item.raw) for item in plan.packets]
    assert parsed[0].payload + parsed[1].payload == payload
    assert parsed[0].seq == 0xFFFFFFF0
    assert parsed[1].seq == (0xFFFFFFF0 + len(parsed[0].payload)) & 0xFFFFFFFF
    assert parsed[1].seq < parsed[0].seq
    assert parsed[0].flags & 0x08 == 0
    assert parsed[1].flags & 0x08 == 0x08
    assert parsed[0].flags & 0x10 == 0x10
    assert parsed[0].window == 40000
    assert parsed[1].window == 40000
    name = b"abcd.example"
    joined_at = len(parsed[0].payload)
    assert payload[info.start : joined_at] == name[: joined_at - info.start]
    assert payload[joined_at : info.end] == name[joined_at - info.start :]
    assert parse_sni(parsed[0].payload).status == "truncated"
    for item, piece in zip(plan.packets, parsed, strict=True):
        assert item.recalculate_checksum is True
        assert tcp_checksum_ok(piece.src, piece.dst, piece.raw[piece.tcp_offset :], piece.ip_version)
        assert ipv4_checksum_ok(piece.raw[: piece.ip_header_len])
    assert raw.startswith(b"\x45") or parse_tcp_packet(raw).ip_version == 4


def test_odd_length_sni_and_pydivert_view() -> None:
    payload = build_client_hello("abcde")
    _raw, plan = _split(payload, seq=10)
    info = parse_sni(payload)
    first = parse_tcp_packet(plan.packets[0].raw)
    assert payload[info.start : info.start + 2] == first.payload[info.start : info.start + 2]
    packet = pydivert.Packet(plan.packets[1].raw, interface=(4, 1), direction=pydivert.Direction.OUTBOUND)
    assert packet.tcp.seq_num == first.seq + len(first.payload)
    assert packet.dst_port == 443
    assert packet.ipv4.ttl == 64
    reference = pydivert.Packet(bytearray(plan.packets[0].raw))
    reference.recalculate_checksums()
    assert reference.tcp.cksum == parse_tcp_packet(plan.packets[0].raw).raw[
        parse_tcp_packet(plan.packets[0].raw).tcp_offset + 16 : parse_tcp_packet(plan.packets[0].raw).tcp_offset + 18
    ][0] * 256 + parse_tcp_packet(plan.packets[0].raw).raw[parse_tcp_packet(plan.packets[0].raw).tcp_offset + 17]


def test_fake_ttl_checksum_and_window() -> None:
    payload = build_client_hello("discord.com")
    raw = build_tcp_packet(payload, ident=9, ttl=64)
    plan = plan_tls_packets(raw, TlsOptions(fake_ttl=1, shrink_window=4))
    assert [item.kind for item in plan.packets] == ["fake", "seg1", "seg2"]
    fake, first, _second = (parse_tcp_packet(item.raw) for item in plan.packets)
    assert fake.ttl == 1
    assert first.ttl == 64
    assert first.window == 4
    assert fake.window == 4
    assert fake.ident != first.ident
    assert ipv4_checksum_ok(fake.raw[: fake.ip_header_len])
    assert not tcp_checksum_ok(fake.src, fake.dst, fake.raw[fake.tcp_offset :], 4)
    assert plan.packets[0].recalculate_checksum is False
    assert tcp_checksum_ok(first.src, first.dst, first.raw[first.tcp_offset :], 4)


def test_truncated_syn_fragment_and_wrong_port_pass_through() -> None:
    full = build_client_hello("example.com")
    truncated = build_tcp_packet(full[:20])
    assert plan_tls_packets(truncated, TlsOptions()).action == "pass"
    assert plan_tls_packets(truncated, TlsOptions()).packets[0].raw == truncated
    syn = build_tcp_packet(full, flags=0x02)
    assert plan_tls_packets(syn, TlsOptions()).reason == "syn"
    fragmented = build_tcp_packet(full, mf=True)
    assert plan_tls_packets(fragmented, TlsOptions()).reason == "fragment"
    port_80 = build_tcp_packet(full, dport=80)
    assert plan_tls_packets(port_80, TlsOptions()).reason == "wrong_port"
    assert plan_tls_packets(b"\x16\x03\x01\x00\x05", TlsOptions()).action == "pass"


def test_malformed_record_and_short_sni() -> None:
    hello = bytearray(build_client_hello("ab"))
    hello[5] = 0x02
    plan = plan_tls_packets(build_tcp_packet(bytes(hello)), TlsOptions())
    assert plan.reason == "not_client_hello"
    short = plan_tls_packets(build_tcp_packet(build_client_hello("a")), TlsOptions())
    assert short.reason == "sni_too_short"
    assert short.packets[0].raw[0] == 0x45


def test_allowlist_and_ech() -> None:
    from core.profiles import DISCORD_GAME_HOSTS

    options = TlsOptions(allowlist=DISCORD_GAME_HOSTS)
    matched = plan_tls_packets(build_tcp_packet(build_client_hello("cdn.discordapp.com")), options)
    assert matched.action == "split"
    missed = plan_tls_packets(build_tcp_packet(build_client_hello("notdiscord.com")), options)
    assert missed.reason == "allowlist"
    ech = plan_tls_packets(build_tcp_packet(build_client_hello("cloudflare-ech.com", ech=True)), TlsOptions())
    assert ech.action == "split"
    assert ech.ech is True


def test_ipv6_extension_header_and_hop_limit() -> None:
    payload = build_client_hello("ipv6.example")
    raw = build_tcp_packet(
        payload,
        ip_version=6,
        src="2001:db8::10",
        dst="2001:db8::20",
        ttl=55,
        ipv6_dest_options=True,
        seq=0xFFFFFFFF,
    )
    plan = plan_tls_packets(raw, TlsOptions(fake_ttl=2))
    assert [item.kind for item in plan.packets] == ["fake", "seg1", "seg2"]
    pieces = [parse_tcp_packet(item.raw) for item in plan.packets]
    assert pieces[0].ttl == 2
    assert pieces[1].ttl == 55
    assert pieces[1].payload + pieces[2].payload == payload
    assert pieces[2].seq == len(pieces[1].payload) - 1
    assert pieces[1].tcp_offset > 40
    for piece in pieces[1:]:
        assert tcp_checksum_ok(piece.src, piece.dst, piece.raw[piece.tcp_offset :], 6)


def test_ipv4_and_tcp_options_survive() -> None:
    payload = build_client_hello("opts.example")
    raw = build_tcp_packet(payload, ipv4_options=b"\x01\x01\x01\x00", tcp_options=b"\x01\x01\x01\x00")
    plan = plan_tls_packets(raw, TlsOptions())
    for item in plan.packets:
        parsed = parse_tcp_packet(item.raw)
        assert parsed.ip_header_len == 24
        assert parsed.tcp_header_len == 24
        assert parsed.raw[parsed.ip_header_len - 4 : parsed.ip_header_len] == b"\x01\x01\x01\x00"
        assert ipv4_checksum_ok(parsed.raw[: parsed.ip_header_len])
