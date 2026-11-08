"""Testler için geçerli IPv4/IPv6 TCP paketleri ve ClientHello üretir."""

from __future__ import annotations

import socket
import struct

from core.ip_tcp import inet_checksum, tcp_checksum


def build_client_hello(
    hostname: str,
    *,
    extra: bytes = b"",
    truncate: int | None = None,
    ech: bool = False,
    prefix_extension: bytes = b"",
) -> bytes:
    name = hostname.encode("ascii")
    sni_body = struct.pack("!HBH", 3 + len(name), 0, len(name)) + name
    extensions = prefix_extension + struct.pack("!HH", 0, len(sni_body)) + sni_body
    if ech:
        ech_body = b"\x00" * 10
        extensions += struct.pack("!HH", 0xFE0D, len(ech_body)) + ech_body
    hello = b"\x03\x03" + (b"\x11" * 32) + b"\x00" + struct.pack("!HH", 2, 0x1301) + b"\x01\x00"
    hello += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake + extra
    if truncate is not None:
        return record[:truncate]
    return record


def build_tcp_packet(
    payload: bytes,
    *,
    ip_version: int = 4,
    seq: int = 1000,
    flags: int = 0x18,
    window: int = 65535,
    ttl: int = 64,
    ident: int = 7,
    sport: int = 40000,
    dport: int = 443,
    src: str = "10.1.2.3",
    dst: str = "93.184.216.34",
    ipv4_options: bytes = b"",
    tcp_options: bytes = b"",
    mf: bool = False,
    frag_offset: int = 0,
    df: bool = True,
    ipv6_dest_options: bool = False,
) -> bytes:
    if len(tcp_options) % 4:
        tcp_options += b"\x01" * (4 - (len(tcp_options) % 4))
    data_offset = 5 + (len(tcp_options) // 4)
    tcp_header = struct.pack("!HHII", sport, dport, seq & 0xFFFFFFFF, 50)
    tcp_header += bytes([(data_offset << 4) & 0xFF, flags & 0xFF])
    tcp_header += struct.pack("!HHH", window & 0xFFFF, 0, 0)
    tcp_header += tcp_options
    segment = tcp_header + payload
    if ip_version == 4:
        if len(ipv4_options) % 4:
            ipv4_options += b"\x01" * (4 - (len(ipv4_options) % 4))
        ihl = 5 + (len(ipv4_options) // 4)
        total = (ihl * 4) + len(segment)
        frag = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag_offset & 0x1FFF)
        src_raw = socket.inet_aton(src)
        dst_raw = socket.inet_aton(dst)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            (4 << 4) | ihl,
            0,
            total,
            ident & 0xFFFF,
            frag,
            ttl & 0xFF,
            6,
            0,
            src_raw,
            dst_raw,
        )
        header += ipv4_options
        checksum = inet_checksum(header)
        header = header[:10] + struct.pack("!H", checksum) + header[12:]
        segment = segment[:16] + struct.pack("!H", tcp_checksum(src_raw, dst_raw, segment, 4)) + segment[18:]
        return header + segment
    src_raw = socket.inet_pton(socket.AF_INET6, src if ":" in src else "2001:db8::1")
    dst_raw = socket.inet_pton(socket.AF_INET6, dst if ":" in dst else "2001:db8::2")
    extension = b""
    next_header = 6
    if ipv6_dest_options:
        extension = bytes([6, 0]) + b"\x01" * 6
        next_header = 60
    payload_len = len(extension) + len(segment)
    header = struct.pack("!IHBB16s16s", 0x60000000, payload_len, next_header, ttl & 0xFF, src_raw, dst_raw)
    segment = segment[:16] + struct.pack("!H", tcp_checksum(src_raw, dst_raw, segment, 6)) + segment[18:]
    return header + extension + segment
