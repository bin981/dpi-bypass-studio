"""IPv4/IPv6 TCP ayrıştırma ve yeniden yazma.

Uzunluk, sıra numarası, bayrak, TTL/hop limit ve checksum alanları burada
güncellenir. Böylece parçalama, Windows sürücüsü olmadan doğrulanabilir.
WinDivert gönderiminde gerçek paketler için checksum ayrıca yeniden hesaplanır;
sahte paketin bozuk TCP checksum'ı ise korunur.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

TCP_PROTOCOL = 6
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

_IPV6_WALK = {0, 43, 44, 50, 51, 60}


def seq_add(seq: int, delta: int) -> int:
    """TCP sıra numarasını 32 bit sarmalayarak ilerletir."""
    return (int(seq) + int(delta)) & 0xFFFFFFFF


def inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_checksum(src: bytes, dst: bytes, segment: bytes, ip_version: int) -> int:
    if len(segment) < 20:
        raise ValueError("TCP kesimi çok kısa")
    folded = bytearray(segment)
    folded[16:18] = b"\x00\x00"
    if len(folded) % 2:
        folded.append(0)
    length = len(segment)
    if ip_version == 4:
        if len(src) != 4 or len(dst) != 4:
            raise ValueError("IPv4 sözde başlık adresleri 4 bayt olmalı")
        pseudo = src + dst + struct.pack("!BBH", 0, TCP_PROTOCOL, length)
    elif ip_version == 6:
        if len(src) != 16 or len(dst) != 16:
            raise ValueError("IPv6 sözde başlık adresleri 16 bayt olmalı")
        pseudo = src + dst + struct.pack("!IBBB", length, 0, 0, TCP_PROTOCOL)
    else:
        raise ValueError("desteklenmeyen IP sürümü")
    return inet_checksum(pseudo + bytes(folded))


def tcp_checksum_ok(src: bytes, dst: bytes, segment: bytes, ip_version: int) -> bool:
    if len(segment) < 18:
        return False
    expected = tcp_checksum(src, dst, segment, ip_version)
    actual = struct.unpack_from("!H", segment, 16)[0]
    return expected == actual


def ipv4_checksum_ok(header: bytes) -> bool:
    if len(header) < 20 or len(header) % 4:
        return False
    return inet_checksum(header) == 0


@dataclass
class ParsedTcp:
    rewriteable: bool
    reason: str
    raw: bytes
    ip_version: int = 0
    tcp_offset: int = 0
    tcp_header_len: int = 0
    ip_header_len: int = 0
    seq: int = 0
    ack: int = 0
    flags: int = 0
    window: int = 0
    payload: bytes = b""
    ttl: int = 0
    ident: int = 0
    src: bytes = b""
    dst: bytes = b""
    src_port: int = 0
    dst_port: int = 0

    @property
    def src_text(self) -> str:
        return _format_addr(self.ip_version, self.src)

    @property
    def dst_text(self) -> str:
        return _format_addr(self.ip_version, self.dst)


def _format_addr(version: int, raw: bytes) -> str:
    if version == 4 and len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    if version == 6 and len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return ""


def _fail(reason: str, raw: bytes, ip_version: int = 0) -> ParsedTcp:
    return ParsedTcp(rewriteable=False, reason=reason, raw=bytes(raw), ip_version=ip_version)


def parse_tcp_packet(raw: bytes) -> ParsedTcp:
    """IP paketini TCP görünümüne ayırır. Bozuk pakette istisna yükseltmez."""
    if len(raw) < 20:
        return _fail("truncated", raw)
    version = raw[0] >> 4
    if version == 4:
        return _parse_ipv4(raw)
    if version == 6:
        return _parse_ipv6(raw)
    return _fail("not_ip", raw)


def _parse_ipv4(raw: bytes) -> ParsedTcp:
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl:
        return _fail("truncated", raw, 4)
    total = struct.unpack_from("!H", raw, 2)[0]
    if total < ihl or total > len(raw):
        return _fail("truncated", raw, 4)
    frag = struct.unpack_from("!H", raw, 6)[0]
    if (frag & 0x1FFF) or (frag & 0x2000):
        return _fail("fragment", raw[:total], 4)
    if raw[9] != TCP_PROTOCOL:
        return _fail("not_tcp", raw[:total], 4)
    return _finish_tcp(
        raw=raw[:total],
        version=4,
        tcp_offset=ihl,
        ip_header_len=ihl,
        src=bytes(raw[12:16]),
        dst=bytes(raw[16:20]),
        ttl=raw[8],
        ident=struct.unpack_from("!H", raw, 4)[0],
        end=total,
    )


def _parse_ipv6(raw: bytes) -> ParsedTcp:
    if len(raw) < 40:
        return _fail("truncated", raw, 6)
    payload_len = struct.unpack_from("!H", raw, 4)[0]
    end = 40 + payload_len
    if end > len(raw) or payload_len < 0:
        return _fail("truncated", raw, 6)
    nxt = raw[6]
    offset = 40
    while nxt in _IPV6_WALK:
        if nxt in (44, 50):
            return _fail("fragment" if nxt == 44 else "unsupported_ext", raw[:end], 6)
        if offset + 2 > end:
            return _fail("truncated", raw[:end], 6)
        hdr_len = (raw[offset + 1] + 2) * 4 if nxt == 51 else (raw[offset + 1] + 1) * 8
        if hdr_len < 8 or offset + hdr_len > end:
            return _fail("truncated", raw[:end], 6)
        nxt = raw[offset]
        offset += hdr_len
    if nxt != TCP_PROTOCOL:
        return _fail("not_tcp", raw[:end], 6)
    return _finish_tcp(
        raw=raw[:end],
        version=6,
        tcp_offset=offset,
        ip_header_len=40,
        src=bytes(raw[8:24]),
        dst=bytes(raw[24:40]),
        ttl=raw[7],
        ident=0,
        end=end,
    )


def _finish_tcp(
    *,
    raw: bytes,
    version: int,
    tcp_offset: int,
    ip_header_len: int,
    src: bytes,
    dst: bytes,
    ttl: int,
    ident: int,
    end: int,
) -> ParsedTcp:
    if tcp_offset + 20 > end:
        return _fail("truncated", raw, version)
    tcp_header_len = ((raw[tcp_offset + 12] >> 4) & 0x0F) * 4
    if tcp_header_len < 20 or tcp_offset + tcp_header_len > end:
        return _fail("bad_tcp_header", raw, version)
    flags = raw[tcp_offset + 13]
    payload = bytes(raw[tcp_offset + tcp_header_len : end])
    rewriteable = True
    reason = "ok"
    if flags & SYN:
        rewriteable, reason = False, "syn"
    elif flags & FIN:
        rewriteable, reason = False, "fin"
    elif flags & RST:
        rewriteable, reason = False, "rst"
    elif not payload:
        rewriteable, reason = False, "empty"
    return ParsedTcp(
        rewriteable=rewriteable,
        reason=reason,
        raw=bytes(raw),
        ip_version=version,
        tcp_offset=tcp_offset,
        tcp_header_len=tcp_header_len,
        ip_header_len=ip_header_len,
        seq=struct.unpack_from("!I", raw, tcp_offset + 4)[0],
        ack=struct.unpack_from("!I", raw, tcp_offset + 8)[0],
        flags=flags,
        window=struct.unpack_from("!H", raw, tcp_offset + 14)[0],
        payload=payload,
        ttl=ttl,
        ident=ident,
        src=src,
        dst=dst,
        src_port=struct.unpack_from("!H", raw, tcp_offset)[0],
        dst_port=struct.unpack_from("!H", raw, tcp_offset + 2)[0],
    )


def rewrite_tcp(
    parsed: ParsedTcp,
    *,
    payload: bytes,
    seq: int,
    flags: int,
    window: int,
    ttl: int,
    ident: int | None = None,
    bad_tcp_checksum: bool = False,
) -> bytes:
    """Başlıkları kopyalayıp TCP yükünü ve ilgili alanları yeniden yazar."""
    if parsed.ip_version not in (4, 6) or parsed.tcp_header_len < 20:
        raise ValueError("yeniden yazılamayan paket")
    header_end = parsed.tcp_offset + parsed.tcp_header_len
    buf = bytearray(parsed.raw[:header_end])
    buf.extend(payload)
    struct.pack_into("!I", buf, parsed.tcp_offset + 4, seq_add(seq, 0))
    buf[parsed.tcp_offset + 13] = flags & 0xFF
    struct.pack_into("!H", buf, parsed.tcp_offset + 14, window & 0xFFFF)
    if parsed.ip_version == 4:
        struct.pack_into("!H", buf, 2, len(buf) & 0xFFFF)
        buf[8] = ttl & 0xFF
        struct.pack_into("!H", buf, 4, (parsed.ident if ident is None else ident) & 0xFFFF)
        buf[10:12] = b"\x00\x00"
        struct.pack_into("!H", buf, 10, inet_checksum(bytes(buf[: parsed.ip_header_len])))
        src = bytes(buf[12:16])
        dst = bytes(buf[16:20])
        segment = bytes(buf[parsed.tcp_offset :])
        checksum = tcp_checksum(src, dst, segment, 4)
    else:
        struct.pack_into("!H", buf, 4, (len(buf) - 40) & 0xFFFF)
        buf[7] = ttl & 0xFF
        src = bytes(buf[8:24])
        dst = bytes(buf[24:40])
        segment = bytes(buf[parsed.tcp_offset :])
        checksum = tcp_checksum(src, dst, segment, 6)
    if bad_tcp_checksum:
        checksum ^= 0xFFFF
    struct.pack_into("!H", buf, parsed.tcp_offset + 16, checksum)
    return bytes(buf)
