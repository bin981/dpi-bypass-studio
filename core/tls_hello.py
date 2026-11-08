"""TLS ClientHello içinden SNI okuma.

Eksik, bölünmüş, çok kayıtlı veya bozuk el sıkışmalarında istisna yükseltmez.
Kayıt bu TCP kesiminde tam değilse yeniden birleştirme yapılmaz; çağıran
paketi olduğu gibi geçirir.
"""

from __future__ import annotations

from dataclasses import dataclass

ECH_EXTENSION = 0xFE0D
SNI_EXTENSION = 0x0000


@dataclass(frozen=True)
class SniInfo:
    status: str
    hostname: str | None = None
    start: int | None = None
    end: int | None = None
    ech: bool = False


def parse_sni(payload: bytes) -> SniInfo:
    if len(payload) < 5:
        return SniInfo("truncated")
    if payload[0] != 0x16:
        return SniInfo("not_handshake")
    version = int.from_bytes(payload[1:3], "big")
    if version < 0x0300 or version > 0x0304:
        return SniInfo("malformed")
    record_len = int.from_bytes(payload[3:5], "big")
    if record_len <= 0:
        return SniInfo("malformed")
    if 5 + record_len > len(payload):
        return SniInfo("truncated")
    body = payload[5 : 5 + record_len]
    if len(body) < 4:
        return SniInfo("truncated")
    if body[0] != 0x01:
        return SniInfo("not_client_hello")
    hello_len = int.from_bytes(body[1:4], "big")
    if hello_len <= 0 or 4 + hello_len > len(body):
        return SniInfo("truncated")
    return _parse_client_hello(body[4 : 4 + hello_len], base=9)


def _parse_client_hello(hello: bytes, base: int) -> SniInfo:
    if len(hello) < 35:
        return SniInfo("malformed")
    index = 34
    session_len = hello[index]
    index += 1
    if session_len > 32 or index + session_len > len(hello):
        return SniInfo("malformed")
    index += session_len
    if index + 2 > len(hello):
        return SniInfo("malformed")
    cipher_len = int.from_bytes(hello[index : index + 2], "big")
    index += 2
    if cipher_len < 2 or cipher_len % 2 or index + cipher_len > len(hello):
        return SniInfo("malformed")
    index += cipher_len
    if index + 1 > len(hello):
        return SniInfo("malformed")
    comp_len = hello[index]
    index += 1
    if comp_len < 1 or index + comp_len > len(hello):
        return SniInfo("malformed")
    index += comp_len
    if index == len(hello):
        return SniInfo("no_sni")
    if index + 2 > len(hello):
        return SniInfo("malformed")
    ext_total = int.from_bytes(hello[index : index + 2], "big")
    index += 2
    if index + ext_total > len(hello):
        return SniInfo("malformed")
    ext_end = index + ext_total
    ech = False
    found: SniInfo | None = None
    while index + 4 <= ext_end:
        ext_type = int.from_bytes(hello[index : index + 2], "big")
        ext_len = int.from_bytes(hello[index + 2 : index + 4], "big")
        index += 4
        if index + ext_len > ext_end:
            return SniInfo("malformed")
        data = hello[index : index + ext_len]
        if ext_type == ECH_EXTENSION:
            ech = True
        elif ext_type == SNI_EXTENSION and found is None:
            parsed = _parse_sni_extension(data, index + base)
            if parsed.status == "malformed":
                return SniInfo("malformed", ech=ech)
            if parsed.status == "ok":
                found = parsed
        index += ext_len
    if found is None or found.hostname is None or found.start is None or found.end is None:
        return SniInfo("no_sni", ech=ech)
    return SniInfo("ok", found.hostname, found.start, found.end, ech)


def _parse_sni_extension(data: bytes, data_base: int) -> SniInfo:
    if len(data) < 5:
        return SniInfo("malformed")
    list_len = int.from_bytes(data[0:2], "big")
    if list_len < 3 or 2 + list_len > len(data):
        return SniInfo("malformed")
    pos = 2
    end = 2 + list_len
    while pos + 3 <= end:
        name_type = data[pos]
        name_len = int.from_bytes(data[pos + 1 : pos + 3], "big")
        pos += 3
        if name_len <= 0 or pos + name_len > end:
            return SniInfo("malformed")
        if name_type == 0:
            raw_name = data[pos : pos + name_len]
            hostname = _decode_hostname(raw_name)
            if hostname is None:
                return SniInfo("malformed")
            return SniInfo("ok", hostname, data_base + pos, data_base + pos + name_len)
        pos += name_len
    return SniInfo("no_sni")


def _decode_hostname(raw_name: bytes) -> str | None:
    try:
        hostname = raw_name.decode("ascii")
    except UnicodeDecodeError:
        hostname = raw_name.decode("utf-8", errors="strict")
    except Exception:
        return None
    if not hostname or any(char in hostname for char in " \r\n\t\x00/\\"):
        return None
    return hostname
