"""Düz HTTP Host başlığında belirleyici büyük/küçük harf karıştırma.

Yalnızca 80/TCP ve tam bir HTTP istek başlığı için çalışır. TLS (0x16) dahil
şifreli yükler değiştirilmez. Aynı giriş her zaman aynı çıkışı üretir; böylece
TCP yeniden iletimi farklı baytlara dönüşmez.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from core.divert_loop import DivertLoop
from core.dpi_engine import PrivacySwitch, ReinjectionGuard
from core.ip_tcp import parse_tcp_packet, rewrite_tcp
from core.profiles import host_matches

HTTP_FILTER = "outbound and !impostor and !loopback and tcp.DstPort == 80 and tcp.PayloadLength > 0"

_REQUEST = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT) ")
_HOST_LINE = re.compile(r"^(Host)(:[ \t]*)([^\r\n]+)$", re.IGNORECASE)


@dataclass(frozen=True)
class HttpOptions:
    allowlist: tuple[str, ...] | None = None


def mix_alpha(text: str) -> str:
    pieces: list[str] = []
    alpha_index = 0
    for char in text:
        if char.isalpha():
            pieces.append(char.upper() if alpha_index % 2 == 0 else char.lower())
            alpha_index += 1
        else:
            pieces.append(char)
    return "".join(pieces)


def mangle_http_payload(payload: bytes, allowlist: tuple[str, ...] | None) -> tuple[bytes, str | None]:
    if not payload or payload[0] == 0x16:
        return payload, None
    separator = payload.find(b"\r\n\r\n")
    if separator < 0:
        return payload, None
    try:
        head = payload[:separator].decode("iso-8859-1")
    except Exception:
        return payload, None
    lines = head.split("\r\n")
    if not lines or _REQUEST.match(lines[0]) is None:
        return payload, None
    changed = False
    logged_host: str | None = None
    rewritten: list[str] = []
    for line in lines:
        match = _HOST_LINE.match(line)
        if match is None:
            rewritten.append(line)
            continue
        raw_value = match.group(3)
        hostname = _hostname_token(raw_value.strip())
        if hostname is None:
            rewritten.append(line)
            continue
        if allowlist is not None and not host_matches(hostname, allowlist):
            rewritten.append(line)
            continue
        mixed = f"{mix_alpha('Host')}{match.group(2)}{mix_alpha(raw_value)}"
        if mixed != line:
            changed = True
            logged_host = hostname
        rewritten.append(mixed)
    if not changed:
        return payload, None
    new_head = "\r\n".join(rewritten).encode("iso-8859-1")
    if len(new_head) != separator:
        return payload, None
    return new_head + payload[separator:], logged_host


def _hostname_token(value: str) -> str | None:
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None
        return value[1:end]
    return value.split(":", 1)[0]


def rewrite_http_packet(raw: bytes, allowlist: tuple[str, ...] | None) -> tuple[bytes, str | None]:
    parsed = parse_tcp_packet(raw)
    if not parsed.rewriteable or parsed.dst_port != 80:
        return raw, None
    new_payload, host = mangle_http_payload(parsed.payload, allowlist)
    if host is None or new_payload == parsed.payload:
        return raw, None
    updated = rewrite_tcp(
        parsed,
        payload=new_payload,
        seq=parsed.seq,
        flags=parsed.flags,
        window=parsed.window,
        ttl=parsed.ttl,
        ident=parsed.ident,
        bad_tcp_checksum=False,
    )
    return updated, host


class HttpCaseEngine:
    def __init__(self, log: Callable[[str, str], None], privacy: PrivacySwitch | None = None) -> None:
        self._log = log
        self.privacy = privacy or PrivacySwitch()
        self._options = HttpOptions()
        self.guard = ReinjectionGuard()
        self._loop = DivertLoop("dpi-http", HTTP_FILTER, self._on_packet, log)

    @property
    def filter(self) -> str:
        return HTTP_FILTER

    def start(self, options: HttpOptions) -> None:
        self._options = options
        self._loop.start()
        self._log("bilgi", "HTTP Host karıştırma yalnızca 80/TCP düz isteklerde açık. 443 yükü değiştirilmez.")

    def stop(self, timeout: float = 5.0) -> None:
        self._loop.stop(timeout)

    def _on_packet(self, handle: Any, packet: Any) -> None:
        raw = bytes(packet.raw)
        decision = self.guard.observe(raw)
        if decision == "drop":
            self._log("uyari", "HTTP yeniden enjeksiyon döngüsü algılandı; paket üçüncü kez iletilmedi.")
            return
        if decision == "forward" or getattr(packet, "is_impostor", False):
            self._send_original(handle, packet)
            return
        try:
            updated, host = rewrite_http_packet(raw, self._options.allowlist)
        except Exception as exc:
            self._log("hata", f"HTTP paketi geçiriliyor: {exc}")
            self._send_original(handle, packet)
            return
        if host is None or updated == raw:
            self._send_original(handle, packet)
            return
        try:
            import pydivert

            clone = pydivert.Packet(updated, interface=packet.interface, direction=packet.direction)
            handle.send(clone, recalculate_checksum=True)
            self.guard.remember(bytes(clone.raw))
            self._log("sni", f"HTTP Host karıştırıldı: {self.privacy.mask(host)}")
        except Exception as exc:
            self._log("hata", f"HTTP paketi gönderilemedi, özgün paket geri veriliyor: {exc}")
            self._send_original(handle, packet)

    def _send_original(self, handle: Any, packet: Any) -> None:
        handle.send(packet, recalculate_checksum=True)
        self.guard.remember(bytes(packet.raw))
