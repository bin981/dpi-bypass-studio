"""Giden 443/TCP paketlerinde TLS ClientHello SNI parçalama.

Filtre, istenen eşleşmeyi ve WinDivert'in döngü korumasını birlikte taşır:
outbound and !impostor and !loopback and tcp.DstPort == 443 and tcp.PayloadLength > 0

Aynı tutamaç kendi gönderdiği paketi normalde yeniden görmez. Yine de !impostor,
düşük öncelik, kesilmiş ClientHello'yu yeniden bölmeme ve kısa süreli bir
gönderim önbelleği üst üste durur. Bozuk veya desteklenmeyen paket düşürülmez.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from core.divert_loop import DivertLoop
from core.ip_tcp import (
    ACK,
    CWR,
    ECE,
    FIN,
    PSH,
    RST,
    SYN,
    URG,
    parse_tcp_packet,
    rewrite_tcp,
    seq_add,
)
from core.profiles import host_matches
from core.tls_hello import parse_sni

TLS_FILTER = "outbound and !impostor and !loopback and tcp.DstPort == 443 and tcp.PayloadLength > 0"

_LOG_PASS_REASONS = {
    "truncated",
    "malformed",
    "no_sni",
    "sni_too_short",
    "allowlist",
    "syn",
    "fin",
    "rst",
    "fragment",
    "bad_fake_ttl",
    "bad_window",
}


@dataclass(frozen=True)
class TlsOptions:
    allowlist: tuple[str, ...] | None = None
    fake_ttl: int | None = None
    shrink_window: int | None = None


@dataclass(frozen=True)
class PlannedPacket:
    raw: bytes
    recalculate_checksum: bool
    kind: str


@dataclass(frozen=True)
class PlanResult:
    packets: tuple[PlannedPacket, ...]
    action: str
    reason: str
    sni: str | None
    ech: bool


@dataclass
class EngineStats:
    seen: int = 0
    split: int = 0
    passed: int = 0
    fake: int = 0
    errors: int = 0
    loops: int = 0


class ReinjectionGuard:
    """Yakın zamanda gönderdiğimiz ham paketleri tanır."""

    def __init__(self, maxlen: int = 4096, ttl: float = 3.0, clock: Callable[[], float] | None = None) -> None:
        self._maxlen = maxlen
        self._ttl = ttl
        self._clock = clock or time.monotonic
        self._seen: OrderedDict[bytes, float] = OrderedDict()
        self._hits: dict[bytes, int] = {}
        self.loops = 0
        self._lock = threading.Lock()

    def remember(self, raw: bytes) -> None:
        digest = hashlib.blake2s(raw).digest()
        now = self._clock()
        with self._lock:
            self._seen[digest] = now
            self._seen.move_to_end(digest)
            self._purge(now)

    def observe(self, raw: bytes) -> str:
        digest = hashlib.blake2s(raw).digest()
        now = self._clock()
        with self._lock:
            self._purge(now)
            if digest not in self._seen:
                return "new"
            hits = self._hits.get(digest, 0) + 1
            self._hits[digest] = hits
            if hits > 2:
                self.loops += 1
                return "drop"
            return "forward"

    def _purge(self, now: float) -> None:
        while self._seen:
            digest, seen_at = next(iter(self._seen.items()))
            expired = now - seen_at > self._ttl
            oversized = len(self._seen) > self._maxlen
            if not expired and not oversized:
                break
            self._seen.popitem(last=False)
            self._hits.pop(digest, None)


class PrivacySwitch:
    def __init__(self) -> None:
        self._hide = False
        self._lock = threading.Lock()

    def set_hide(self, hide: bool) -> None:
        with self._lock:
            self._hide = bool(hide)

    def mask(self, hostname: str | None) -> str:
        if not hostname:
            return ""
        with self._lock:
            hide = self._hide
        if hide:
            return f"<gizli {len(hostname)} bayt>"
        return hostname


def plan_tls_packets(raw: bytes, options: TlsOptions) -> PlanResult:
    """Her zaman en az bir paket döndürür. Boş dönüş trafiği düşürürdü."""

    def passthrough(reason: str, sni: str | None = None, ech: bool = False) -> PlanResult:
        return PlanResult((PlannedPacket(raw, True, "pass"),), "pass", reason, sni, ech)

    parsed = parse_tcp_packet(raw)
    if not parsed.rewriteable:
        return passthrough(parsed.reason)
    if parsed.dst_port != 443:
        return passthrough("wrong_port")
    info = parse_sni(parsed.payload)
    if info.status != "ok" or info.start is None or info.end is None or not info.hostname:
        return passthrough(info.status, info.hostname, info.ech)
    if options.allowlist is not None and not host_matches(info.hostname, options.allowlist):
        return passthrough("allowlist", info.hostname, info.ech)
    span = info.end - info.start
    if span < 2:
        return passthrough("sni_too_short", info.hostname, info.ech)
    midpoint = info.start + (span // 2)
    if not (info.start < midpoint < info.end) or midpoint >= len(parsed.payload):
        return passthrough("sni_too_short", info.hostname, info.ech)
    if options.fake_ttl is not None and not 1 <= options.fake_ttl <= 8:
        return passthrough("bad_fake_ttl", info.hostname, info.ech)
    if options.shrink_window is not None and not 1 <= options.shrink_window <= 65535:
        return passthrough("bad_window", info.hostname, info.ech)

    first = parsed.payload[:midpoint]
    second = parsed.payload[midpoint:]
    flags_first = parsed.flags & ~(PSH | URG | FIN | SYN | RST)
    flags_second = parsed.flags & ~(URG | FIN | SYN | RST | ECE | CWR)
    if parsed.flags & ACK:
        flags_first |= ACK
        flags_second |= ACK
    window_first = parsed.window if options.shrink_window is None else options.shrink_window
    seq_first = parsed.seq
    seq_second = seq_add(seq_first, len(first))
    common = {
        "ttl": parsed.ttl,
    }
    segment_one = rewrite_tcp(
        parsed,
        payload=first,
        seq=seq_first,
        flags=flags_first,
        window=window_first,
        ident=parsed.ident,
        bad_tcp_checksum=False,
        **common,
    )
    segment_two = rewrite_tcp(
        parsed,
        payload=second,
        seq=seq_second,
        flags=flags_second,
        window=parsed.window,
        ident=(parsed.ident + 1) & 0xFFFF,
        bad_tcp_checksum=False,
        **common,
    )
    planned: list[PlannedPacket] = []
    if options.fake_ttl is not None:
        fake = rewrite_tcp(
            parsed,
            payload=first,
            seq=seq_first,
            flags=flags_first,
            window=window_first,
            ttl=options.fake_ttl,
            ident=(parsed.ident + 7) & 0xFFFF,
            bad_tcp_checksum=True,
        )
        planned.append(PlannedPacket(fake, False, "fake"))
    planned.append(PlannedPacket(segment_one, True, "seg1"))
    planned.append(PlannedPacket(segment_two, True, "seg2"))
    return PlanResult(tuple(planned), "split", "split", info.hostname, info.ech)


class DpiEngine:
    def __init__(
        self,
        log: Callable[[str, str], None],
        privacy: PrivacySwitch | None = None,
        guard: ReinjectionGuard | None = None,
    ) -> None:
        self._log = log
        self.privacy = privacy or PrivacySwitch()
        self.guard = guard or ReinjectionGuard()
        self._options = TlsOptions()
        self._stats = EngineStats()
        self._stats_lock = threading.Lock()
        self._loop = DivertLoop("dpi-tls", TLS_FILTER, self._on_packet, log)

    @property
    def filter(self) -> str:
        return TLS_FILTER

    def stats(self) -> EngineStats:
        with self._stats_lock:
            snapshot = EngineStats(**self._stats.__dict__)
        snapshot.loops = self.guard.loops
        return snapshot

    def start(self, options: TlsOptions) -> None:
        self._options = options
        self._loop.start()
        self._log(
            "bilgi",
            "DPI motoru açıldı. Filtre: giden, impostor değil, loopback değil, "
            "tcp.DstPort == 443, tcp.PayloadLength > 0. QUIC/UDP engellenmez.",
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._loop.stop(timeout)
        self._log("bilgi", "DPI motoru durdu.")

    def _on_packet(self, handle: Any, packet: Any) -> None:
        raw = bytes(packet.raw)
        with self._stats_lock:
            self._stats.seen += 1
        if getattr(packet, "is_impostor", False):
            self._forward(handle, packet, count_pass=True)
            return
        decision = self.guard.observe(raw)
        if decision == "drop":
            with self._stats_lock:
                self._stats.loops += 1
            self._log("uyari", "Yeniden enjeksiyon döngüsü algılandı; aynı paket üçüncü kez iletilmedi.")
            return
        if decision == "forward":
            self._forward(handle, packet, count_pass=True)
            return
        try:
            plan = plan_tls_packets(raw, self._options)
        except Exception as exc:
            with self._stats_lock:
                self._stats.errors += 1
            self._log("hata", f"Paket planı kurulamadı, özgün paket geçiriliyor: {exc}")
            self._forward(handle, packet, count_pass=True)
            return
        self._report(plan)
        if plan.action != "split":
            self._forward(handle, packet, count_pass=True)
            return
        sent = 0
        try:
            import pydivert

            for item in plan.packets:
                clone = pydivert.Packet(item.raw, interface=packet.interface, direction=packet.direction)
                handle.send(clone, recalculate_checksum=item.recalculate_checksum)
                self.guard.remember(bytes(clone.raw))
                sent += 1
                if item.kind == "fake":
                    with self._stats_lock:
                        self._stats.fake += 1
            with self._stats_lock:
                self._stats.split += 1
        except Exception as exc:
            with self._stats_lock:
                self._stats.errors += 1
            self._log("hata", f"Parçalanmış paket gönderilemedi: {exc}")
            if sent == 0:
                self._forward(handle, packet, count_pass=False)

    def _forward(self, handle: Any, packet: Any, *, count_pass: bool) -> None:
        handle.send(packet, recalculate_checksum=True)
        self.guard.remember(bytes(packet.raw))
        if count_pass:
            with self._stats_lock:
                self._stats.passed += 1

    def _report(self, plan: PlanResult) -> None:
        if plan.action == "split":
            shown = self.privacy.mask(plan.sni)
            ech = " ECH eklentisi var; görünen SNI gerçek ad olmayabilir." if plan.ech else ""
            self._log("sni", f"SNI parçalandı: {shown}.{ech}")
            return
        if plan.reason not in _LOG_PASS_REASONS:
            return
        if plan.sni:
            self._log("bilgi", f"Geçirildi ({plan.reason}): {self.privacy.mask(plan.sni)}")
        else:
            self._log("bilgi", f"Geçirildi ({plan.reason})")

