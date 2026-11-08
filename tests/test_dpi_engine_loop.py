"""WinDivert tutamacı sahteyle; gerçek sürücü açılmaz."""

from __future__ import annotations

import sys
import time

import pydivert
import pytest

from core.dpi_engine import TLS_FILTER, DpiEngine, ReinjectionGuard, TlsOptions
from core.errors import PlatformError
from tests.packet_factory import build_client_hello, build_tcp_packet

REAL_FILTER = TLS_FILTER


class FakeWinDivert:
    created: list[FakeWinDivert] = []

    def __init__(self, filter="true", layer=0, priority=0, flags=0, **kwargs) -> None:
        self.filter = filter
        self.layer = layer
        self.priority = priority
        self.flags = flags
        self.sent: list[tuple[bytes, bool]] = []
        self.queue: list = []
        self.closed = False
        FakeWinDivert.created.append(self)

    def open(self):
        return self

    def recv(self, timeout=None):
        if self.queue:
            return self.queue.pop(0)
        raise TimeoutError()

    def send(self, packet, recalculate_checksum=True):
        self.sent.append((bytes(packet.raw), bool(recalculate_checksum)))
        return len(packet.raw)

    def close(self) -> None:
        self.closed = True


def test_filter_guards_reinjection_terms() -> None:
    assert "outbound" in REAL_FILTER
    assert "tcp.DstPort == 443" in REAL_FILTER
    assert "tcp.PayloadLength > 0" in REAL_FILTER
    assert "!impostor" in REAL_FILTER
    assert "!loopback" in REAL_FILTER
    assert "udp" not in REAL_FILTER


def test_engine_refuses_to_open_off_windows() -> None:
    if sys.platform == "win32":
        pytest.skip("Windows")
    engine = DpiEngine(lambda level, message: None)
    with pytest.raises(PlatformError):
        engine.start(TlsOptions())


def test_engine_sends_split_with_pydivert_packet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    FakeWinDivert.created = []
    monkeypatch.setattr(pydivert, "WinDivert", FakeWinDivert)
    raw = build_tcp_packet(build_client_hello("example.com"))
    packet = pydivert.Packet(raw, interface=(7, 0), direction=pydivert.Direction.OUTBOUND)
    engine = DpiEngine(lambda level, message: None)
    original_init = FakeWinDivert.__init__

    def init_with_packet(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.queue.append(packet)

    monkeypatch.setattr(FakeWinDivert, "__init__", init_with_packet)
    engine.start(TlsOptions(fake_ttl=1))
    try:
        deadline = time.time() + 3
        while time.time() < deadline and (not FakeWinDivert.created or len(FakeWinDivert.created[-1].sent) < 3):
            time.sleep(0.02)
        handle = FakeWinDivert.created[-1]
        assert handle.filter == REAL_FILTER
        assert handle.priority == -30000
        assert len(handle.sent) >= 3
        assert handle.sent[0][1] is False
        assert handle.sent[1][1] is True
        assert handle.sent[2][1] is True
    finally:
        engine.stop()


def test_reinjection_guard_drops_the_third_copy() -> None:
    clock = {"now": 0.0}
    guard = ReinjectionGuard(maxlen=2, ttl=5, clock=lambda: clock["now"])
    guard.remember(b"one")
    guard.remember(b"two")
    guard.remember(b"three")
    assert guard.observe(b"one") == "new"
    assert guard.observe(b"three") == "forward"
    assert guard.observe(b"three") == "forward"
    assert guard.observe(b"three") == "drop"
    clock["now"] = 9
    assert guard.observe(b"three") == "new"
