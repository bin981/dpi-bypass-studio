"""Koyu tema masaüstü penceresi.

Tk çağrıları ana iş parçacığında kalır. Ağ işi iş parçacığındadır ve sonuçlar
kuyrukla geri gelir. Pencereyi açmak start() çağırmaz.
"""

from __future__ import annotations

import json
import queue
import sys
import threading
from pathlib import Path
from tkinter import messagebox

import customtkinter as ctk

from core.conn_test import ProbeResult, run_probes
from core.doh import PROVIDERS
from core.lifecycle import Controller
from core.profiles import PROFILES, StartConfig
from core.system_net import default_journal_path
from ui.strings import APP_TITLE, LIMITATIONS, RECOVERY_HINT, SUBTITLE, TRAY_MISSING

FONT = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"

BG = "#0e141b"
CARD = "#17212b"
LINE = "#2a394a"
TEXT = "#e7eef6"
MUTED = "#9aafc3"
ACCENT = "#3ecfb2"
START = "#1f8a70"
START_HOVER = "#176955"
STOP = "#8f2d2d"
STOP_HOVER = "#742424"
WARN_BG = "#3a2e1a"
WARN_FG = "#f3d7a1"
LOG_BG = "#090d12"
LOG_FG = "#d5e6df"


class AppWindow(ctk.CTk):
    def __init__(
        self,
        controller: Controller,
        *,
        enable_tray: bool = True,
        prefs_path: Path | None = None,
    ) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        super().__init__()
        self.controller = controller
        self.prefs_path = prefs_path or (default_journal_path().parent / "ui_prefs.json")
        self.queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._exit_after = False
        self._destroyed = False
        self._tray_ok = False
        self._tray = None
        self._test_cancel = threading.Event()
        self._test_running = False
        self._prefs = _load_prefs(self.prefs_path)
        self._log_lines = 0

        self.title(APP_TITLE)
        self.geometry("1120x760")
        self.minsize(920, 640)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self._build_header()
        self._build_controls()
        self._build_banner()
        self._build_tabs()
        self._build_footer()
        self._load_existing_log()
        self._refresh_profile_text()
        self._apply_state_buttons()
        if self.controller.net.has_dirty_journal():
            self._show_recovery(self.controller.net.describe())
        if enable_tray:
            self.after(200, self._start_tray)
        self.after(120, self._poll)

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=BG)
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 6))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text=APP_TITLE,
            font=ctk.CTkFont(family=FONT, size=26, weight="bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        self.state_label = ctk.CTkLabel(
            header,
            text="Durum: Hazır — ağ ayarları değiştirilmedi",
            font=ctk.CTkFont(family=FONT, size=16, weight="bold"),
            text_color=ACCENT,
            anchor="e",
        )
        self.state_label.grid(row=0, column=1, sticky="e", padx=(12, 0))
        ctk.CTkLabel(
            header,
            text=SUBTITLE,
            font=ctk.CTkFont(family=FONT, size=13),
            text_color=MUTED,
            wraplength=1040,
            justify="left",
            anchor="w",
        ).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))

    def _build_controls(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=CARD, corner_radius=14)
        bar.grid(row=1, column=0, sticky="ew", padx=20, pady=8)
        bar.grid_columnconfigure(2, weight=1)
        self.start_button = ctk.CTkButton(
            bar,
            text="Başlat",
            height=72,
            width=220,
            font=ctk.CTkFont(family=FONT, size=24, weight="bold"),
            fg_color=START,
            hover_color=START_HOVER,
            command=self._on_start,
        )
        self.start_button.grid(row=0, column=0, rowspan=2, padx=16, pady=16, sticky="nsw")
        self.stop_button = ctk.CTkButton(
            bar,
            text="Durdur",
            height=72,
            width=180,
            font=ctk.CTkFont(family=FONT, size=22, weight="bold"),
            fg_color=STOP,
            hover_color=STOP_HOVER,
            command=self._on_stop,
        )
        self.stop_button.grid(row=0, column=1, rowspan=2, padx=(0, 16), pady=16, sticky="nsw")
        ctk.CTkLabel(bar, text="Profil", text_color=MUTED, anchor="w").grid(row=0, column=2, sticky="sw", padx=8)
        self.profile_menu = ctk.CTkOptionMenu(
            bar,
            values=[profile.title for profile in PROFILES.values()],
            command=self._on_profile,
            font=ctk.CTkFont(family=FONT, size=14),
            fg_color=BG,
            button_color=LINE,
            button_hover_color=ACCENT,
            width=360,
        )
        self.profile_menu.grid(row=1, column=2, sticky="ew", padx=8, pady=(0, 16))
        ctk.CTkLabel(bar, text="DoH", text_color=MUTED, anchor="w").grid(row=0, column=3, sticky="sw", padx=8)
        self.provider_menu = ctk.CTkOptionMenu(
            bar,
            values=[item.label for item in PROVIDERS.values()],
            command=lambda _choice: self._save_prefs(),
            font=ctk.CTkFont(family=FONT, size=14),
            fg_color=BG,
            button_color=LINE,
            button_hover_color=ACCENT,
            width=180,
        )
        self.provider_menu.grid(row=1, column=3, sticky="ew", padx=(8, 16), pady=(0, 16))
        self._select_saved_profile()

    def _build_banner(self) -> None:
        self.banner = ctk.CTkFrame(self, fg_color=WARN_BG, corner_radius=10)
        self.banner.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 8))
        self.banner.grid_columnconfigure(0, weight=1)
        self.banner_label = ctk.CTkLabel(
            self.banner,
            text="",
            text_color=WARN_FG,
            justify="left",
            anchor="w",
            wraplength=980,
            font=ctk.CTkFont(family=FONT, size=13),
        )
        self.banner_label.grid(row=0, column=0, sticky="ew", padx=12, pady=10)
        self.recover_button = ctk.CTkButton(
            self.banner,
            text="Kayıtlı DNS ayarlarını geri yükle",
            command=self._on_recover,
            fg_color=ACCENT,
            hover_color="#2aa892",
            text_color="#06211c",
        )
        self.banner.grid_remove()

    def _build_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(self, fg_color=CARD, segmented_button_fg_color=BG, segmented_button_selected_color=LINE)
        self.tabs.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 8))
        for name in ("Günlük", "Bağlantı testi", "Seçenekler", "Sınırlamalar"):
            self.tabs.add(name)
        self._build_log_tab(self.tabs.tab("Günlük"))
        self._build_test_tab(self.tabs.tab("Bağlantı testi"))
        self._build_options_tab(self.tabs.tab("Seçenekler"))
        self._build_limits_tab(self.tabs.tab("Sınırlamalar"))

    def _build_log_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        self.privacy_var = ctk.BooleanVar(value=bool(self._prefs.get("hide_sni", False)))
        ctk.CTkSwitch(
            row,
            text="SNI adlarını gizle (yeni satırlar)",
            variable=self.privacy_var,
            command=self._on_privacy,
            font=ctk.CTkFont(family=FONT, size=13),
        ).pack(side="left", padx=6)
        ctk.CTkButton(row, text="Günlüğü temizle", width=140, command=self._clear_log, fg_color=LINE).pack(side="right", padx=6)
        self.log_box = ctk.CTkTextbox(
            tab,
            font=ctk.CTkFont(family=MONO, size=13),
            fg_color=LOG_BG,
            text_color=LOG_FG,
            wrap="word",
            activate_scrollbars=True,
        )
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.log_box.configure(state="disabled")

    def _build_test_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(
            tab,
            text=(
                "Discord, Roblox ve birkaç yaygın site için DNS, TCP ve TLS gerçekten ölçülür. "
                "Yeşil bir «engel aşıldı» durumu yoktur. TLS olması bypass kanıtı değildir."
            ),
            text_color=MUTED,
            wraplength=980,
            justify="left",
            font=ctk.CTkFont(family=FONT, size=13),
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 4))
        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        self.test_button = ctk.CTkButton(actions, text="Ölçümü başlat", command=self._on_test, fg_color=START, hover_color=START_HOVER)
        self.test_button.pack(side="left", padx=6)
        self.cancel_test_button = ctk.CTkButton(
            actions, text="Ölçümü iptal et", command=self._cancel_test, fg_color=LINE, state="disabled"
        )
        self.cancel_test_button.pack(side="left", padx=6)
        self.test_status = ctk.CTkLabel(actions, text="Henüz ölçüm yok.", text_color=MUTED)
        self.test_status.pack(side="left", padx=12)
        self.test_list = ctk.CTkScrollableFrame(tab, fg_color=BG)
        self.test_list.grid(row=2, column=0, sticky="nsew", padx=8, pady=8)
        self.test_list.grid_columnconfigure(0, weight=1)

    def _build_options_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll.grid(row=0, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)
        self.profile_summary = ctk.CTkLabel(
            scroll,
            text="",
            justify="left",
            anchor="w",
            wraplength=960,
            text_color=TEXT,
            font=ctk.CTkFont(family=FONT, size=14),
        )
        self.profile_summary.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        self.risk_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            scroll,
            text="Deneysel ve doğrulanmamış seçeneklerin bağlantıyı bozabileceğini anlıyorum",
            variable=self.risk_var,
            font=ctk.CTkFont(family=FONT, size=13),
        ).grid(row=1, column=0, sticky="w", padx=8, pady=6)
        self.fake_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(scroll, text="Düşük TTL sahte paket (1–8, deneysel)", variable=self.fake_var, command=self._save_prefs).grid(
            row=2, column=0, sticky="w", padx=8, pady=4
        )
        self.fake_entry = ctk.CTkEntry(scroll, width=80, placeholder_text="1")
        self.fake_entry.grid(row=3, column=0, sticky="w", padx=28, pady=4)
        self.fake_entry.insert(0, "1")
        self.shrink_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(
            scroll,
            text="İlk kesimde TCP penceresini küçült (1–64, deneysel)",
            variable=self.shrink_var,
            command=self._save_prefs,
        ).grid(row=4, column=0, sticky="w", padx=8, pady=4)
        self.shrink_entry = ctk.CTkEntry(scroll, width=80, placeholder_text="4")
        self.shrink_entry.grid(row=5, column=0, sticky="w", padx=28, pady=4)
        self.shrink_entry.insert(0, "4")
        self.http_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(
            scroll,
            text="Düz HTTP Host harf karıştırma (yalnız 80/TCP, 443'e dokunmaz)",
            variable=self.http_var,
            command=self._save_prefs,
        ).grid(row=6, column=0, sticky="w", padx=8, pady=4)
        self.allow_label = ctk.CTkLabel(
            scroll,
            text="",
            justify="left",
            anchor="w",
            wraplength=960,
            text_color=MUTED,
        )
        self.allow_label.grid(row=7, column=0, sticky="ew", padx=8, pady=8)
        ctk.CTkButton(
            scroll,
            text="Bağdaştırıcıları oku (yalnızca okuma)",
            command=self._read_adapters,
            fg_color=LINE,
        ).grid(row=8, column=0, sticky="w", padx=8, pady=8)
        self.adapter_label = ctk.CTkLabel(
            scroll,
            text="Bağdaştırıcı listesi henüz okunmadı. Okumak DNS ayarını değiştirmez.",
            justify="left",
            anchor="w",
            wraplength=960,
            text_color=MUTED,
        )
        self.adapter_label.grid(row=9, column=0, sticky="ew", padx=8, pady=(0, 12))
        self._apply_saved_toggles()

    def _build_limits_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        box = ctk.CTkTextbox(tab, font=ctk.CTkFont(family=FONT, size=14), wrap="word", fg_color=BG, text_color=TEXT)
        box.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        box.insert("end", LIMITATIONS)
        box.configure(state="disabled")

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, fg_color=BG)
        footer.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 14))
        footer.grid_columnconfigure(0, weight=1)
        self.stats_label = ctk.CTkLabel(footer, text="İstatistik bekleniyor.", text_color=MUTED, anchor="w")
        self.stats_label.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(footer, text="Tepsiye küçült", command=self._hide_to_tray, fg_color=LINE, width=140).grid(
            row=0, column=1, padx=6
        )
        ctk.CTkButton(
            footer,
            text="Çıkış ve geri yükle",
            command=self._request_exit,
            fg_color=STOP,
            hover_color=STOP_HOVER,
            width=170,
        ).grid(row=0, column=2, padx=6)

    def _select_saved_profile(self) -> None:
        wanted = str(self._prefs.get("profile_id") or "standard")
        profile = PROFILES.get(wanted, PROFILES["standard"])
        self.profile_menu.set(profile.title)
        provider_id = str(self._prefs.get("provider") or "cloudflare")
        provider = PROVIDERS.get(provider_id, PROVIDERS["cloudflare"])
        self.provider_menu.set(provider.label)

    def _apply_saved_toggles(self) -> None:
        profile = self._current_profile()
        self.fake_var.set(profile.fake_ttl is not None or bool(self._prefs.get("fake_ttl_enabled", False)))
        self.shrink_var.set(bool(self._prefs.get("shrink_enabled", False)))
        self.http_var.set(bool(self._prefs.get("http_host_case", False)))
        if profile.fake_ttl is not None:
            self.fake_entry.delete(0, "end")
            self.fake_entry.insert(0, str(profile.fake_ttl))
        self._refresh_profile_text()

    def _current_profile(self):
        title = self.profile_menu.get()
        for profile in PROFILES.values():
            if profile.title == title:
                return profile
        return PROFILES["standard"]

    def _current_provider_id(self) -> str:
        label = self.provider_menu.get()
        for provider in PROVIDERS.values():
            if provider.label == label:
                return provider.id
        return "cloudflare"

    def _on_profile(self, _title: str) -> None:
        profile = self._current_profile()
        self.fake_var.set(profile.fake_ttl is not None)
        self.shrink_var.set(profile.shrink_window is not None)
        self.http_var.set(profile.http_host_case)
        if profile.fake_ttl is not None:
            self.fake_entry.delete(0, "end")
            self.fake_entry.insert(0, str(profile.fake_ttl))
        self.risk_var.set(False)
        self._refresh_profile_text()
        self._save_prefs()

    def _refresh_profile_text(self) -> None:
        profile = self._current_profile()
        self.profile_summary.configure(text=profile.summary)
        if profile.allowlist:
            names = ", ".join(profile.allowlist)
            self.allow_label.configure(text=f"Bu profil yalnızca şu adlarda parçalar: {names}")
        else:
            self.allow_label.configure(text="Bu profil, SNI'si okunabilen ClientHello paketlerini adres süzmeden ele alır.")

    def _collect_config(self) -> StartConfig:
        return StartConfig(
            profile_id=self._current_profile().id,
            provider=self._current_provider_id(),
            risk_accepted=bool(self.risk_var.get()),
            fake_ttl_enabled=bool(self.fake_var.get()),
            fake_ttl=_parse_int(self.fake_entry.get(), 1),
            shrink_enabled=bool(self.shrink_var.get()),
            shrink_window=_parse_int(self.shrink_entry.get(), 4),
            http_host_case=bool(self.http_var.get()),
        )

    def _on_start(self) -> None:
        if self._busy:
            return
        self._busy = True
        self._set_status("Durum: Başlatılıyor — ağ henüz değiştirilmiş sayılmaz", MUTED)
        self._apply_state_buttons()
        config = self._collect_config()

        def work() -> None:
            try:
                self.controller.start(config)
            except Exception as exc:
                self.queue.put(("start_failed", exc))
            else:
                self.queue.put(("start_ok", None))

        threading.Thread(target=work, name="studio-start", daemon=True).start()

    def _on_stop(self) -> None:
        if self._busy:
            return
        self._busy = True
        self._set_status("Durum: Durduruluyor — önce DNS geri yazılacak", WARN_FG)
        self._apply_state_buttons()

        def work() -> None:
            try:
                self.controller.stop()
            except Exception as exc:
                self.queue.put(("stop_failed", exc))
            else:
                self.queue.put(("stop_ok", None))

        threading.Thread(target=work, name="studio-stop", daemon=True).start()

    def _on_recover(self) -> None:
        if self._busy:
            return
        self._busy = True
        self._set_status("Durum: Kayıtlı DNS geri yükleniyor", WARN_FG)

        def work() -> None:
            try:
                self.controller.recover()
            except Exception as exc:
                self.queue.put(("recover_failed", exc))
            else:
                self.queue.put(("recover_ok", None))

        threading.Thread(target=work, name="studio-recover", daemon=True).start()

    def _read_adapters(self) -> None:
        def work() -> None:
            try:
                adapters = self.controller.net.backend.list_default_adapters()
            except Exception as exc:
                self.queue.put(("adapters", str(exc)))
                return
            if not adapters:
                self.queue.put(("adapters", "Uygun bağdaştırıcı yok."))
                return
            lines = [
                f"{item.alias} #{item.index} IPv4={item.ipv4.mode} IPv6={item.ipv6.mode}" for item in adapters
            ]
            self.queue.put(("adapters", "\n".join(lines)))

        threading.Thread(target=work, name="studio-adapters", daemon=True).start()

    def _on_test(self) -> None:
        if self._test_running:
            return
        self._test_running = True
        self._test_cancel.clear()
        self.test_button.configure(state="disabled")
        self.cancel_test_button.configure(state="normal")
        self.test_status.configure(text="Ölçülüyor. Rakamlar geldikçe yazılacak.")
        for child in self.test_list.winfo_children():
            child.destroy()
        if self.controller.dns_running and self.controller.dns_port:
            server, port, path = "127.0.0.1", int(self.controller.dns_port), "Yerel şifreli DNS vekili"
        else:
            provider = PROVIDERS[self._current_provider_id()]
            server, port, path = provider.bootstrap_resolvers[0], 53, (
                f"Vekil kapalı. Doğrudan {provider.bootstrap_resolvers[0]} sorgulanıyor, sistem DNS'i değil."
            )

        def work() -> None:
            try:
                for result in run_probes(
                    dns_server=server,
                    dns_port=port,
                    dns_path=path,
                    cancel=self._test_cancel.is_set,
                ):
                    self.queue.put(("probe", result))
                    if self._test_cancel.is_set():
                        break
            except Exception as exc:
                self.queue.put(("probe_failed", exc))
            finally:
                self.queue.put(("probe_done", None))

        threading.Thread(target=work, name="studio-probe", daemon=True).start()

    def _cancel_test(self) -> None:
        self._test_cancel.set()
        self.test_status.configure(text="İptal istendi. Süren soket zaman aşımını bekleyebilir.")

    def _on_privacy(self) -> None:
        hide = bool(self.privacy_var.get())
        for engine in (self.controller.dpi, self.controller.http):
            privacy = getattr(engine, "privacy", None)
            if privacy is not None:
                privacy.set_hide(hide)
        self._save_prefs()

    def _poll(self) -> None:
        self._drain()
        if self.controller.state == "running":
            try:
                self.stats_label.configure(text=self.controller.stats_line())
            except Exception:
                pass
        if not self._destroyed:
            self.after(120, self._poll)

    def _drain(self) -> None:
        while True:
            try:
                kind, payload = self.queue.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self._append_log(str(payload))
            elif kind == "start_ok":
                self._busy = False
                self._set_status("Durum: Çalışıyor — DNS vekile yöneltildi, garanti yok", ACCENT)
                self._show_banner(
                    "Oturum açık. Bu bir VPN değildir. Başarılı bir site açılışı engelin kalktığını kanıtlamaz.",
                    recover=False,
                )
                self._finish_transition()
            elif kind == "start_failed":
                self._busy = False
                self._set_status("Durum: Başlatılamadı — ayar değişmediyse ağ eski halinde", "#e7b3a8")
                self._show_banner(str(payload), recover=self.controller.net.has_dirty_journal())
                self._finish_transition()
            elif kind == "stop_ok":
                self._busy = False
                self._set_status("Durum: Hazır — DNS geri yükleme adımı tamamlandı", ACCENT)
                self.banner.grid_remove()
                self._finish_transition()
            elif kind == "stop_failed":
                self._busy = False
                self._set_status("Durum: Durdurma yarım — vekil bilinçli olarak açık kalabilir", "#e7b3a8")
                self._show_banner(str(payload), recover=True)
                self._finish_transition()
            elif kind == "recover_ok":
                self._busy = False
                self._set_status("Durum: Hazır — kayıtlı DNS geri yüklendi", ACCENT)
                self.banner.grid_remove()
                self._finish_transition()
            elif kind == "recover_failed":
                self._busy = False
                self._set_status("Durum: Geri yükleme başarısız", "#e7b3a8")
                self._show_banner(str(payload), recover=True)
                self._finish_transition()
            elif kind == "adapters":
                self.adapter_label.configure(text=str(payload))
            elif kind == "probe":
                if isinstance(payload, ProbeResult):
                    self._add_probe(payload)
            elif kind == "probe_failed":
                self.test_status.configure(text=f"Ölçüm hatası: {payload}")
            elif kind == "probe_done":
                self._test_running = False
                self.test_button.configure(state="normal")
                self.cancel_test_button.configure(state="disabled")
                if self._test_cancel.is_set():
                    self.test_status.configure(text="Ölçüm iptal edildi. Eksik satır uydurulmadı.")
                else:
                    self.test_status.configure(text="Ölçüm bitti. TLS satırı bypass anlamına gelmez.")
            elif kind == "exit_ok":
                self._destroy()
                return
            elif kind == "exit_failed":
                self._busy = False
                self._set_status("Durum: Çıkış tamamlanamadı — pencere açık", "#e7b3a8")
                self._show_banner(f"Geri yükleme başarısız, pencere açık kaldı: {payload}", recover=True)
                self._apply_state_buttons()
            elif kind == "tray_failed":
                self._tray_ok = False
                self.deiconify()
                self.lift()
                self._show_banner(f"{TRAY_MISSING} Ayrıntı: {payload}", recover=False)
            elif kind == "show":
                self.deiconify()
                self.lift()
            elif kind == "exit":
                self._request_exit()

    def _finish_transition(self) -> None:
        self._apply_state_buttons()
        if self._exit_after:
            self._request_exit()

    def _apply_state_buttons(self) -> None:
        state = self.controller.state
        if self._busy or state in {"starting", "stopping"}:
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="disabled")
            return
        if state == "running" or self.controller.net_applied or self.controller.dns_running:
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            return
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def _set_status(self, text: str, color: str) -> None:
        self.state_label.configure(text=text, text_color=color)

    def _show_banner(self, text: str, *, recover: bool) -> None:
        self.banner_label.configure(text=text)
        self.banner.grid()
        if recover:
            self.recover_button.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))
        elif self.recover_button.winfo_manager():
            self.recover_button.grid_remove()

    def _show_recovery(self, detail: str) -> None:
        self._show_banner(RECOVERY_HINT + "\n" + detail, recover=True)
        self._set_status("Durum: Geri yükleme bekleniyor — açılış ağı değiştirmedi", WARN_FG)

    def _append_log(self, line: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self._log_lines += 1
        if self._log_lines > 1000:
            self.log_box.delete("1.0", "2.0")
            self._log_lines -= 1
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        self._log_lines = 0

    def _load_existing_log(self) -> None:
        def incoming(line: str) -> None:
            self.queue.put(("log", line))

        self.controller.log.subscribe(incoming)
        for line in self.controller.log.snapshot():
            self._append_log(line)
        self._on_privacy()

    def _add_probe(self, result: ProbeResult) -> None:
        card = ctk.CTkFrame(self.test_list, fg_color=CARD, corner_radius=10)
        card.grid(sticky="ew", padx=4, pady=4)
        card.grid_columnconfigure(0, weight=1)
        title = f"{result.name} · {result.host}:{result.port}"
        ctk.CTkLabel(card, text=title, text_color=TEXT, anchor="w", font=ctk.CTkFont(family=FONT, size=15, weight="bold")).grid(
            row=0, column=0, sticky="ew", padx=10, pady=(8, 2)
        )
        dns = _measure_line("DNS", result.dns_ok, result.dns_ms, result.dns_error)
        tcp = _measure_line("TCP", result.tcp_ok, result.tcp_ms, result.tcp_error)
        tls = _measure_line("TLS", result.tls_ok, result.tls_ms, result.tls_error)
        ctk.CTkLabel(
            card,
            text=f"{dns}\n{tcp}\n{tls}\nYol: {result.dns_path}",
            justify="left",
            anchor="w",
            text_color=MUTED,
        ).grid(row=1, column=0, sticky="ew", padx=10)
        ctk.CTkLabel(card, text=result.interpretation, justify="left", anchor="w", wraplength=920, text_color=TEXT).grid(
            row=2, column=0, sticky="ew", padx=10, pady=(2, 8)
        )

    def _save_prefs(self) -> None:
        payload = {
            "profile_id": self._current_profile().id,
            "provider": self._current_provider_id(),
            "hide_sni": bool(self.privacy_var.get()),
            "fake_ttl_enabled": bool(self.fake_var.get()),
            "shrink_enabled": bool(self.shrink_var.get()),
            "http_host_case": bool(self.http_var.get()),
        }
        try:
            self.prefs_path.parent.mkdir(parents=True, exist_ok=True)
            self.prefs_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            return

    def _start_tray(self) -> None:
        try:
            import pystray
            from PIL import Image, ImageDraw
        except Exception as exc:
            self.queue.put(("tray_failed", exc))
            return
        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((4, 4, 60, 60), radius=14, fill=(18, 32, 46, 255))
        draw.ellipse((18, 18, 46, 46), fill=(62, 207, 178, 255))

        def show(icon: object, item: object) -> None:
            del icon, item
            self.queue.put(("show", None))

        def exit_item(icon: object, item: object) -> None:
            del icon, item
            self.queue.put(("exit", None))

        menu = pystray.Menu(
            pystray.MenuItem("Göster", show, default=True),
            pystray.MenuItem("Çıkış ve geri yükle", exit_item),
        )
        try:
            self._tray = pystray.Icon("dpi-bypass-studio", image, APP_TITLE, menu)
        except Exception as exc:
            self.queue.put(("tray_failed", exc))
            return

        def runner() -> None:
            try:
                self._tray_ok = True
                self._tray.run()
            except Exception as exc:
                self._tray_ok = False
                self.queue.put(("tray_failed", exc))

        threading.Thread(target=runner, name="studio-tray", daemon=True).start()

    def _hide_to_tray(self) -> None:
        if not self._tray_ok:
            self._show_banner(TRAY_MISSING, recover=False)
            return
        self.withdraw()

    def _on_close(self) -> None:
        if self._tray_ok:
            self.withdraw()
            return
        leave = messagebox.askokcancel(
            APP_TITLE,
            "Sistem tepsisi yok. Çıkış, açıksa DNS ayarını geri yüklemeyi dener. Çıkılsın mı?",
        )
        if leave:
            self._request_exit()

    def _request_exit(self) -> None:
        if self._busy:
            self._exit_after = True
            self._show_banner("Süren işlem bitince çıkılacak ve geri yükleme denenecek.", recover=False)
            return
        self._busy = True
        self._exit_after = False

        def work() -> None:
            try:
                self.controller.stop()
            except Exception as exc:
                self.queue.put(("exit_failed", exc))
            else:
                self.queue.put(("exit_ok", None))

        threading.Thread(target=work, name="studio-exit", daemon=True).start()

    def _destroy(self) -> None:
        self._destroyed = True
        if self._tray is not None:
            try:
                self._tray.stop()
            except Exception:
                pass
        self.destroy()


def _parse_int(value: str, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _load_prefs(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _measure_line(label: str, ok: bool, elapsed: float | None, error: str | None) -> str:
    if ok and elapsed is not None:
        return f"{label}: ölçüldü, {elapsed:.0f} ms"
    if elapsed is not None and error:
        return f"{label}: ölçülemedi ({elapsed:.0f} ms denendi) — {error}"
    if error:
        return f"{label}: ölçülemedi — {error}"
    return f"{label}: denenmedi"
