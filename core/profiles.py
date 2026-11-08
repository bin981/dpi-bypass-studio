"""Başlatma profilleri ve desteklenmeyen kombinasyonların reddi."""

from __future__ import annotations

from dataclasses import dataclass

from core.errors import ConfigError

DISCORD_GAME_HOSTS: tuple[str, ...] = (
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discord.media",
    "discord.co",
    "discordstatus.com",
    "roblox.com",
    "rbxcdn.com",
    "robloxlabs.com",
)


@dataclass(frozen=True)
class Profile:
    id: str
    title: str
    summary: str
    fake_ttl: int | None
    shrink_window: int | None
    http_host_case: bool
    allowlist: tuple[str, ...] | None
    experimental: bool


PROFILES: dict[str, Profile] = {
    "standard": Profile(
        id="standard",
        title="Standart",
        summary=(
            "Yalnızca 443/TCP üzerindeki tam TLS ClientHello içindeki SNI'nin "
            "ortasından iki TCP kesimi üretir. Sahte TTL, pencere küçültme ve "
            "HTTP karıştırma kapalıdır. Bunun bir ISS engelini kaldırdığı "
            "doğrulanmış değildir."
        ),
        fake_ttl=None,
        shrink_window=None,
        http_host_case=False,
        allowlist=None,
        experimental=False,
    ),
    "aggressive": Profile(
        id="aggressive",
        title="Agresif (Superonline/Kablonet, doğrulanmamış)",
        summary=(
            "SNI parçalamasına ek olarak TTL değeri 1 olan sahte bir ilk kesim "
            "gönderir. Superonline veya Kablonet üzerinde etkili olduğu bu "
            "projede doğrulanmadı. Bağlantıyı yavaşlatabilir veya bozabilir. "
            "Pencere küçültme bu profilin varsayılanı değildir."
        ),
        fake_ttl=1,
        shrink_window=None,
        http_host_case=False,
        allowlist=None,
        experimental=True,
    ),
    "discord": Profile(
        id="discord",
        title="Discord / oyun kapsamı",
        summary=(
            "Parçalama yalnızca listedeki ana makine adları TLS SNI içinde "
            "görünürse yapılır. UDP, QUIC ve SNI taşımayan oyun trafiği "
            "değiştirilmez. Tüm oyunların TLS SNI kullandığı varsayılmaz."
        ),
        fake_ttl=None,
        shrink_window=None,
        http_host_case=False,
        allowlist=DISCORD_GAME_HOSTS,
        experimental=False,
    ),
}


@dataclass(frozen=True)
class StartConfig:
    profile_id: str
    provider: str
    risk_accepted: bool
    fake_ttl_enabled: bool
    fake_ttl: int
    shrink_enabled: bool
    shrink_window: int
    http_host_case: bool

    def allowlist(self) -> tuple[str, ...] | None:
        return PROFILES[self.profile_id].allowlist


def host_matches(hostname: str, allowlist: tuple[str, ...]) -> bool:
    candidate = _normalize_host(hostname)
    if candidate is None:
        return False
    for pattern in allowlist:
        normalized = _normalize_host(pattern)
        if normalized is None:
            continue
        if candidate == normalized or candidate.endswith("." + normalized):
            return True
    return False


def _normalize_host(hostname: str) -> str | None:
    text = hostname.strip().rstrip(".").lower()
    if not text or any(char in text for char in " \t\r\n/\\"):
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except Exception:
        return None
    return text


def validate_config(config: StartConfig, *, known_providers: set[str]) -> None:
    if config.profile_id not in PROFILES:
        raise ConfigError("Bilinmeyen profil.")
    if config.provider not in known_providers:
        raise ConfigError("Bilinmeyen DNS sağlayıcısı.")
    experimental = (
        config.profile_id == "aggressive"
        or config.fake_ttl_enabled
        or config.shrink_enabled
        or config.http_host_case
    )
    if experimental and not config.risk_accepted:
        raise ConfigError(
            "Deneysel veya doğrulanmamış seçenekler için «riski anlıyorum» kutusunu işaretleyin."
        )
    if config.fake_ttl_enabled and not 1 <= config.fake_ttl <= 8:
        raise ConfigError("Sahte TTL 1 ile 8 arasında olmalıdır. 0 geçersizdir ve kullanılmaz.")
    if config.shrink_enabled and not 1 <= config.shrink_window <= 64:
        raise ConfigError(
            "Pencere küçültme 1 ile 64 arasında olmalıdır. 0 bağlantıyı durdurduğu için kapalıdır."
        )
    if config.profile_id == "discord" and config.fake_ttl_enabled and config.shrink_enabled:
        raise ConfigError(
            "Discord/oyun profilinde sahte TTL ve pencere küçültme birlikte kullanılamaz. "
            "Bu kombinasyon desteklenmiyor."
        )
    if config.fake_ttl_enabled and config.shrink_enabled and config.shrink_window == 1:
        raise ConfigError(
            "Pencere değeri 1 ile sahte TTL birlikte kullanılamaz. "
            "Bu kombinasyon bağlantıyı durdurma riski nedeniyle kapalıdır."
        )
