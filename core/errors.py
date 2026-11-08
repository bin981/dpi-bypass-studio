"""Uygulama genelinde kullanılan hata türleri."""

from __future__ import annotations


class StudioError(Exception):
    """Kullanıcıya gösterilebilecek bir çalışma hatası."""


class PlatformError(StudioError):
    """İşlem bu işletim sisteminde yapılmaz."""


class ConfigError(StudioError):
    """Başlatma ayarı geçersiz veya desteklenmeyen bir kombinasyon."""


class AdminRequired(StudioError):
    """İşlem yönetici hakları olmadan reddedildi."""


class RecoveryRequired(StudioError):
    """Çökme günlüğü duruyor; yeni yönlendirmeden önce geri yükleme gerekir."""


class NetworkRollbackError(StudioError):
    """DNS değişikliği yarım kaldı ve otomatik geri alma da başarısız oldu."""


class DnsRestoreError(StudioError):
    """DNS geri yüklenemedi. Yerel vekil, makine DNS'siz kalmasın diye çalışır bırakıldı."""


class DohError(StudioError):
    """DNS-over-HTTPS isteği veya önyüklemesi başarısız."""
