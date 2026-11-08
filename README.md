# dpi-bypass-studio

## DPI Bypass & Şifreli DNS Stüdyosu

Windows masaüstü aracı. Kendi makinenizde giden TLS ClientHello içindeki SNI'yi iki TCP kesimine bölebilir ve DNS sorgularını yerel bir vekilden DNS-over-HTTPS ile iletebilir.

Bu bir VPN değildir. ISS engelini kaldırdığı doğrulanmamıştır. Hız kaybı olmayacağı da söylenemez. Başarılı bir TLS el sıkışması sansürün aşıldığını göstermez.

Geliştirme Linux üzerinde yapıldı. WinDivert sürücüsü açılmadı, yönetici yükseltmesi denenmedi, sistem DNS'i değiştirilmedi. Windows davranışı bu depoda doğrulanmış değildir.

## Ne yapar

- Giden, loopback olmayan, impostor olmayan, yükü boş olmayan 443/TCP paketlerini yakalar.
- TLS ClientHello bu kesimin içinde tamsa SNI'nin bayt ortasından iki kesim üretir. Sıra numarası 32 bitte sarar. IPv4 ve IPv6, seçenekler ve checksum yeniden yazılır.
- Kayıt yarım, bozuk, SNI'siz, SYN/FIN/RST veya IP parçasıysa paket olduğu gibi geri verilir. Amaç trafik düşürmek değildir.
- İsteğe bağlı ve risk onayıyla: TTL 1–8 sahte ilk kesim, ilk kesimde 1–64 pencere, yalnız 80/TCP düz HTTP Host harf karıştırma.
- `127.0.0.1:53` üzerinde UDP ve TCP DNS. Mümkünse `[::1]:53`. Cloudflare veya Google genel DoH uç noktası. Hesap veya API anahtarı yok.
- DoH adresi sistem DNS'i ile çözülmez. Sayısal önyükleme çözümleyicisine doğrudan sorulur, TLS sertifikası ana makine adına göre doğrulanır, httpx bağlantı havuzu o IP'ye bağlanır.
- DNS değişmeden önce anlık görüntü ve kurtarma günlüğü yazılır. Özgün kip DHCP ise geri yükleme DHCP'dir. Kısmi hatada geri alma denenir. Çökme sonrası açılış kendiliğinden yazmaz; düğme ister.
- Vekil dinlemeden DNS yönlenmez. Durdururken önce eski DNS yazılır. Geri yazma olmazsa vekil kapatılmaz.

## Ne yapmaz

- QUIC/UDP engellemez. ECH'yi çözmez veya silmez. Oyunların hepsinde SNI varmış gibi davranmaz.
- IPv6 dinleyicisi açılmazsa IPv6 DNS'ine dokunmaz ve sızıntı olmadığını iddia etmez.
- DNS sağlayıcısından, hedef IP'den veya ECH'siz SNI'den gizlemez.
- Sıfır gecikme vaat etmez. Her giden 443 veri paketi kullanıcı kipine çıkar.

Ayrıntı uygulamanın Sınırlamalar sekmesindedir. Windows adımları `docs/windows_kabul_listesi.md`, sürücü notları `docs/windivert.md` içindedir.

## Kurulum

Python 3.11 veya daha yenisi, 64 bit:

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
py -3.11 -m pip install -r requirements.txt
py -3.11 main.py
```

Yönetici istemi için `packaging\yonetici_olarak_baslat.ps1` veya `.bat`. Betik yalnızca süreci yükseltir. DNS'i Başlat düğmesi değiştirir.

Linux'ta arayüz açılır fakat Başlat, sürücü ve DNS yazmadan durur. Testler için:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m compileall -q core ui main.py tests
```

## Kullanım

1. Pencereyi açın. Ağ aynı kalır. Günlük varsa geri yükleme bandı çıkar; kendiliğinden uygulanmaz.
2. Profil ve DoH sağlayıcısını seçin. Deneysel anahtarlar risksiz başlamaz.
3. Başlat. Önce DoH ve vekil, sonra WinDivert, en son sistem DNS'i.
4. Günlükte parçalanan SNI görünür. Gizle anahtarı bundan sonraki satırları maskeler. DNS sorgu adları günlüğe yazılmaz.
5. Bağlantı testi sekmesi gerçek DNS, TCP ve TLS sürelerini ölçer.
6. Durdur veya Çıkış ve geri yükle. Çarpı, tepsi varsa pencereyi saklar. Tepsi yoksa çıkış sorulur ve pencere kaybolmaz.

Çökme sonrası: uygulamayı yine yönetici olarak açıp geri yükleyin veya `py -3.11 main.py --recover`.

## Profiller

- **Standart:** Yalnız SNI ortasından bölme.
- **Agresif:** Bölme artı TTL 1 sahte kesim. Superonline/Kablonet için önerilir ve bu depoda doğrulanmamıştır. Pencere küçültme varsayılan olarak kapalıdır.
- **Discord / oyun:** Yalnızca `discord.*`, `discordapp.*`, `roblox.com`, `rbxcdn.com`, `robloxlabs.com` ve alt adlar. UDP ve SNI'siz trafik değişmez.

Desteklenmeyen kombinasyonlar kodda reddedilir: TTL 0, pencere 0 veya 64 üstü, Discord profilinde sahte TTL ile pencere küçültme, pencere 1 ile sahte TTL, risksiz deney.

## Düzen

```
main.py
core/dpi_engine.py
core/dns_proxy.py
core/system_net.py
ui/app_window.py
requirements.txt
```

Yan modüller: `core/divert_loop.py`, `core/doh.py`, `core/tls_hello.py`, `core/ip_tcp.py`, `core/http_mangle.py`, `core/lifecycle.py`, `core/conn_test.py`.

PyInstaller spec'i `packaging/DPIBypassStudio.spec`. Bu ortamda exe üretilmedi.
