"""Kullanıcıya görünen Türkçe metinler."""

from __future__ import annotations

APP_TITLE = "DPI Bypass & Şifreli DNS Stüdyosu"

SUBTITLE = (
    "Kendi bağlantınızda giden TLS el sıkışmasını parçalayabilir ve DNS sorgularını "
    "DNS-over-HTTPS ile iletebilir. ISS engelini kaldırdığı, hız kaybı olmadığı "
    "veya bir VPN yerine geçtiği söylenemez."
)

LIMITATIONS = """
Bu sayfa ürünün bilerek yapmadığı şeyleri yazar.

VPN veya anonimlik hizmeti değildir. Trafiğiniz yine kendi IP adresinizden hedefe gider. DoH, sorgunun ISS DNS'ine düz metin gitmemesini sağlar; DoH sağlayıcısı sorguyu görür. SNI, şifreli değilse yol üzerindeki gözlemciye görünebilir. ECH (Encrypted Client Hello) gerçek adı gizler. Bu program ECH'yi çözmez, silmez ve ECH yüzünden bağlantıyı kesmez. Günlükte ECH varsa görünen adın ön ad olabileceği yazılır.

QUIC çoğunlukla UDP/443 kullanır. Bu program UDP'yi yakalamaz ve QUIC'i sessizce engellemez. Tarayıcı QUIC ile giderse TCP parçalaması o bağlantıya uygulanmaz. Bunu kapatmak için tarayıcı veya oyun ayarına ayrıca bakmanız gerekir; bu uygulama QUIC'i düşürmez.

Parçalama yalnızca bu TCP kesiminde tam duran bir TLS ClientHello için yapılır. El sıkışma birden fazla kesime bölünmüşse, kayıt bozuksa, SNI yoksa veya paket SYN/FIN/RST ya da IP parçasıysa paket olduğu gibi geri verilir. Amaç trafik düşürmek değildir.

Agresif profildeki düşük TTL sahte paketi Superonline ve Kablonet için bir denemedir. Bu depoda o ISS'lerde doğrulanmadı. Sahte paketin TCP checksum'ı bilerek bozuktur ve IP checksum'ı sağlam bırakılır. Ağ kartı checksum offload'u bozuk checksum'ı düzeltebilir. TTL'in DPI'dan önce mi sonra mı tükeneceği ağa bağlıdır.

Pencere küçültme deneyseldir ve yalnızca SNI bölünürse ilk kesime uygulanır. 0 değeri kapalıdır. Discord/oyun profilinde sahte TTL ile pencere küçültme birlikte reddedilir.

HTTP Host harf karıştırma yalnız 80/TCP ve tam bir HTTP isteğidir. 443 üzerindeki şifreli yük değiştirilmez. HTTP/2 veya başlığı yarım kalmış paketler geçirilir.

Her giden 443 veri paketi kullanıcı kipine çıkar. Bu ek gecikme ve işlemci kullanımı yaratabilir. Sıfır hız kaybı iddia edilmez.

DNS vekili 127.0.0.1:53 ve mümkünse [::1]:53 adresindedir. Yalnızca vekil gerçekten dinlemeye başladıktan sonra sistem DNS'i değişir. Durdururken önce eski DNS yazılır. Geri yükleme başarısız olursa vekil kapatılmaz. Özgün kip DHCP ise DHCP'ye dönülür; DHCP sunucusunun o anki adresi statik liste diye yazılmaz.

IPv6 dinleyicisi açılmazsa IPv6 DNS sunucuları değiştirilmez. Bu durumda IPv6 üzerinden DNS'in ISS'e gidebileceği açıkça söylenir. DNS sızıntısı olmadığı iddia edilmez.

Çökme günlüğü değişimden önce diske yazılır. Sonraki açılış ağı kendiliğinden değiştirmez; geri yükleme düğmesi günlüğü uygular. Günlük bozuksa komut çalıştırılmaz.

WinDivert çekirdek sürücüsüdür, yönetici ister ve güvenlik yazılımları onu zararlı sanabilir. Bu Linux ortamında sürücü, yükseltme, tepsi ve gerçek Windows DNS değişikliği çalıştırılmadı. Windows davranışı doğrulanmış kabul edilmemelidir.

Tek örnek kilidi ikinci pencereyi açmaz. Tepsi kurulamazsa pencere görünür kalır; çıkış düğmesi temizliği yine yapar.
""".strip()

RECOVERY_HINT = (
    "Önceki oturum DNS ayarlarını geri yüklemeden kapanmış görünüyor. "
    "Pencereyi açmak ağı değiştirmez. Kayıtlı ayarlar yalnızca aşağıdaki düğmeyle geri yüklenir."
)

TRAY_MISSING = (
    "Sistem tepsisi başlatılamadı. Pencere görünür kaldı. "
    "Çıkış ve geri yükle düğmesi temizliği yapar; pencereyi çarpıdan kapatmak önce sorar."
)

IPV6_WARNING = (
    "IPv6 DNS dinleyicisi yok. IPv6 DNS sunucuları değiştirilmeyecek. "
    "Bu bir sızıntı koruması değildir."
)
