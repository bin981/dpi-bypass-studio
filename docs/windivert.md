# WinDivert sürücüsü, pydivert 4 ve lisans

Bu proje paket yakalamak için pydivert 4.0.1 kullanır. Windows'ta uygulama sınıfı `pydivert.WinDivert`tır. `Divert` cephesi Linux'ta deneysel eBPFDivert'e düşebilir. Bu program `start()` içinde platform Windows değilse `WinDivert` nesnesini hiç kurmaz.

## Çağrılan API

Kaynak, 4.0.1 paketindeki imzalara göredir:

- `pydivert.WinDivert(filter, layer=pydivert.Layer.NETWORK, priority=-30000, flags=pydivert.Flag.DEFAULT)`
- `handle.open()`, `handle.recv(timeout=0.4)`, `handle.send(packet, recalculate_checksum=True)`
- `handle.close()`
- `pydivert.Packet(raw, interface=packet.interface, direction=packet.direction)`
- `packet.raw`, `packet.tcp.seq_num`, `packet.tcp.window`, `packet.payload`, `packet.ipv4.ttl`, `packet.ipv6.hop_limit`
- `packet.recalculate_checksums()` gönderimde `recalculate_checksum=True` iken çağrılır

Zaman aşımı `TimeoutError` yükseltir. `recv` paketi yığından alır. İşlenemezse özgün paket `recalculate_checksum=True` ile geri verilir. Sahte TTL paketinde TCP checksum bilerek bozulduğu için o gönderim `recalculate_checksum=False` kullanır. Gerçek kesimlerde checksum yeniden hesaplanır.

Filtre:

```
outbound and !impostor and !loopback and tcp.DstPort == 443 and tcp.PayloadLength > 0
```

HTTP karıştırma ayrı tutamaçta ve yalnız `tcp.DstPort == 80` içindir. `and` ile `&&` WinDivert 2.2'de aynı işleçtir. `!impostor`, başka sürücünün enjekte ettiği ve döngüye girebilen paketleri ele alır. Öncelik `-30000`, WinDivert'in düşük ucuna yakındır: gönderilen paket daha düşük öncelikli bir tutamaça düşmesin diye. Aynı önceliği paylaşan tutamaçların filtreleri port bazında ayrıktır.

UDP veya QUIC için filtre yoktur.

## Sürücünün kurulumu

`WinDivertOpen` sürücüyü ilk çağrıda yükler. Bunun için süreç yönetici olmalıdır. pydivert 4.0.1, Windows tekerinde WinDivert 2.2.2 ikilisini taşır. Linux tekerinde bu `.sys` dosyası yoktur; orada sürücü açılmamalıdır ve bu program açmaz.

Windows'ta dosyalar paketin yanında durmalıdır. PyInstaller kullanıyorsanız `packaging/DPIBypassStudio.spec` `collect_all("pydivert")` çağırır. Bu spec burada üretilip çalıştırılmadı.

Sürücü imzalı olsa bile bellek bütünlüğü, kurumsal ilke veya antivirüs yüklemeyi reddedebilir. Red, Python istisnası olarak yüzeye çıkar. Uygulama bu durumda DNS'i değiştirmemiş olmalıdır: sürücü, DNS yönlendirmesinden önce açılır; açılış bozulursa yönlendirme yapılmaz ve vekil kapatılır.

Kaldırmak için uygulamayı durdurun. WinDivert hizmeti başka süreç kullanmıyorsa bir sonraki açılışta inebilir. Zorla `sc delete WinDivert` bu deponun işi değildir ve başka araçların sürücüsünü da kaldırır.

## Lisans

pydivert kaynak başlığı `LGPL-3.0-or-later OR GPL-2.0-or-later` der. WinDivert projesi de kullanıcıya LGPLv3 veya GPLv2 arasında seçim sunar. İkiliyi yeniden dağıtırsanız:

- Lisans metnini ve telif bildirimini pakete koyun.
- LGPL seçeneğinde kullanıcının sürücü veya kitaplık yerine yenisini bağlayabilmesine imkan verin. PyInstaller ile gömülü bir exe bunu kendiliğinden sağlamaz.
- Bu depo bir kurulum exe'si üretmedi. Spec yalnızca talimattır.

Güvenlik yazılımları WinDivert'i zararlı sürücü diye işaretleyebilir. Bu, çekirdekte paket yönlendiren her araçta görülen bir yanlış pozitiftir. İmzayı ve kaynağı kendi politikanıza göre kontrol edin.
