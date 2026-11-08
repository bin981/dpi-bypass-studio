# Windows elle kabul ve performans listesi

Bu liste bu deponun geliştirildiği Linux ortamında çalıştırılmadı. WinDivert, yönetici yükseltmesi, sistem DNS'i ve sistem tepsisi burada doğrulanmış değildir. Aşağıdaki adımlar bir Windows 10 veya 11 makinesinde, kendi bağlantınızda, elle uygulanmalıdır.

Her maddenin yanına tarih ve gözlem yazın. Yeşil bir "engel kalktı" sonucu çıkarmayın. TLS'nin kurulması bypass kanıtı değildir.

## Hazırlık

- [ ] Python 3.11 veya 3.12 64 bit kurulu, `py -3.11 --version` çalışıyor.
- [ ] `py -3.11 -m pip install -r requirements.txt` hatasız bitti.
- [ ] `py -3.11 -m pytest -q` bu makinede de geçiyor. Linux'ta geçen testler sürücüyü açmaz.
- [ ] Antivirüs WinDivert sürücüsünü karantinaya almıyor. Alırsa önce bunu not edin; uygulama sessizce "çalışıyor" sanılmasın.
- [ ] `packaging\yonetici_olarak_baslat.ps1` UAC soruyor ve pencere açılıyor.
- [ ] Pencere açılır açılmaz `ipconfig /all` DNS adresleri değişmiyor.

## Kurtarma

- [ ] Başlatmadan önce etkin bağdaştırıcının DNS kipi not edildi: DHCP mi, statik mi, IPv4 ve IPv6 listeleri neler.
- [ ] Başlat sonrası IPv4 DNS `127.0.0.1`. IPv6 dinleyici açıldıysa IPv6 DNS `::1`. Açılmadıysa IPv6 listesi eski halinde ve pencerede sızıntı uyarısı var.
- [ ] Durdur sonrası DNS, not ettiğiniz kiple birebir aynı. DHCP idi ise statik listeye dönmemiş.
- [ ] Uygulama çalışırken süreç sonlandırılıyor. Yeniden açılışta kurtarma bandı çıkıyor ve kendiliğinden DNS yazılmıyor.
- [ ] "Kayıtlı DNS ayarlarını geri yükle" eski ayarı döndürüyor. `python main.py --recover` aynı işi penceresiz yapıyor.
- [ ] İkinci bağdaştırıcıda yönlendirme yarıda kalırsa (örneğin birini devre dışı bırakıp deneyin) günlük duruyor ve geri alma deneniyor.

## Paket yolu

- [ ] Standart profilde bir HTTPS sitesine girince günlükte SNI satırı görünüyor. Gizle anahtarı yeni satırlarda adı gizliyor.
- [ ] Bilinmeyen veya bölünmüş el sıkışması bağlantıyı düşürmüyor; sayfa açılmaya devam ediyor.
- [ ] QUIC kapatılmadan bir site hâlâ UDP/443 kullanabiliyor. Uygulama bunu engellemiyor.
- [ ] Agresif profil risksiz başlamıyor. Risk kutusu işaretlenince başlıyor. Superonline veya Kablonet üzerinde işe yarayıp yaramadığı ayrıca not ediliyor; bu depo bunu doğrulamaz.
- [ ] Discord profili, listede olmayan bir sitenin SNI'sini parçalamıyor.
- [ ] HTTP Host karıştırma yalnızca düz HTTP. Bir HTTPS isteğinin şifreli yükü değişmiyor.

## Ölçüm sekmesi

- [ ] Discord, Roblox ve listedeki siteler için DNS, TCP ve TLS süreleri gerçekten yazıyor.
- [ ] Ulaşılamayan bir ad için yeşil başarı veya uydurma ping yok.
- [ ] TLS satırının metni, el sıkışmanın bypass kanıtı olmadığını söylüyor.

## Tepsi ve çıkış

- [ ] Çarpı pencereyi tepsiye alıyor, DNS'i geri yazmıyor.
- [ ] Tepsi "Çıkış ve geri yükle" DNS'i eski haline getirip süreci kapatıyor.
- [ ] Tepsi simgesi oluşamazsa pencere görünür kalıyor ve çıkış düğmesi temizliği yapıyor.

## Performans

Kullanıcı kipine çıkan her giden 443 veri paketi ek gecikme ve işlemci kullanır. Sıfır kayıp beklemeyin.

- [ ] Araç kapalıyken ve Standart profil açıkken aynı dosyanın indirme süresi ve görev yöneticisindeki Python CPU'su not edildi.
- [ ] Agresif profil ayrıca ölçüldü. Sahte paketler kötüleştirebilir.
- [ ] Oyun veya ses görüşmesi varsa Discord profili ile agresif profil ayrı ayrı denendi. Takılma olursa profil kapatıldı.

Sonuçları "doğrulandı" diye bu depoya geri yazmayın. Gözlem, denenen Windows sürümü ve sürücü sürümüyle birlikte sizin notunuzdur.
