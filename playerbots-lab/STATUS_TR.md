# Durum, kanıtlar ve yapılacaklar

Güncellendi: 2026-11-04 UTC. **Tamamlanan son kapsamlı CI: [#41874659407](https://github.com/unpacker1/Port/actions/runs/41874659407) — success.**

## Kaynakların tamamı bağlantılandı
- Sabit MIT-era kaynak: TieruYT/metin2-playerbots `v2.2.16`.
- Git submodule commit: `47106704f5c4f049619db44235754ce3670cd87c`.
- CI envanteri: **7.301 dosya** (kaynak kodu, varlıklar, betikler, belgeler ve testler dahil), **85 bot başlık dosyası**, **14 bağımsız C++ test hedefi**.
- Bu yöntem orijinal `v2.2.16` GitHub deposuna referans verir; güncel kapalı kaynak binaryleri veya özel oyun verilerini kopyalamaz.

## Gerçek test sonuçları
| Denetim | Çalıştırıldığı yer | Sonuç |
|---|---|---|
| 14 C++ politika testi | GitHub Linux x86_64 | **14/14 PASS** |
| Aynı 14 C++ testi | GitHub Linux ARM64 | **14/14 PASS** |
| 5 Python istemci mock + 1 Shell veritabanı migrator mock | GitHub Linux x86_64 | **6/6 PASS** |
| 8 kaynak/platform olgusu | Sabitlenmiş eski kaynak + güncel public manifest | **8/8 doğrulandı** |
| Tam ARM64 GAME + DB + AUTH | Gerçek sunucu | **Henüz test edilmedi** |
| Termux / Android runtime | Telefon | **Henüz test edilmedi** |
| WebClient oyuna login / hareket / NPC / savaş | Tarayıcı | **Henüz test edilmedi** |

> **Ölçüm sınırı:** 34 başarılı izole test çalıştırması gerçek oyun sunucusunun veya WebClient'ın çalıştığını kanıtlamaz. Buradaki 8/8 statik tarama, bazı **engellerin mevcut olduğunu** doğrular; uyumluluğu doğrulamaz.

## Geçmiş
- [#41872272857](https://github.com/unpacker1/Port/actions/runs/41872272857): İlk C++ testleri 28/28 PASS.
- [#41872566324](https://github.com/unpacker1/Port/actions/runs/41872566324): Tekrar doğrulama PASS.
- [#41874659407](https://github.com/unpacker1/Port/actions/runs/41874659407): Kaynak submodule, C++ x86+ARM, Python/shell mock ve envanter birlikte PASS.

## Engeller ve açık kapılar
1. `artifacts.json` ve `linux-port-mt2009` üretim derlemesi için harici engine, SQL ve istemci dosyaları istiyor. Bunlar GitHub kaynak ağacında tam olarak yok.
2. `linux-port-mt2009/docker/game/Dockerfile` Linux/i386 ve `-m32` kullanıyor; aarch64 GAME ikilisi henüz derlenmedi.
3. Güncel `v2.2.140` istemcisi Windows x64 EXE istiyor. Proje, eski WebClient motorunu yayımlamıyor ve desteklemiyor.
4. Android/Termux GAME server için uyumlu engine + tüm bağımlılıklar gerekir; bunun ardından AUTH/DB/GAME canlı testleri yapılabilir.
5. Tarayıcı istemcisi ancak gerçek protokol karşılaştırması ve lisansça uygun WebClient kodu hazır olduğunda test edilebilir.

## Sonraki gerçek doğrulama aşamaları
- [ ] Yetkili/izinli engine baseline ve eşleşen SQL dosyalarını ayrı, **özel** çalışma ortamında sağla.
- [ ] GAME için aarch64 derleme ve başlatma testlerini yap; gerçek derleyici hatalarını kaydet.
- [ ] Ayrı DB ve portlarla AUTH login, karakter listesi, GAME join, hareket ve bot spawn testi.
- [ ] Uyumlu WebClient üzerinde WebSocket/native protokol entegrasyonu.
- [ ] Android Chrome üzerinden render, NPC shop, envanter, savaş ve performans testi.

## Proje bağlantıları
- [Ana proje dalı](https://github.com/unpacker1/Port/tree/tieruyt-playerbots-arm64-web-audit)
- [CI dosyası](https://github.com/unpacker1/Port/blob/tieruyt-playerbots-arm64-web-audit/.github/workflows/tieruyt-playerbots-audit.yml)
- [Teknik mimari](ARCHITECTURE_TR.md)
- [Lisans ve sınırlar](NOTICE_TR.md)
