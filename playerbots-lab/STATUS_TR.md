# Durum, kanıtlar ve yapılacaklar

Güncellendi: 2026-11-04 UTC. **Son başarılı genişletilmiş çalışma:** [#41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784).

## Sürekli akış
- [x] [Düzenli GitHub Actions](https://github.com/unpacker1/Port/blob/main/.github/workflows/playerbots-periodic-ci.yml) varsayılan dalda kuruldu: `23 */6 * * *` (UTC; altı saatte bir) ve isteğe bağlı manuel çalıştırma.
- [x] İlk düzenli kontrol [#41876503825](https://github.com/unpacker1/Port/actions/runs/41876503825) başarıyla tamamlandı.
- [x] Kaynak/test belgeleri için `tieruyt-playerbots-arm64-web-audit` dalında her committe kapsamlı CI.
- [x] [Takip görevi #1](https://github.com/unpacker1/Port/issues/1): kabul kriterleri ve sıradaki kanıt kapıları.
- [x] Günlük proje kontrol/geliştirme otomasyonu oluşturuldu (sabah Türkiye saatiyle yaklaşık 08:00); gerçek kod ilerlemesi çalışmanın koşullarına ve GitHub erişimine bağlıdır.

## Kaynaklar
- **v2.2.16 MIT dönemi**: `47106704f5c4f049619db44235754ce3670cd87c` commitine sabitlenmiş Git submodule.
- **7.301** eski kaynak dosyası (kod + görseller + belgeler + betikler), **85** playerbot başlık dosyası.
- Güncel istemci manifesti Windows x64 EXE gerektirir; güncel WebClient resmen desteklenmez.

## Doğrulanmış sonuçlar
| Test | Platform | Sonuç | Kanıt |
|---|---|---|---|
| 14 C++ politika testi | Linux x86_64 | **14/14 PASS** | [#41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784) |
| Aynı C++ testleri | Gerçek Linux ARM64 | **14/14 PASS** | [#41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784) |
| İstemci Python/shell mock testleri | Linux x86_64 | **6/6 PASS** | [#41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784) |
| Eski WebSocket köprüsü | Linux x86_64, yerel sahte TCP GAME | **6/6 PASS** | [#41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784) |
| Kaynak/istemci engel taraması | v2.2.16 ve güncel manifest | Gerçek kaynak olguları doğrulandı | [#41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784) |
| Tam GAME/DB/AUTH, Termux | Gerçek oyun | **Henüz test edilmedi** | Eksik kaynaklar/bağımlılıklar |
| Chrome WebClient ile oyun | Gerçek oyun | **Henüz test edilmedi** | İstemci motoru/verileri eksik |

Sonuç: **40 bağımsız otomatik test çalıştırması başarılı.** Bunlar x86_64/ARM64 C++ kuralları, istemci simülasyonları ve gerçek soketle **sahte** TCP sunucusuna WS echo testini kapsar. Tam oyun server build veya gerçek login sonucu değildir.

### Yeni bulgu: Eski köprü tamamen kayıp değil
- `upstream/linux-port/docker/wsbridge/bin/ws2tcp.py`: v2.2.16 için WebSocket → TCP uygulaması.
- `upstream/linux-port/docker/wsbridge/README.md`: URL şekli, /ping, /to/{host}:{port}, auth/game port politikası ve güvenlik tasarımı.
- `upstream/linux-port/package-web-client.sh`: eski `index.wasm`, `index.js` ve oyun corpus arşivleme şeması. **Arşivler bu repoda değil.**
- `playerbots-lab/tools/test_wsbridge.py`: WebSocket handshake → ikili frame → TCP sahte GAME → frame geri dönüşü ile gerçek soket testi. Host istekten değil sabit TARGET_HOST'tan alınıyor; DB/P2P portları yasak.
- **Sınır:** Bu test, köprünün gerçek Metin2 native paketleriyle veya Android Chrome'da eksiksiz çalıştığını kanıtlamaz. Köprü bir protokol çeviricisi değildir.

## Engeller
1. r40250/mt2009 baseline GAME + istemci/veri + SQL paketlerinin bir kısmı bu public kaynakta yok; yasa/izin çerçevesinde sağlanmaları gerekir.
2. `linux-port-mt2009/docker/game/Dockerfile`: `-m32` ve Linux/i386, dolayısıyla ARM64 GAME doğrudan derlenmedi.
3. Windows native istemcisi tarayıcıda çalışmaz; eski WASM dağıtımının kod/veri dosyaları temin edilmeden tarayıcı oynanışı yok.
4. Testler güvenlik veya tam oynanış onayı vermez; lokal izole testlerdir.

## Sıradaki teknik işler
- [ ] [G3-A] wasm-port kaynak betikleri, WebSocket/native paket, portlar ve /ping kapı denetimi arasındaki bağı satır referanslarıyla çıkar.
- [ ] [G3-B] `linux-port-mt2009` derleme bağımlılıklarının ARM64 engellerini dosya/satır bazında çıkar.
- [ ] [G4] Yetkili engine baseline ve SQL dosyaları olmadan tam GAME derlemesi iddiasında bulunma.
- [ ] [G5] İzinli kaynaklar sağlandığında izole ARM64 GAME + AUTH + DB başlatma ve canlı paket kanıtları.
- [ ] [G6] Bot AI spawn/hareket/savaş/NPC shop testleri.
- [ ] [G7] Lisans bakımından uygun WebClient ve gerçek oyun paketleri ile Android Chrome doğrulaması.

[Proje dalı](https://github.com/unpacker1/Port/tree/tieruyt-playerbots-arm64-web-audit) · [GitHub issue #1](https://github.com/unpacker1/Port/issues/1) · [CI](https://github.com/unpacker1/Port/actions/workflows/tieruyt-playerbots-audit.yml) · [Mimari](ARCHITECTURE_TR.md)
