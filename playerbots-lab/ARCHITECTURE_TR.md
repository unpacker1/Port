# Teknik mimari ve uyumluluk sınırları

## Doğrulanan kaynak mimarisi

```text
           (güncel / eski) Native Windows Metin2 İstemcisi
                                |
                 Metin2 native oyun protokolü
                                |
                AUTH ---- DB ---- GAME
                                 |
                      CPlayerBotManager
                     /     |      |      \
                 AI Planner Nav Combat Economy
                                 |
                               MariaDB

ESKİ SÜRÜMDE KAYNAĞI BULUNAN KÖPRÜ (yalnızca loopback sahte GAME testi geçti):
Android Chrome -> [eksik eski WASM WebClient] -> WebSocket /to/host:port
                                                  |
                                 python ws2tcp.py byte relay
                                                  |
                                         TCP -> AUTH/GAME

Gerçek Chrome istemcisi, WebClient WASM/veri ve AUTH/GAME ARM64 runtime HENÜZ YOK.
```

**Kaynaklar:** `upstream/linux-port/overlays/playerbot/src/game/src/`, `upstream/linux-port-mt2009/docker/`, `upstream/artifacts.json`, `upstream/README_TR.md`.

## Paket katmanları

| Katman | Bulunduğu yer | Bulgu |
|---|---|---|
| Botlar | `playerbot_manager.cpp`, `playerbot_*.h` | GAME içine C++ olarak gömülü |
| Nav | `playerbot_navigation.h` | server_attr hücreleri ve rota önbelleği |
| Savaş | `playerbot_combat.h` | istemcinin beklediği native paketlere uygun görsel yayını |
| Plan | `playerbot_planner.h` | görev öncelik / ağırlık sistemi |
| Veri | `docker/mariadb/playerbot`, `sql/` | seed ve kalıcı karakterler |
| Sunucu derlemesi | `linux-port-mt2009/docker/game/Dockerfile` | Linux/i386, `-m32`, harici engine kaynakları gerekir |
| Güncel istemci | `update-manifest-mt2009.json` main | Windows x64 ve native EXE gerekiyor |
| Eski WebSocket köprüsü | `linux-port/docker/wsbridge/bin/ws2tcp.py` | /ping, /ports ve /to/{host}:{port} köprüsü; localhost sahte-TCP echo testi geçti |
| Eski WebClient araçları | `wasm-port/scripts/`, `linux-port/package-web-client.sh` | Eski WASM üretim/düzeltme betikleri var; bitmiş engine/corpus ZIP mevcut değil |
| Güncel WebClient | `artifacts.json` main | yeni sürüm resmen desteklenmiyor |

## Köprü hakkında önemli ayrım

`ws2tcp.py` gelen WebSocket binary payload'unu sabit `TARGET_HOST` üzerinde izin verilen TCP portuna geçirir. **Oyunun native AUTH/GAME protokolünü dönüştürmez, şifrelemeyi sonlandırmaz.** Köprü, kamuya açık bir sunucuda veri tabanı/P2P portlarını iletmeyecek şekilde tasarlanmıştır. Orijinal `linux-port/docker/wsbridge/README.md` güvenlik ayarlarını açıklar; buradaki testler dağıtım güvenliği onayı değildir.

İzole altı test gerçek Python WebSocket sunucu el sıkışması, port kısıtları, RFC 6455 maskeli frame, /ping ve sahte TCP echo çağrısını doğruladı: [GitHub CI #41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784). Gerçek native sunucu ve Chrome oyun istemcisi denenmedi.

## ARM64 portunun ön koşulları

1. Oyun engine kaynakları ve bağımlılıklarının kullanım izniyle elde edilmesi. Bu repo tam engine'i içermiyor.
2. `-m32`, i386 statik kütüphaneler ve 32-bit struct/pointer varsayımlarının ARM64'e uygun hale getirilmesi.
3. Native GAME/DB derlenip `file`, `readelf` ve çalıştırma testleriyle aarch64 doğrulaması.
4. MariaDB init, AUTH login, karakter listesi, GAME join, hareket ve kayıt akışının localhost'ta kanıtlanması.
5. WebClient için yasal/uyumlu ayrı kaynak ve protokol adaptörü hazırlanması. AUTH/GAME paketleri aynı değilse sırf bir WS proxy yetmez.
6. Android Chrome'da gerçek çizim, hareket, NPC, shop, envanter, savaş ve performans testleri.

## Bilinçli sınır

ARM64 üzerinde 14 adet **izole C++ politika testi** başarılı olması, bütün oyun engine'inin ARM64 üzerinde derlenebilir olduğu anlamına gelmez. Web tarayıcıları Windows EXE çalıştırmaz. Bunlar farklı kanıt seviyeleridir.
