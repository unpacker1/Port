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

İSTENEN (mevcut değil):
Android Chrome -> WebClient -> [WebSocket / protokol adaptörü] -> AUTH/GAME
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
| WebClient | `artifacts.json` | eski referans var ama motor yayımlanmıyor veya desteklenmiyor |

## ARM64 portunun ön koşulları

1. Oyun engine kaynakları ve bağımlılıklarının kullanım izniyle elde edilmesi. Bu repo tam engine'i içermiyor.
2. `-m32`, i386 statik kütüphaneler ve 32-bit struct/pointer varsayımlarının ARM64'e uygun hale getirilmesi.
3. Native GAME/DB derlenip `file`, `readelf` ve çalıştırma testleriyle aarch64 doğrulaması.
4. MariaDB init, AUTH login, karakter listesi, GAME join, hareket ve kayıt akışının localhost'ta kanıtlanması.
5. WebClient için yasal/uyumlu ayrı kaynak ve protokol adaptörü hazırlanması. AUTH/GAME paketleri aynı değilse sırf bir WS proxy yetmez.
6. Android Chrome'da gerçek çizim, hareket, NPC, shop, envanter, savaş ve performans testleri.

## Bilinçli sınır

ARM64 üzerinde 14 adet **izole C++ politika testi** başarılı olması, bütün oyun engine'inin ARM64 üzerinde derlenebilir olduğu anlamına gelmez. Web tarayıcıları Windows EXE çalıştırmaz. Bunlar farklı kanıt seviyeleridir.
