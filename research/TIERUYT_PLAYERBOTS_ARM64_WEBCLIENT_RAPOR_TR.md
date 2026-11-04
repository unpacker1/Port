# TieruYT Metin2 Playerbots — ARM64 / WebClient kontrol raporu

Tarih: 2026-11-04 UTC
Kaynak: https://github.com/TieruYT/metin2-playerbots
Açık kaynak etiketi: v2.2.16 (MIT dönemindeki kaynaklar)
Güncel dağıtım: sunucu 2.2.140, native istemci 2.0.141
Test çalışması: https://github.com/unpacker1/Port/actions/runs/41872272857

## Doğrudan doğrulanan sonuçlar

| Kontrol | Sonuç |
|---|---|
| GitHub Actions, eski kaynakları indirebildi | EVET |
| x86_64 Linux üzerinde C++ birim testi | 14/14 başarılı |
| ARM64 Linux üzerinde C++ birim testi | 14/14 başarılı |
| ARM64 ve WebClient statik kontrolü | 6/6 kaynak olgusu doğrulandı |
| Tam GAME + DB + AUTH derlendi/başlatıldı | HAYIR, bu kapsamda test edilmedi |
| Termux / Android'de çalıştırma | HAYIR, bu kapsamda test edilmedi |
| WebClient ile giriş, karakter, hareket, NPC ve savaş | HAYIR, bu kapsamda test edilmedi |

İki mimaride derlenip başarıyla yürütülen kaynak testleri:
- playerbot_channel_rules_test.cpp
- playerbot_empire_rules_test.cpp
- playerbot_event_rules_test.cpp
- playerbot_lure_order_rules_test.cpp
- playerbot_offline_policy_test.cpp
- playerbot_offline_scan_test.cpp
- playerbot_persona_rules_test.cpp
- playerbot_progression_needs_test.cpp
- playerbot_shop_name_rules_test.cpp
- playerbot_stall_rules_test.cpp
- playerbot_truce_rules_test.cpp
- playerbot_world_rules_test.cpp
- playerbot_arrange_rules_test.cpp
- playerbot_conversation_test.cpp

## ARM64 ve WebClient bulguları

- Eski C++ bot motoru, v2.2.16 altında playerbot_manager.cpp ve birçok pure policy header içeriyor.
- mt2009 Dockerfile varsayılan olarak Linux/i386 ve gcc -m32 yaklaşımı kullanıyor; ARM64'e taşımak için ayrıca port gerek.
- Aynı repodaki artifacts.json, eski WebClient'ı dağıtmadığını, indirmediğini ve desteklemediğini açıkça belirtiyor.
- WebClient motoru için engine_url alanı boş; bir tarayıcı motoru ikilisi burada sağlanmıyor.
- Tam GAME kaynaklarının bir bölümü repo dışında sahip olunan r40250/mt2009 sunucu paketlerinden bekleniyor.
- Güncel istemci manifesti x64 Windows executable gerektiriyor.

## Ne anlama geliyor?

**Kanıtlanan:** 14 adet izole bot C++ davranış/politika testi x86_64 ve gerçek ARM64 Linux GitHub runner üzerinde geçti.

**Kanıtlanmayan:** Bu sonuçlar tam server runtime, MariaDB, auth, native/game protokolü, WebSocket/WebClient, mobil GPU ya da Termux performansını doğrulamaz.

**Engel:** Eksik server baseline + güncel WebClient desteğinin kaldırılması. Bunlar çözülmeden 'Termux'ta tarayıcıdan direkt oynanıyor' denemez.

## Koruma / kapsam

- Kullanıcının telefonuna hiçbir dosya indirilmedi.
- Kullanıcının mevcut oyun projelerine, AUTH/GAME/DB ve SQL kurulumlarına dokunulmadı.
- Çalışma, unpacker1/Port deposunun ayrı bir public dalında yürütüldü; main değiştirilmedi.
- Kaynaklar GitHub Actions runner tarafından yalnızca test sırasında çekildi.
- Güncel korumalı çalıştırılabilirler çözülmedi/decompile edilmedi.
- Bu, upstream repoyu fork etmek değildir: mevcut GitHub konektöründe fork oluşturma yeteneği yok.

## Tekrar üretim

GitHub Actions iş akışı:
https://github.com/unpacker1/Port/blob/tieruyt-playerbots-arm64-web-audit/.github/workflows/tieruyt-playerbots-audit.yml

MIT dönemi kaynaklar:
https://github.com/TieruYT/metin2-playerbots/tree/v2.2.16

Test kayıtları:
https://github.com/unpacker1/Port/actions/runs/41872272857
