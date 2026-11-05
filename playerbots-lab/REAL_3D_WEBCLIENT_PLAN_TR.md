# Gerçek 3D WebClient kabul planı (2026-11-05)

Bu belge yalnızca `tieruyt-playerbots-arm64-web-audit` dalındaki bağımsız geliştirme planıdır. Mevcut çevrimdışı 2D mini RPG, Metin2 WebClient veya 3D oyun olarak kabul edilmez.

## Kaynak ve lisans kapısı (G0)
- Kullanılabilir orijinal oyun motoru, harita, karakter, animasyon ve dokuları dosya yolları, format, boyut ve lisansla envanterle.
- Erişilemeyen ya da yeniden dağıtım izni olmayan varlıkları depoya koyma; boş sahneyi HD harita diye sunma.
- GAME/AUTH/DB için kaynak ve platform bağımlılıklarını ayrı kaydet.

## 3D görüntüleme (G1)
- Gerçek WebGL2 renderer, kamera, ışık, gölge ve resize/context-loss yönetimi.
- Doğrulama: Android Chrome WebGL2 destek raporu; sahne yükleme hataları ve FPS ölçümü.

## Harita (G2)
- Yetkili kaynaklardan gerçek terrain/mesh, texture ve koordinat dönüşümü.
- Doğrulama: referans harita koordinatları, çarpışma ve sahne içi konum tutarlılığı.

## Karakter ve animasyon (G3)
- Lisanslı glTF/GLB karakter; idle/walk/run/attack ve skeleton animasyon eşlemesi.
- Doğrulama: model boyutu, rig, animasyon süreleri ve hareket yönleri.

## HD ve mobil optimizasyon (G4)
- GPU uyumlu sıkıştırılmış dokular, mipmap, LOD, frustum culling, ışık/gölge kalite kademeleri.
- Doğrulama: cihazda gerçek FPS, bellek ve yükleme süresi; performans sayıları uydurulmaz.

## Gerçek oyun protokolü (G5)
- Orijinal AUTH/DB/GAME ile giriş, karakter seçimi, dünya bağlantısı, hareket, NPC, savaş ve envanter.
- Doğrulama: gerçek servislerle uçtan uca Android Chrome oturumu; mock testleri yeterli değildir.

## Geliştirme ilkeleri
- Her adımda küçük, izole ve test edilebilir değişiklik; CI completed/success sonucu dışında başarı iddiası yok.
- Eksik kaynaklar açık engel olarak kaydedilir. Başka oyunlardan veya korumalı materyallerden izinsiz varlık kopyalanmaz.
- `main`, private depolar, Termux ve diğer projeler değiştirilmez.
