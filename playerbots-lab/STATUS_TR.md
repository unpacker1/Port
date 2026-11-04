# Durum, kanıtlar ve yapılacaklar

Güncellendi: 2026-11-04.

## Doğrudan doğrulanmış
- [x] MIT-era `v2.2.16` kodu GitHub'dan erişilebilir (sabit commit: `47106704f5c4f049619db44235754ce3670cd87c`).
- [x] Linux x86_64: 14/14 mevcut C++ davranış testi derlenip çalıştı.
- [x] Linux ARM64: 14/14 mevcut C++ davranış testi derlenip çalıştı.
- [x] Statik taramada altı kaynak/istemci/derleme bulgusu doğrulandı.
- [x] İlk Actions koşusu: [#41872272857](https://github.com/unpacker1/Port/actions/runs/41872272857) — success.
- [x] İkinci Actions koşusu: [#41872566324](https://github.com/unpacker1/Port/actions/runs/41872566324) — success.

## Henüz kanıtlanmamış / başarılmadı
- [ ] Tam Metin2 GAME/DB/AUTH motoru ARM64 derlemesi.
- [ ] Termux/proot üzerinde servislerin açılması.
- [ ] Gerçek karakter login / join / hareket.
- [ ] Windows native istemci yerine tarayıcı istemcisi.
- [ ] NPC ticareti, savaş, yürüme, yedekleme ve uzun süreli FPS kararlılığı.

## Açık engeller
- Eksik olan temel GAME engine, client ve SQL dosyalarının bir kısmı `artifacts.json` tarafından **harici** bekleniyor; kamu deposunda kaynak/ikili olarak yoklar.
- mt2009 Dockerfile Linux/i386 + `-m32` hedefli; bu üretim paketi ARM64'e doğrudan uyumlu değil.
- Güncel `v2.2.140` istemcisi Windows x64 EXE istiyor; retired WebClient bu proje tarafından dağıtılmıyor.
- 2.2.17 sonrası kaynaklar yayımlanmıyor, CC BY-NC-ND dağıtım sınırları var.

## Sonraki teknik kapılar
1. Bu laboratuvardaki bağımsız C++ ve Python/shell testlerini sürekli doğrula, artefaktları yayınla.
2. Kullanım izni olan engine baseline olmadan **tam GAME build yapıldı** iddiasında bulunma.
3. Kaynaklar yetkili biçimde hazır olduğunda ARM64 `build-deps` ve C++20 proje derlemesini deneyip gerçek hata listesini çıkar.
4. Native login ve GAME hareket akışı ölçülünce yalnızca aynı protokolü konuşan yasal bir WebClient'ı adapte et.
5. Her aşamayı ayrı port + ayrı DB + ayrı çalışma dizininde tut.

## GitHub
- [Proje dalı](https://github.com/unpacker1/Port/tree/tieruyt-playerbots-arm64-web-audit)
- [CI dosyası](https://github.com/unpacker1/Port/blob/tieruyt-playerbots-arm64-web-audit/.github/workflows/tieruyt-playerbots-audit.yml)
- [Eski rapor](../research/TIERUYT_PLAYERBOTS_ARM64_WEBCLIENT_RAPOR_TR.md)
