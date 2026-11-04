# Metin2 Playerbots — ARM64 / WebClient GitHub Laboratuvarı

> **Çalışan bir mobil oyun değildir.** Bu dal, TieruYT/metin2-playerbots'un MIT lisanslı `v2.2.16` kaynaklarına sabitlenmiş bir Git submodule ve otomatik platform testleri içeren açık bir araştırma laboratuvarıdır.

## Son test sonuçları (4 Kasım 2026; genişletilmiş köprü testleri)
- **Linux x86_64 C++ testleri:** 14/14 başarılı.
- **Gerçek Linux ARM64 C++ testleri:** 14/14 başarılı.
- **İstemci/mock Python ve shell testleri:** 6/6 başarılı.
- **Eski WebSocket → TCP loopback testleri:** 6/6 başarılı (yerel sahte GAME).
- **Kaynak/platform statik denetimi:** 8/8 beklenen olgu doğrulandı.
- **Kaynak envanteri:** 7.301 dosya (kod + varlık + belge), 85 playerbot başlık dosyası.
- **GAME/DB/AUTH'nin ARM64 üzerinde gerçekten çalışması ve WebClient ile oynanış:** Henüz doğrulanmadı.

**Çalışma:** [Tamamlanan GitHub Actions #41876840784](https://github.com/unpacker1/Port/actions/runs/41876840784) · [Düzenli kalite kapısı](https://github.com/unpacker1/Port/blob/main/.github/workflows/playerbots-periodic-ci.yml) · [Takip #1](https://github.com/unpacker1/Port/issues/1)

**Belgeler:** [Türkçe proje rehberi](playerbots-lab/README_TR.md) · [Ayrıntılı durum](playerbots-lab/STATUS_TR.md) · [Mimari](playerbots-lab/ARCHITECTURE_TR.md) · [Lisans](playerbots-lab/NOTICE_TR.md)

**Upstream:** [TieruYT/metin2-playerbots v2.2.16](https://github.com/TieruYT/metin2-playerbots/tree/v2.2.16)

## Depodaki bileşenler
- `playerbots-lab/upstream` — v2.2.16 sürümüne sabitlenmiş kaynak submodule (orijinal dosyalara bağlantı, yeniden dağıtım değil).
- `playerbots-lab/tools/run_cpp_tests.py` — x86_64/ARM64 için 14 C++ davranış testi.
- `playerbots-lab/tools/run_client_tests.py` — Python istemci mock ve shell migrator testleri.
- `playerbots-lab/tools/audit.py` — kaynak envanteri ve ARM64/WebClient engel analizi, JSON/Markdown raporu.
- `playerbots-lab/tools/test_wsbridge.py` — 6 gerçek yerel socket ve WebSocket frame/port testleri.
- `.github/workflows/tieruyt-playerbots-audit.yml` — GitHub CI pipeline, sonuç artefaktları.

**Sınır:** Termux projeleri, mevcut AUTH/DB/GAME sunucuları, private depolar, SQL verileri ve ana dal değiştirilmedi. `port.py` önceki ana depodan kalan ilgisiz dosyadır; laboratuvarda kullanılmaz.
