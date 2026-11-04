# Metin2 Playerbots — ARM64 / WebClient GitHub Laboratuvarı

> **Çalışan bir mobil oyun değildir.** Bu dal, TieruYT/metin2-playerbots projesinin **MIT lisanslı v2.2.16 kaynak kodunu** değişiklik yapmadan referanslayan ve x86_64 / ARM64 testlerini otomatik çalıştıran açık bir araştırma laboratuvarıdır.

**Ana başlangıç:** [Türkçe proje rehberi](playerbots-lab/README_TR.md) · [Güncel durum](playerbots-lab/STATUS_TR.md) · [Kaynak ve lisans](playerbots-lab/NOTICE_TR.md)

**Testler:** [GitHub Actions](https://github.com/unpacker1/Port/actions/workflows/tieruyt-playerbots-audit.yml) · [İlk doğrulanmış 28/28 test](https://github.com/unpacker1/Port/actions/runs/41872272857)

**Kaynak:** [TieruYT/metin2-playerbots v2.2.16](https://github.com/TieruYT/metin2-playerbots/tree/v2.2.16)

### İçerik

- `playerbots-lab/upstream` — Git submodule olarak **sabitlenmiş** v2.2.16 kaynak ağacı. Yeniden dağıtım değil, kaynağa tam sürüm bağlantısıdır.
- `playerbots-lab/tools/` — C++ politika testleri, Python istemci birim testleri ve statik uyumluluk denetleyicisi.
- `.github/workflows/tieruyt-playerbots-audit.yml` — bulutta x86_64 / gerçek ARM64 testleri, rapor artefaktları.
- `playerbots-lab/ARCHITECTURE_TR.md` — GAME, bot AI, SQL, istemci ve protokol sınırları.
- `playerbots-lab/STATUS_TR.md` — kanıtlanmış sonuçlar, engeller ve sonraki doğrulama kapıları.

**Güvenlik:** Eski oyun dosyaları, MariaDB parolaları, kişisel veriler ve özel repolar bu dalın parçası değildir. Port.py eski ana deponun dosyasıdır; Playerbots laboratuvarında kullanılmaz. Ana dal değiştirilmemiştir.
