# Metin2 Playerbots — ARM64 / WebClient Geliştirme Laboratuvarı

## Hedef
TieruYT/metin2-playerbots'un eski açık kaynak (`v2.2.16`) bot modüllerini incelemek ve şu hedefi aşama aşama doğrulamak: **Android / Termux ARM64 üzerinde gerçek AUTH + DB + GAME sunucusu ve ayrı bir web istemcisi ile oynanış**.

Bu depoda **çalışan Android oyunu, sunucu ikilisi, Windows EXE, oyun veri arşivi ya da tarayıcı oyun motoru yoktur**. Güncel dağıtım (`v2.2.140`) korumalıdır ve WebClient'ı resmi olarak desteklemez. Eski açık kaynak kaynaklarının çalışması güncel korumalı sürümün mobilde çalışacağı anlamına gelmez.

## Yapı
```text
/
  README.md
  .gitmodules
  .github/workflows/tieruyt-playerbots-audit.yml
  playerbots-lab/
    upstream/                        Git submodule: TieruYT, v2.2.16 commit
    tools/run_cpp_tests.py           14 bağımsız C++ test hedefi
    tools/run_client_tests.py        Seçilmiş Python ve shell testleri
    tools/audit.py                   Gerçek kaynak envanteri + engel taraması
    ARCHITECTURE_TR.md               Bağımlılıklar ve paket sınırları
    STATUS_TR.md                     Doğrulanmış sonuçlar ve yol haritası
    NOTICE_TR.md                     Lisans ve dağıtım sınırları
  research/                           Önceki çalışmanın korunmuş raporu
```

## Bulutta otomatik test
[Actions sekmesi](https://github.com/unpacker1/Port/actions/workflows/tieruyt-playerbots-audit.yml) üzerinden `Run workflow` kullanılabilir. İş akışı yalnızca bu proje dalında çalışır. Kaynak ve testler GitHub runner içinde alınır, telefonunuza bir şey kurulmaz.

```bash
git clone --branch tieruyt-playerbots-arm64-web-audit --recurse-submodules \
  https://github.com/unpacker1/Port.git playerbots-arm64-web-lab
cd playerbots-arm64-web-lab
python3 playerbots-lab/tools/audit.py --upstream playerbots-lab/upstream --report-dir reports
python3 playerbots-lab/tools/run_cpp_tests.py --upstream playerbots-lab/upstream --report-dir reports
python3 playerbots-lab/tools/run_client_tests.py --upstream playerbots-lab/upstream --report-dir reports
```
C++ testleri için `g++`, istemci testleri için `python3` ve `sh` gerekir; bu, **yalnızca laboratuvarın testlerini** çalıştırır. Tam oyun çalıştırmaz.

## Kaynakların nerede olduğu
- Bot motoru: `upstream/linux-port/overlays/playerbot/src/game/src/playerbot_manager.cpp`
- AI durum/kural modülleri: `upstream/linux-port/overlays/playerbot/src/game/src/playerbot_*.h`
- MariaDB seed: `upstream/linux-port/overlays/playerbot/sql/playerbots_seed.sql`
- Portlama: `upstream/linux-port-mt2009/port/playerbotify.py`
- r41023 Docker: `upstream/linux-port-mt2009/docker/game/Dockerfile`
- Eski testler: `upstream/tests/playerbot_*_test.cpp`

## Temel güvenlik ilkeleri
- Orijinal kullanıcı projelerine, private repolara, SQL hesaplarına ve Termux dosyalarına dokunulmaz.
- Repo herkese açık; sır, token, şifre, özel oyun dosyası ya da korumalı EXE gönderilmez.
- Yalnızca GitHub'da **zaten açık** bulunan MIT-era kaynakları doğrudan referanslanır.
- Güncel CC BY-NC-ND sürümün değiştirilmiş binary dağıtımı ya da tersine mühendislik paketi yapılmaz.

Detay: [Mimari](ARCHITECTURE_TR.md) · [Durum/plan](STATUS_TR.md) · [Lisans](NOTICE_TR.md)
