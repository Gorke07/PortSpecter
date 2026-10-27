# PortSpecter

**Rust ve Iced ile geliştirilmiş, çoklu subnet destekli ağ keşfi ve port tarama uygulaması.**

[English](README.md) · [Kurulum](docs/INSTALLATION.md) · [Kullanım](docs/USAGE.md) · [Yol haritası](docs/ROADMAP.md)

PortSpecter; cihaz adlarını, MAC bilgilerini, açık portları, kamera keşiflerini ve paylaşılan klasörleri yerel bir masaüstü arayüzünde birleştirir. Türkçe/İngilizce dil ve koyu/açık tema desteği vardır.

## Geliştirme durumu

Proje geliştirme önizlemesidir. Windows üzerinde yerel kontroller yapıldı. Linux/macOS kodu ve paketleme betikleri mevcut; gerçek platformlarda çalışma ve kurulum doğrulaması sürüm öncesi yapılacak işler arasındadır. IPv4 SYN deneyseldir. [Doğrulama ayrıntıları](docs/STATUS.md)

## Özellikler

- TCP connect, UDP ve yerel Rust motoruyla IPv4 SYN taraması.
- Çoklu subnet, CIDR, kısa IP aralığı, hostname, hariç tutma ve VLAN etiketleri.
- ICMP, ters DNS, NetBIOS, mDNS/LLMNR, MAC adresi ve çevrimdışı üretici veritabanı.
- ONVIF, Hikvision SADP, Dahua, DNS-SD/Bonjour ve SSDP/UPnP keşfi.
- Sunucunun izin verdiği gizli paylaşımlar dahil SMB klasör listesi.
- Özet, Portlar, Keşif ve Paylaşım sekmeleri; filtreleme ve arama.
- SQLite geçmişi, tarama karşılaştırması, profiller, kuyruk ve CSV/JSON dışa aktarma.
- 1–256 worker thread; ayrı eşzamanlılık, hız, zaman aşımı ve tekrar sınırları.

## Başlangıç

Rust **1.99+** ve [işletim sistemi bağımlılıklarını](docs/INSTALLATION.md#build-from-source) kurun:

```sh
git clone https://github.com/Gorke07/PortSpecter.git
cd PortSpecter
cargo run --locked -p portspecter-desktop
```

Hedefleri girin, yöntem ve portları seçip **Taramayı başlat** düğmesine basın. Uygulama açılışta kendiliğinden tarama yapmaz.

```text
192.168.10.1/24 | Bilgisayarlar | 10
192.168.20.1-255 | Kameralar | 20
10.10.30.10-10.10.30.50 | Sunucular | 30
```

Varsayılan TCP listesi 11 porttur; genişletilmiş liste 34 port içerir. Özel port listesi de girebilirsiniz. **Yalnızca açık portu olanlar** filtresi, portu açılmasa da keşfedilen cihazları gizleyebilir.

## Bilinmesi gerekenler

- Diğer VLAN'lara erişim mevcut yönlendirme/VPN üzerinden olur. VLAN etiketi ağ cihazlarını yapılandırmaz.
- Multicast keşif çoğunlukla yerel subnet ile sınırlıdır. Uzak cihazın MAC adresi her ağda alınamaz.
- Bildirilen servis portu, taramayla doğrulanmış açık port değildir.
- UDP yanıt vermemesi cihazın kapalı olduğunu göstermez.
- SYN için Windows'ta Npcap, Linux'ta libpcap ve paket erişimi, macOS'ta BPF erişimi gerekir.
- Paylaşım listeleme ve dosyalara erişim izinleri farklıdır.
- Yalnızca sahibi olduğunuz veya tarama izniniz bulunan ağlarda kullanın.

## Katkı ve destek

[Katkı rehberi](CONTRIBUTING.md), [sorun giderme](docs/TROUBLESHOOTING.md), [destek](SUPPORT.md) ve [güvenlik bildirimi](SECURITY.md) belgelerine bakın. Hata bildirimlerine gerçek ağ dökümleri, parolalar veya kişisel veriler eklemeyin.

Kod [Apache-2.0](LICENSE) lisanslıdır. Üretici verileri ve yazı tiplerinin kendi koşulları [NOTICE](NOTICE) dosyasında belirtilmiştir.
