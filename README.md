# BurpAIExtension

**BurpAIExtension**, Burp Suite için geliştirilen bir yapay zeka destekli güvenlik test uzantısıdır. Bu uzantı, AI modelini kullanarak güvenlik testlerinizi geliştirmek ve otomatikleştirmek için öneriler sağlar. Özellikle manuel güvenlik testlerinde AI destekli analizler elde etmek isteyen siber güvenlik uzmanları ve bug bounty avcıları için tasarlanmıştır.

<img src="https://github.com/alpernae/BurpAI/blob/main/assets/burpai.png" />
## İçindekiler

- [Özellikler](#özellikler)
- [Gereksinimler](#gereksinimler)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Menü ve Özellikler](#menü-ve-özellikler)
- [API Anahtarı Yönetimi](#api-anahtarı-yönetimi)
- [Sunucu Başlatma](#sunucu-başlatma)
- [Sorun Giderme](#sorun-giderme)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)

## Özellikler

- **AI Destekli Analiz:** Burp Suite içinde gerçekleştirdiğiniz güvenlik testlerinde AI'dan öneriler ve analizler alabilirsiniz.
- **Kullanıcı ve AI Mesajları:** Sohbet tabanlı bir arayüz ile AI modeline sorular sorabilir ve yanıtlar alabilirsiniz.
- **API Anahtarı Yönetimi:** API anahtarınızı güvenli bir şekilde kaydedebilir ve kullanabilirsiniz.
- **Sunucu Entegrasyonu:** AI modeli için yerel bir sunucu çalıştırarak Burp Suite ile entegrasyon sağlar.

## Gereksinimler

- Burp Suite Professional veya Community Edition
- Python 2.7 veya daha yeni bir Python sürümü
- Flask (Sunucu için gerekli)
- Java Runtime Environment (Burp Suite için)

## Kurulum

1. **Depoyu Klonlayın:**
   ```bash
   git clone https://github.com/alpernae/BurpAIExtension.git
   cd BurpAIExtension
   ```
   
2. **Burp Suite'e Uzantıyı Ekleyin:**
   - Burp Suite'i açın.
   - "Extender" sekmesine gidin.
   - "Extensions" sekmesinde "Add" butonuna tıklayın.
   - Uzantı türü olarak "Python" seçin.
   - `BurpAIExtension.py` dosyasını seçin ve ekleyin.

## Kullanım

1. **API Anahtarını Girin:**
   - Uzantı sekmesine gidin ve API anahtarınızı ilgili alana girin.
   - "Add API Key" butonuna tıklayarak anahtarı kaydedin.

2. **AI ile İletişim Kurun:**
   - Alt kısımda bulunan metin alanına sorularınızı veya komutlarınızı girin.
   - "Send Prompt" butonuna tıklayarak AI modeline gönderin.
   - Yanıtlar sohbet alanında görüntülenecektir.

## Menü ve Özellikler

- **Send Requests:** Seçilen HTTP isteğini ve yanıtını AI modeline gönderebilir ve analiz alabilirsiniz.

## API Anahtarı Yönetimi

API anahtarınızı uzantı üzerinden güvenli bir şekilde saklayabilirsiniz. Anahtar, uzantı başlatıldığında otomatik olarak yüklenecektir.

## Sunucu Başlatma

Uzantı, AI modeline bağlantı kurmak için yerel bir Flask sunucusu çalıştırır. Sunucu otomatik olarak başlatılır ancak ihtiyaç duyulursa manuel olarak başlatabilirsiniz.

- Sunucuyu başlatmak için `server.py` dosyasını çalıştırın:
   ```bash
   python server.py
   ```

## Sorun Giderme

- **Bağlantı Hataları:** Sunucunun çalıştığından ve doğru API anahtarının girildiğinden emin olun.
- **Yanıt Alınamıyor:** API isteğinin geçerli olduğundan ve sunucunun doğru çalıştığından emin olun.

## Katkıda Bulunma

Bu projeye katkıda bulunmak isterseniz, lütfen bir pull request gönderin veya bir issue açın.

## Lisans

Bu proje CC BY-NC 4.0 Lisansı ile lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakabilirsiniz.
