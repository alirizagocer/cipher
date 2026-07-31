# identify — Terminal Cipher / Encoding Identifier

Elindeki garip metnin ne olduğunu bilmiyorsan (Base64 mü, hex mi, ROT13 mi, hash mı, XOR ile mi şifrelenmiş...) bu araç:

1. Karakter setini/uzunluğunu analiz edip hızlı ipuçları verir (JWT, hash formatları, UUID dahil)
2. Bilinen tüm encoding/cipher'ları otomatik dener (Base64/32/58/85/91, Hex, Binary, Octal, Decimal, URL/HTML/Unicode escape, Quoted-Printable, ROT13/47/5/18, Atbash, Caesar (25 shift), Morse, Bacon)
3. **Anahtar gerektiren zayıf şifrelemeleri brute-force ile kırar**: XOR (tek-byte ve tekrarlayan anahtar — Hamming distance ile anahtar uzunluğu tahmini), Vigenère (Index of Coincidence ile), Rail Fence, Affine
4. **Dosya imzası (magic byte) tespiti** — decode edilen veri aslında bir PNG/ZIP/PDF/ELF/GZIP dosyasıysa bunu anında söyler (CyberChef'in "Detect File Type" özelliğinin offline karşılığı)
5. **JWT tespiti** — header.payload.signature yapısını tanır, JSON içeriğini decode edip gösterir
6. Sonuçları **3 katmana kadar zincirleme** dener (Base64 → ROT13 → Hex gibi)
7. Her sonucu chi-kare harf frekansı + bigram analizi + kelime eşleşmesi + yazdırılabilirlik oranıyla **0-100 arası skorlar**
8. En yüksek skorlu adayı en üstte gösterir

CyberChef'in "Magic" özelliğinin terminal/offline, açık kaynak versiyonu gibi düşünebilirsin — üstüne klasik kriptanaliz (XOR/Vigenère kırma) da ekli.

## Kurulum

```bash
git clone <bu-repo>
cd ciphertool
pip install -e .
```

Bağımlılık yok, sadece Python 3.8+ standart kütüphanesi kullanılıyor.

## Kullanım

```bash
identify "SGVsbG8gV29ybGQh"

# dosyadan oku
identify -f sifreli.txt

# stdin'den oku
echo "Uryyb Jbeyq" | identify

# zincir derinliğini artır (varsayılan 3)
identify -d 4 "..."

# gösterilecek aday sayısı
identify -n 15 "..."

# renksiz çıktı (log/pipe için)
identify --no-color "..." > out.txt

# JSON çıktı (scripting/otomasyon için)
identify --json "..." | jq '.candidates[0]'
```

## Örnek çıktı

```
=== Karakter Seti Analizi ===
  - Uzunluk: 24 karakter
  - Sadece hex karakterler (0-9a-f), çift uzunluk -> güçlü Hex/Base16 adayı

=== Otomatik Decode Denemeleri (skora göre sıralı) ===
#1 [ 97.2] ███████████████████░
    Zincir: Hex (Base16)
    Çıktı : Hello World!

#2 [ 67.6] ██████████████░░░░░░
    Zincir: Hex (Base16) -> ROT13 -> Caesar (shift 10)
    Çıktı : Ebiil Tloia!
```

Dosya tespiti örneği (Base64 içine gömülü PNG):
```
#1 [ 93.0] ██████████████████░░  [DOSYA]
    Zincir: Base64 -> dosya
    Çıktı : [DOSYA TESPİT EDİLDİ] Base64 ile decode edilince PNG image
            imzasına uyuyor (58 byte). Bu metin değil, binary bir dosya —
            diske yazıp açman lazım.
```

## Neyi tespit eder, neyi etmez

**Tespit eder (encoding'ler — anahtarsız çözülür):**
Base64 (standart + URL-safe), Base32, Base58, Base85/Ascii85, Base91, Hex, Binary, Octal, Decimal ASCII kodları, URL encoding, HTML entities, Unicode/hex escape (`\u`, `\x`), Quoted-Printable, JWT

**Tespit eder (klasik şifreler — brute-force ile çözülür):**
ROT13, ROT47, ROT5, ROT18, Atbash, Caesar (tüm 25 shift), Morse code, Bacon cipher, basit reverse, **Rail Fence** (2-8 ray denenir), **Affine** (tüm geçerli a/b kombinasyonları)

**Kırar (anahtar gerektiren ama brute-force ile aşılabilen zayıf şifrelemeler):**
- **XOR tek-byte** — 256 anahtarın tamamı denenir, en okunabilir sonuç seçilir
- **XOR tekrarlayan-anahtar** — Hamming distance ile anahtar uzunluğu tahmin edilir, sonra her sütun ETAOIN frekans tablosuyla tek tek kırılır (klasik Cryptopals yöntemi)
- **Vigenère** — Index of Coincidence ile anahtar uzunluğu tahmin edilir, sonra her sütun Caesar-crack ile kırılır

**Tespit eder ama kırmaya çalışmaz (gerçek kriptografik güvenlik var):**
AES, RSA (uygun anahtar/private key olmadan kırılamaz — araç bunu denemez), gerçek hash kırma (MD5/SHA çözülmez, sadece "bu bir hash" uyarısı verir — brute-force/rainbow table için CrackStation gibi özel araçlar gerekir)

Charset analiz kısmı hash formatlarını (MD5/SHA1/SHA256/SHA3/bcrypt/argon2 vb.), JWT yapısını ve UUID'leri tanıyıp uygun uyarı verir.

## Nasıl çalışıyor (skor mantığı)

`ciphertool/scorer.py` içinde:
- **Chi-kare testi**: harf frekans dağılımını standart İngilizce dağılımla karşılaştırır
- **Bigram analizi**: ardışık harf çiftlerinin (th, he, in, er...) İngilizce'de ne kadar yaygın olduğuna bakar — tek başına chi-kareden daha isabetli
- **Kelime eşleşmesi**: küçük bir İngilizce/Türkçe ortak kelime listesiyle eşleşen kelime oranı
- **Boşluk oranı**: doğal dilde makul boşluk yoğunluğu (~%8-30) bonus puan alır
- **Yazdırılabilirlik oranı**: çıktının ne kadarı yazdırılabilir ASCII

JWT gibi yapısal olarak doğrulanabilen sonuçlar (başarılı JSON parse) taban puan garantisi alır, çünkü tesadüfi metin skorlamasından çok daha güvenilir bir sinyaldir.

XOR/Vigenère sütun bazlı kırmada, çok kısa sütunlarda (az örnek) chi-kare testi gürültülü sonuç verdiği için ETAOIN frekans tablosu (boşluk dahil) kullanılıyor; anahtar uzunluğu tahmininde de "en küçük yeterli uzunluk" tercih ediliyor (yoksa gerçek uzunluğun 2x/3x katları yanlışlıkla seçilebiliyor).

Toplamda 0-100 arası bir skor üretilir. 65+ genelde doğru çözümdür, 35 altı büyük ihtimalle yanlış yol ya da gerçek şifrelenmiş veri.

## Performans

- Node ve zaman bütçesi var (varsayılan: 3500 node / 6 saniye) — çok büyük/karmaşık girdilerde motor sonsuza kadar dallanmaz
- Pahalı analizler (XOR/Vigenère/Rail Fence/Affine kırma) sadece orijinal girdi üzerinde çalışır, zincirin her adımında tekrarlanmaz — performans için

## Sınırlamalar / gelecek fikirleri

- Substitution cipher (genel, anahtar kelimesiz) brute-force'u yok — quipqiup tarzı dil modeli + hill-climbing eklenebilir
- Sadece İngilizce/Türkçe için optimize skor fonksiyonu var, başka dillerde frekans analizi zayıf kalır
- AES/RSA elbette kırılmıyor (kriptografik olarak güvenli), sadece "bu muhtemelen gerçek şifreleme" tespiti yapılıyor
- Playfair cipher brute-force'u yok

PR'lar açık. Kendi ihtiyacına göre `ciphertool/decoders.py`'a yeni decoder eklemek çok kolay: `(isim, fonksiyon, "encoding"|"cipher")` formatında `SINGLE_SHOT_DECODERS` listesine eklemen yeterli. Anahtar-brute-force gerektiren teknikler için `ciphertool/crack.py`'a bakabilirsin.

## Testler

```bash
python3 tests/test_basic.py
```

15 sanity test var (encoding'ler, klasik şifreler, XOR/Vigenère kırma, dosya tespiti, JWT).

## Lisans

MIT

