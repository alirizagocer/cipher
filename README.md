# identify — Terminal Cipher / Encoding Identifier

Elindeki garip metnin ne olduğunu bilmiyorsan (Base64 mü, hex mi, ROT13 mi, hash mı, XOR ile mi şifrelenmiş...) bu araç:

1. Karakter setini/uzunluğunu analiz edip hızlı ipuçları verir (JWT, hash formatları, UUID dahil)
2. **Hash/KDF tespitini pattern-veritabanıyla yapar** — bcrypt/argon2/md5crypt/sha512crypt/Django PBKDF2 gibi yapısal olarak KESİN formatları %95+ güvenle tek adayla söyler; sadece hex uzunluğundan ayırt edilebilen durumlarda (örn. 32 hex → MD5 mi NTLM mi MD4 mü) TÜM adayları ayrı ayrı, gerçek-dünya yaygınlığına göre ağırlıklandırılmış yüzdelerle sıralar — asla "bunlardan biri" diye geçiştirmez
3. Bilinen tüm encoding/cipher'ları otomatik dener (Base64/32/36/45/58/85/91, Hex, Binary, Octal, Decimal, URL/HTML/Unicode escape, Quoted-Printable, ROT13/47/5/18, Atbash, Caesar (25 shift), Morse, Bacon, Polybius Square)
4. **Anahtar gerektiren zayıf şifrelemeleri brute-force ile kırar**: XOR (tek-byte ve tekrarlayan anahtar — Hamming distance ile anahtar uzunluğu tahmini), Vigenère ve Beaufort (Index of Coincidence ile), Rail Fence, Affine
5. **Dosya imzası (magic byte) tespiti** — decode edilen veri aslında bir PNG/ZIP/PDF/ELF/GZIP dosyasıysa bunu anında söyler (CyberChef'in "Detect File Type" özelliğinin offline karşılığı)
6. **JWT tespiti** — header.payload.signature yapısını tanır, JSON içeriğini decode edip gösterir
7. Sonuçları **3 katmana kadar zincirleme** dener (Base64 → ROT13 → Hex gibi)
8. Her sonucu chi-kare harf frekansı + bigram analizi + kelime eşleşmesi + yazdırılabilirlik oranıyla **0-100 arası skorlar**
9. **Hash/KDF gibi kesin olarak tespit edilen girdilerde anlamsız klasik-şifre kırma denemelerini otomatik atlar** — eskiden bir MD5 hash'i Caesar/Affine ile "kırmaya" çalışıp %40 gibi yanıltıcı skorlu çöp sonuçlar üretiyordu, artık üretmiyor
10. En yüksek skorlu adayı en üstte gösterir

CyberChef'in "Magic" özelliğinin terminal/offline, açık kaynak versiyonu gibi düşünebilirsin — üstüne klasik kriptanaliz (XOR/Vigenère/Beaufort kırma) ve hashID tarzı pattern-tabanlı hash tespiti de ekli.

## Kurulum

```bash
git clone <github.com/alirizagocer/cipher>
cd ciphertool
pip install -e .
```


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

Hash tespiti örneği (yapısal olarak kesin format):
```
=== Karakter Seti Analizi ===
  - Uzunluk: 60 karakter
  - KESIN TESPIT (yapisal formattan, %99+ guven):
    -> bcrypt  [%99]  '$2a$/$2b$/$2y$' + cost faktoru -> bcrypt imzasi, format olarak kesin.
```

Hash tespiti örneği (sadece uzunluktan tahmin, tüm adaylar ayrı ayrı):
```
  - Uzunluk/format tek basina KESIN ayirt etmiyor -- en olasi 5 aday
    gercek-dunya yayginligina gore siralandi:
    1. MD5  -- tahmini olasilik: %55   En yaygın 32-hex hash...
    2. NTLM -- tahmini olasilik: %20   Windows/AD parola hash'i...
    3. MD4  -- tahmini olasilik: %8    NTLM'in temeli...
    4. RIPEMD-128 -- tahmini olasilik: %7
    5. Haval-128  -- tahmini olasilik: %5
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
Base64 (standart + URL-safe), Base32, Base36, Base45, Base58, Base85/Ascii85, Base91, Hex, Binary, Octal, Decimal ASCII kodları, URL encoding, HTML entities, Unicode/hex escape (`\u`, `\x`), Quoted-Printable, JWT

**Tespit eder (klasik şifreler — brute-force ile çözülür):**
ROT13, ROT47, ROT5, ROT18, Atbash, Caesar (tüm 25 shift), Morse code, Bacon cipher, Polybius Square (5x5), basit reverse, **Rail Fence** (2-8 ray denenir), **Affine** (tüm geçerli a/b kombinasyonları)

**Kırar (anahtar gerektiren ama brute-force ile aşılabilen zayıf şifrelemeler):**
- **XOR tek-byte** — 256 anahtarın tamamı denenir, en okunabilir sonuç seçilir
- **XOR tekrarlayan-anahtar** — Hamming distance ile anahtar uzunluğu tahmin edilir, sonra her sütun ETAOIN frekans tablosuyla tek tek kırılır (klasik Cryptopals yöntemi)
- **Vigenère** — Index of Coincidence ile anahtar uzunluğu tahmin edilir, sonra her sütun Caesar-crack ile kırılır
- **Beaufort** — Vigenère'in matematiksel kardeşi (P = K − C mod 26), aynı IC tabanlı anahtar uzunluğu tahminiyle ayrı bir sütun-kırma formülü kullanır

**Hash/KDF tespiti (kırma değil, TANIMA — `ciphertool/hashid.py`):**
- **Yapısal olarak KESİN formatlar** (%90-99 güven, tek aday): bcrypt, md5crypt, sha256crypt, sha512crypt, scrypt, Argon2 (i/d/id), yescrypt, phpass (WordPress/phpBB), LDAP SSHA/SHA, Django SHA1/PBKDF2-SHA256, genel PBKDF2 — hepsi prefix/delimiter imzasından kesin olarak tanınır
- **Sadece uzunluktan tahmin edilen durumlar**: her hex uzunluğu (8/16/32/40/56/64/96/128) için TÜM olası algoritmalar ayrı ayrı isimlendirilip gerçek-dünya yaygınlığına göre ağırlıklandırılmış "tahmini olasılık" yüzdesiyle listelenir (örn. 32 hex → MD5 %55, NTLM %20, MD4 %8, RIPEMD-128 %7, Haval-128 %5). Girdi tamamen büyük harfse NTLM ihtimali hafifçe yukarı, MD5 hafifçe aşağı çekilir (mimikatz/hashcat çıktıları genelde büyük harf).
- **Asla tek cümlede "bunlardan biri" diye geçiştirmez** — her aday kendi satırında, kendi yüzdesiyle.

**Tespit eder ama kırmaya çalışmaz (gerçek kriptografik güvenlik var):**
AES, RSA (uygun anahtar/private key olmadan kırılamaz — araç bunu denemez), gerçek hash kırma (MD5/SHA çözülmez, sadece "bu hangi algoritma" tespiti yapılır — brute-force/rainbow table için hashcat/John the Ripper gibi özel araçlar gerekir)

## Nasıl çalışıyor (skor mantığı)

`ciphertool/scorer.py` içinde:
- **Chi-kare testi**: harf frekans dağılımını standart İngilizce dağılımla karşılaştırır
- **Bigram analizi**: ardışık harf çiftlerinin (th, he, in, er...) İngilizce'de ne kadar yaygın olduğuna bakar — tek başına chi-kareden daha isabetli
- **Kelime eşleşmesi**: küçük bir İngilizce/Türkçe ortak kelime listesiyle eşleşen kelime oranı (2 harften kısa kelimeler kredi almaz — yoksa Türkçe "de/da/mi" gibi baglaçlar rastgele 2-karakterlik çıktılarda tesadüfen eşleşip yanlış-pozitif yüksek skor üretiyordu)
- **Boşluk oranı**: doğal dilde makul boşluk yoğunluğu (~%8-30) bonus puan alır
- **Yazdırılabilirlik oranı**: çıktının ne kadarı yazdırılabilir ASCII
- **Gürültü tavanı**: gerçek kelime eşleşmesi yok VE bigram sinyali zayıfsa (ya da harf sayısı çok azsa) toplam skor sert biçimde sınırlanır — bu, hash'leri Caesar/Affine ile "kırmaya" çalışınca çıkan yarı-rastgele string'lerin yanlışlıkla %35-45 gibi güven verici skorlar almasını engeller

JWT gibi yapısal olarak doğrulanabilen sonuçlar (başarılı JSON parse) taban puan garantisi alır, çünkü tesadüfi metin skorlamasından çok daha güvenilir bir sinyaldir.

XOR/Vigenère/Beaufort sütun bazlı kırmada, çok kısa sütunlarda (az örnek) chi-kare testi gürültülü sonuç verdiği için ETAOIN frekans tablosu (boşluk dahil) kullanılıyor; anahtar uzunluğu tahmininde de "en küçük yeterli uzunluk" tercih ediliyor (yoksa gerçek uzunluğun 2x/3x katları yanlışlıkla seçilebiliyor).

Toplamda 0-100 arası bir skor üretilir. 65+ genelde doğru çözümdür, 35 altı büyük ihtimalle yanlış yol ya da gerçek şifrelenmiş veri.

**Bilinen istatistiksel sınır**: 2-3 karakterlik çok kısa doğru çözümler (örn. "AB") istatistiksel olarak rastgele kısa string'lerden ayırt edilemeyebilir — bu chi-kare/bigram gibi frekans tabanlı yöntemlerin temel bir sınırıdır, tek çözüm sözlük/dil-modeli tabanlı doğrulama (bkz. "Sınırlamalar" bölümü).

## Performans

- Node ve zaman bütçesi var (varsayılan: 3500 node / 6 saniye) — çok büyük/karmaşık girdilerde motor sonsuza kadar dallanmaz
- Pahalı analizler (XOR/Vigenère/Beaufort/Rail Fence/Affine kırma) sadece orijinal girdi üzerinde çalışır, zincirin her adımında tekrarlanmaz — performans için
- **Hash/KDF olarak tespit edilen girdilerde decode/cipher denemeleri tamamen atlanır** — hem performans hem doğruluk kazancı

## Sınırlamalar / gelecek fikirleri

- Substitution cipher (genel, anahtar kelimesiz) brute-force'u yok — quipqiup tarzı dil modeli + hill-climbing eklenebilir (en değerli sıradaki eklenti)
- Sadece İngilizce/Türkçe için optimize skor fonksiyonu var, başka dillerde frekans analizi zayıf kalır
- AES/RSA elbette kırılmıyor (kriptografik olarak güvenli), sadece "bu muhtemelen gerçek şifreleme" tespiti yapılıyor (entropi analizi `scorer.looks_like_binary_blob` içinde var ama CLI çıktısına henüz bağlı değil)
- Playfair, Hill cipher, ADFGVX brute-force'u yok
- Hash tespitindeki yüzdeler gerçek-dünya yaygınlığına göre KABA bir tahmindir, istatistiksel kanıt değildir — kesin ayrım için verinin kaynağına (Windows dump/git/TLS sertifikası vb.) bakmak gerekir

PR'lar açık. Kendi ihtiyacına göre `ciphertool/decoders.py`'a yeni decoder eklemek çok kolay: `(isim, fonksiyon, "encoding"|"cipher")` formatında `SINGLE_SHOT_DECODERS` listesine eklemen yeterli. Anahtar-brute-force gerektiren teknikler için `ciphertool/crack.py`'a, yeni hash/KDF pattern'i eklemek için `ciphertool/hashid.py`'daki `PREFIX_PATTERNS` / `LENGTH_CANDIDATES` listelerine bakabilirsin.

## Testler

```bash
python3 tests/test_basic.py
```

26 sanity test var (encoding'ler, klasik şifreler, XOR/Vigenère/Beaufort kırma, dosya tespiti, JWT, hash tespiti).

## Lisans

MIT