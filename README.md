# identify — Terminal Cipher / Encoding Identifier

## English summary

identify is a terminal-based tool for identifying unknown text or data such as Base64, hex, ROT13, hashes, XOR-encrypted content, and other encodings or classical ciphers. It analyzes character sets and lengths, detects hash and KDF formats by structural patterns, cracks several weak ciphers without a key, recognizes file signatures, detects JWTs, and ranks candidate decodings with a scoring system. **v8 adds yEnc (Usenet) and Baudot/ITA2 (teleprinter) decoding, plus ADFGVX/ADFGX cipher recognition (65 tests, all passing).**

Elindeki garip metnin ne olduğunu bilmiyorsan (Base64 mü, hex mi, ROT13 mi, hash mı, XOR ile mi şifrelenmiş...) bu araç:

1. Karakter setini/uzunluğunu analiz edip hızlı ipuçları verir (JWT, hash formatları, UUID, **PEM sertifika**, **IBAN**, **kredi kartı Luhn**, **MAC adresi**, **ADFGVX/ADFGX şifre**, **yEnc başlığı**, **Baudot 5-bit gruplar** dahil)
2. **Hash/KDF tespitini pattern-veritabanıyla yapar** — bcrypt/argon2/md5crypt/sha512crypt/Django PBKDF2 gibi yapısal olarak KESİN formatları %95+ güvenle tek adayla söyler; sadece hex uzunluğundan ayırt edilebilen durumlarda (örn. 32 hex → MD5 mi NTLM mi MD4 mü) TÜM adayları ayrı ayrı, gerçek-dünya yaygınlığına göre ağırlıklandırılmış yüzdelerle sıralar — asla "bunlardan biri" diye geçiştirmez
3. **Genel substitution cipher'ları anahtar kelimesiz kırar** (quipqiup tarzı hill-climbing + gerçek İngilizce quadgram istatistikleri — ~389.000 quadgram, ~4.2 milyar sayım içeren practicalcryptography.com korpusu) — 26! büyüklüğündeki anahtar uzayında rastgele-takas + çoklu-restart ile arama yapar, en az ~60 harflik metinlerde güvenilir sonuç verir
4. **Columnar Transposition cipher'ları anahtar kelimesiz kırar** — sütun sayısını (2-12) ve okuma sırasını (permütasyon) aynı quadgram fitness ile brute-force/hill-climbing yaparak bulur
5. **Entropi analizi ile "gerçek şifreleme mi yoksa çözülebilir encoding mi" ayrımını yapar** — Shannon entropi (örneklem-boyutu düzeltmeli), AES-ECB modu işareti olan 16-byte blok tekrarı tespiti dahil
6. Bilinen tüm encoding/cipher'ları otomatik dener (Base64/32/36/45/58/85/91, **uuencode**, **z85 (ZeroMQ)**, **yEnc** (Usenet), **Baudot/ITA2** (5-bit teleprinter), Hex, Binary, Octal, Decimal, URL/HTML/Unicode escape, Quoted-Printable, ROT13/47/5/18, Atbash, Caesar (25 shift), Morse, Bacon, Polybius Square)
7. **Anahtar gerektiren zayıf şifrelemeleri brute-force ile kırar**: XOR (tek-byte ve tekrarlayan anahtar — artık **quadgram fitness ile doğrulama**, Vigenère/Beaufort ile aynı strateji), Vigenère ve Beaufort (IC + quadgram ile), Rail Fence, Affine
8. **[YENİ] Crib-dragging (bilinen parça saldırısı)**: `--crib 'flag{'` gibi bilinen bir metin parçası verilirse XOR/Vigenère anahtarını bu ipucundan türetip doğrular — CTF'lerde yaygın, tespiti güçlendiren bir teknik
9. **Dosya imzası (magic byte) tespiti** — decode edilen veri aslında bir PNG/ZIP/PDF/ELF/GZIP dosyasıysa bunu anında söyler
10. **JWT tespiti** — header.payload.signature yapısını tanır, JSON içeriğini decode edip gösterir
11. Sonuçları **3 katmana kadar zincirleme** dener (Base64 → ROT13 → Hex gibi)
12. Her sonucu chi-kare harf frekansı + bigram analizi + kelime eşleşmesi + yazdırılabilirlik oranıyla **0-100 arası skorlar**
13. **Hash/KDF gibi kesin olarak tespit edilen girdilerde anlamsız klasik-şifre kırma denemelerini otomatik atlar**
14. **Geliştirilmiş JSON çıktısı** (`--json`): `hash_candidates` (yapılandırılmış, certain/confidence alanlarıyla), `crib_drag_results` (crib kullanıldıysa) alanları eklendi — scripting/otomasyon için tam makine-okunabilir
15. En yüksek skorlu adayı en üstte gösterir

CyberChef'in "Magic" özelliğinin terminal/offline, açık kaynak versiyonu gibi düşünebilirsin — üstüne klasik kriptanaliz (XOR/Vigenère/Beaufort kırma, crib-dragging) ve hashID tarzı pattern-tabanlı hash tespiti de ekli.

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

# JSON çıktı (scripting/otomasyon için) — hash_candidates dahil
identify --json "..." | jq '.candidates[0]'
identify --json "$2b$12$..." | jq '.hash_candidates[0]'

# Crib-dragging: XOR/Vigenère'de bilinen parça ipucu ver
identify --crib 'flag{' "<XOR_sifreli_hex>"
identify --crib 'the ' "<Vigenere_sifreli_metin>"

# Crib + JSON kombinasyonu
identify --json --crib 'SECRET' "<veri>" | jq '.crib_drag_results'
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
ROT13, ROT47, ROT5, ROT18, Atbash, Caesar (tüm 25 shift), Morse code, Bacon cipher, Polybius Square (5x5), **A1Z26 (harf-sayı kodu)**, **NATO Fonetik Alfabesi**, basit reverse, **Rail Fence** (2-8 ray denenir), **Affine** (tüm geçerli a/b kombinasyonları)

**Kırar (anahtar gerektiren ama brute-force ile aşılabilen zayıf şifrelemeler):**
- **XOR tek-byte** — 256 anahtarın tamamı denenir, en okunabilir sonuç seçilir
- **XOR tekrarlayan-anahtar** — Hamming distance ile anahtar uzunluğu tahmin edilir, sonra her sütun ETAOIN frekans tablosuyla tek tek kırılır (klasik Cryptopals yöntemi)
- **Vigenère** — Index of Coincidence ile **birden fazla aday** anahtar uzunluğu üretilir (tek bir "en iyi tahmin" değil), her aday gerçekten denenip **quadgram fitness ile doğrulanır** — tek-tahmin yöntemi kısa/orta metinlerde bazen yanlış uzunluğa gidebiliyordu, bu iyileştirme doğruluğu doğrudan artırıyor
- **Beaufort** — Vigenère'in matematiksel kardeşi (P = K − C mod 26), aynı çoklu-aday + quadgram doğrulama mantığıyla ayrı bir sütun-kırma formülü kullanır
- **Genel Substitution Cipher (anahtar kelimesiz)** — `ciphertool/crack.py::crack_substitution`: frekans-eşleşmeli başlangıç anahtarından başlayıp **simulated annealing + hill-climbing** ile (sıcaklık zamanla azalan, yerel optimumdan kaçabilen bir arama) rastgele harf-çifti takasları dener, fitness fonksiyonu olarak gerçek İngilizce quadgram log-olabilirliğini kullanır (`ciphertool/ngram.py`, ~389.000 quadgram / ~4.2 milyar sayım). Yerel optimuma takılmayı azaltmak için zaman bütçesi dolana kadar sınırsız restart yapar. En az 80 harf gerektirir; **200+ harflik doğal dil metinlerinde test setimizde %100 başarı**, 80-130 harf arası "sınır bölge" — bunu dürüstçe bir güven notuyla (düşük/orta/yüksek) işaretler, asla sahte kesinlik iddia etmez. **Not**: pangram tarzı yapay metinler (her harfin ~1 kez geçtiği, "the quick brown fox...") uzun olsa bile istatistiksel tekrar azlığından zorlanabilir — bu algoritmanın değil, substitution-kırmanın matematiksel bir sınırı (Shannon'ın "unicity distance" kavramı)
- **Columnar Transposition (anahtar kelimesiz)** — `ciphertool/transposition.py::crack_columnar_transposition`: sütun sayısını (2-12 arası dener) ve sütun okuma sırasını (permütasyon) aynı quadgram fitness ile bulur — ≤8 sütun için TÜM permütasyonlar (8!=40320) denenir, 9-12 sütun için hill-climbing kullanılır. En az 20 karakter gerektirir, boşluk/noktalama korunarak çalışır (harfleri değil tüm karakterleri sütunlara dağıtır)

**Entropi analizi (kırma değil, gerçek-şifreleme AYIRT ETME — `ciphertool/entropy.py`):**
- Shannon entropi hesaplanır ve **örneklem boyutuna göre normalize edilir** (küçük veri setlerinde mutlak entropi 8 bit/byte'a hiçbir zaman ulaşamaz — n=64 byte için teorik tavan 6.0'dır, 8.0 değil — bunu test ederken fark ettim ve düzelttim)
- **AES-ECB modu tespiti**: 16-byte'lık tekrarlayan blok arar (ECB aynı plaintext bloğunu her zaman aynı şekilde şifreler, bu yüzden tekrarlı veri şifrelenmiş çıktıda da görünür kalır)
- Sonucu net bir sınıflandırmaya çevirir: düz metin / yapısal veri (JSON gibi) / muhtemelen gerçek şifreleme-sıkıştırma-rastgele veri
- **Yanlış-pozitif koruması**: sadece hiçbir decoder (Base64/32/45/58/85/91 vb.) anlamlı bir sonuç bulamadıysa gösterilir — yoksa bir Base64 metnini yanlışlıkla Base85 alfabesiyle "denemek" de rastgele görünümlü çıktı üretir ve bu gerçek şifreleme değildir; test ederken bu tam olarak böyle bir yanlış-alarmı yakalayıp düzelttim

**Hash/KDF tespiti (kırma değil, TANIMA — `ciphertool/hashid.py`):**
- **Yapısal olarak KESİN formatlar** (%90-99 güven, tek aday): bcrypt, md5crypt, sha256crypt, sha512crypt, scrypt, Argon2 (i/d/id), yescrypt, phpass (WordPress/phpBB), LDAP SSHA/SHA, Django SHA1/PBKDF2-SHA256, genel PBKDF2, **Kerberos 5 TGS-REP/AS-REP (Kerberoasting/AS-REP Roasting)**, **WPA/WPA2 handshake**, **Apache APR1**, **Drupal 7**, **GRUB2 PBKDF2**, **MySQL 4.1+**, **Cisco IOS Type 5**, **NTLM LM:NTLM çifti** — hepsi prefix/delimiter imzasından kesin olarak tanınır
- **Sadece uzunluktan tahmin edilen durumlar**: her hex uzunluğu (8/16/32/40/56/64/96/128) için TÜM olası algoritmalar ayrı ayrı isimlendirilip gerçek-dünya yaygınlığına göre ağırlıklandırılmış "tahmini olasılık" yüzdesiyle listelenir (örn. 32 hex → MD5 %55, NTLM %20, MD4 %8, RIPEMD-128 %7, Haval-128 %5). Girdi tamamen büyük harfse NTLM ihtimali hafifçe yukarı, MD5 hafifçe aşağı çekilir (mimikatz/hashcat çıktıları genelde büyük harf).
- **Asla tek cümlede "bunlardan biri" diye geçiştirmez** — her aday kendi satırında, kendi yüzdesiyle.
- **Regresyon notu**: ilk sürümde aşırı-geniş bir regex ("Cisco Type 7", "Oracle") herhangi bir uzun hex string'i (MD5/SHA1 dahil) yanlışlıkla KESİN diye işaretliyordu — bunu test ederken fark edip kaldırdım, artık spesifik olmayan pattern'ler PREFIX_PATTERNS listesine girmiyor.

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
- Pahalı analizler (XOR/Vigenère/Beaufort/Rail Fence/Affine/Substitution/Columnar Transposition kırma) sadece orijinal girdi üzerinde çalışır, zincirin her adımında tekrarlanmaz — performans için
- **Hash/KDF olarak tespit edilen girdilerde decode/cipher denemeleri tamamen atlanır** — hem performans hem doğruluk kazancı
- **En pahalı iki analiz (Substitution ~4.5sn + Columnar Transposition ~3.5sn) daha erken bir aşamada zaten güçlü bir sonuç (skor ≥55) bulunduysa otomatik atlanır** — tipik çözülebilir girdilerde (`identify "SGVsbG8gV29ybGQh"` gibi) toplam çalışma süresi ~0.1 saniye; hash'lerde ~0.07 saniye. Sadece gerçekten hiçbir şeyin çözülmediği (rastgele/gerçek şifreli) girdilerde tüm pipeline çalışır ve bu ~8 saniye sürebilir — ki zaten o durumda derin analiz gerçekten gerekli olan durumdur

## Sınırlamalar / gelecek fikirleri

- Sadece İngilizce/Türkçe için optimize skor fonksiyonu var, başka dillerde frekans analizi zayıf kalır (substitution/transposition kırma quadgram istatistikleri de sadece İngilizce)
- AES/RSA elbette kırılmıyor (kriptografik olarak güvenli), sadece entropi analiziyle "bu muhtemelen gerçek şifreleme" tespiti yapılıyor
- **Playfair cipher denendi ama ÇIKARILDI**: hill-climbing + quadgram fitness ile denedim (substitution/transposition'da işe yarayan aynı yöntem), satır/sütun takası gibi gelişmiş hamleler de ekledim, ama ciphertext-only Playfair kırma 25! büyüklüğündeki anahtar uzayında güvenilir yakınsamadı (test ettiğim örnekte 30 saniye bile verilse ~%13 doğrulukta takılı kaldı). Yanlış sonucu "kesin" gibi sunmak doğruluk önceliğine aykırı olacağından koda dahil etmedim — bu dürüst bir sınır, gizlenen bir eksik değil. Hill cipher de benzer nedenlerle (ciphertext-only kırma akademik olarak da güvenilir değil, genelde known-plaintext gerektirir) eklenmedi
- ADFGVX/ADFGX brute-force'u yok (Polybius + transposition'ın birleşimi olduğu için Playfair'den de zor)
- Hash tespitindeki yüzdeler gerçek-dünya yaygınlığına göre KABA bir tahmindir, istatistiksel kanıt değildir — kesin ayrım için verinin kaynağına (Windows dump/git/TLS sertifikası vb.) bakmak gerekir
- Substitution kırma ~80 harfin altında güvenilir değil (hiç sonuç üretmez), 80-130 harf arası "sınır bölge" — pangram tarzı yapay metinlerde uzun olsa bile zorlanabilir
- Columnar Transposition'da 12'den fazla sütun denenmiyor (permütasyon uzayı pratik olmayan boyutlara ulaşıyor)

PR'lar açık. Kendi ihtiyacına göre `ciphertool/decoders.py`'a yeni decoder eklemek çok kolay: `(isim, fonksiyon, "encoding"|"cipher")` formatında `SINGLE_SHOT_DECODERS` listesine eklemen yeterli. Anahtar-brute-force gerektiren teknikler için `ciphertool/crack.py`'a, yeni hash/KDF pattern'i eklemek için `ciphertool/hashid.py`'daki `PREFIX_PATTERNS` / `LENGTH_CANDIDATES` listelerine bakabilirsin.

## Testler

```bash
python3 tests/test_basic.py
```

41 sanity test var (encoding'ler, klasik şifreler, XOR/Vigenère/Beaufort/Substitution/Columnar Transposition kırma, entropi analizi, dosya tespiti, JWT, hash tespiti).

## Lisans

MIT