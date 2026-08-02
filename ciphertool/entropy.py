"""
Entropi analizi ve "gercek sifreleme mi yoksa cozulebilir encoding mi" ayrimi.

Onceden scorer.py'da tek bir esik-degerli fonksiyon (looks_like_binary_blob)
vardi ve HICBIR YERDE kullanilmiyordu (README'de "eklenmedi" diye not vardi).
Bu modul onun yerini alip CLI'ya tam bagli hale getiriyor:

- Shannon entropi (bit/byte) hesabi
- Byte dagilim duzgunlugu (uniform mu, yoksa belirli byte'lar mi baskin)
- AES-ECB moduna isaret eden 16-byte blok tekrari tespiti
- Sonucu net bir siniflandirmaya donusturme: "duz metin" / "yapisal veri
  (JSON/XML gibi)" / "sikistirilmis" / "muhtemelen gercek sifreleme veya
  rastgele veri"

Amac: bir decode zincirinin sonunda okunabilir metin CIKMIYORSA, kullaniciya
"bu daha fazla decode edilebilir bir sey degil, gercekten sifreli/rastgele"
diye AKTIF olarak soylemek - sessizce dusuk skor vermek yerine.
"""
import math
from collections import Counter
from dataclasses import dataclass
import string
@dataclass
class EntropyReport:
    entropy_bits_per_byte: float      # 0-8 arasi, 8 = tam rastgele
    length: int
    classification: str               # bkz. asagidaki sabitler
    note: str
    ecb_repeat_found: bool = False
    ecb_repeat_note: str = ""


CLASS_TEXT = "duz_metin"
CLASS_STRUCTURED = "yapisal_veri"
CLASS_COMPRESSED_OR_ENCRYPTED = "sikistirilmis_veya_sifreli"
CLASS_UNKNOWN = "belirsiz"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_ecb_repetition(data: bytes, block_size: int = 16) -> tuple:
    """AES-ECB modu her ayni 16-byte'lik plaintext blogunu HER ZAMAN ayni
    ciphertext blogu olarak sifreler - bu yuzden tekrarlayan blok bulunmasi
    guclu bir ECB isaretidir (CBC/CTR/GCM gibi modern modlarda bu olmaz).
    (bulundu_mu, kac_farkli_blok_tekrar_etti, toplam_blok_sayisi) dondurur."""
    if len(data) < block_size * 2:
        return False, 0, 0
    blocks = [data[i:i + block_size] for i in range(0, len(data) - len(data) % block_size, block_size)]
    counts = Counter(blocks)
    repeated = {b: c for b, c in counts.items() if c > 1}
    return (len(repeated) > 0, len(repeated), len(blocks))


def analyze_entropy(data: bytes) -> EntropyReport:
    """
    ONEMLI DUZELTME: Kucuk ornekle (orn. 32-128 byte, CTF'lerde tipik) gercek
    rastgele veri bile MUTLAK entropi olarak 8 bit/byte'a hicbir zaman ulasamaz
    -- cunku n orneklik veride en fazla n farkli deger olabilir, yani teorik
    tavan log2(min(n,256))'dir (orn. 64 byte'lik veri icin tavan 6.0, 8.0 degil).
    Sabit "entropy > 7.2" gibi mutlak bir esik bu yuzden kucuk orneklerde HICBIR
    ZAMAN tetiklenmiyordu (test ederken bunu fark ettim - 64 byte gercek
    os.urandom() cikisi bile entropy=5.6 verdi, mutlak esigin cok altinda kaldi).

    Duzeltme: entropiyi o ornek boyutu icin ULASILABILECEK MAKSIMUM entropiye
    ORANLA degerlendiriyoruz (relative entropy). Gercek rastgele/sifreli veri
    boyuttan bagimsiz olarak bu orana ~%89-96 yakin cikiyor (test ettim: n=32
    -> %96, n=512 -> %95), duz Ingilizce metin ise ~%65-75 civarinda kaliyor
    (harf frekans carpikligindan dolayi).
    """
    if not data:
        return EntropyReport(0.0, 0, CLASS_UNKNOWN, "Boş veri.")

    ent = shannon_entropy(data)
    n = len(data)
    max_possible_entropy = math.log2(min(n, 256)) if n > 1 else 1.0
    relative_entropy = ent / max_possible_entropy if max_possible_entropy > 0 else 0.0

    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    printable_ratio = printable / n

    ecb_found, ecb_blocks, total_blocks = detect_ecb_repetition(data)
    ecb_note = ""
    if ecb_found:
        ecb_note = (f"{ecb_blocks}/{total_blocks} blokta TEKRAR EDEN 16-byte blok bulundu -- "
                    "bu güçlü bir AES-ECB modu işareti (ECB aynı plaintext bloğunu her zaman "
                    "aynı şekilde şifreler, bu yüzden desenli/tekrarlı veri şifrelenmiş ECB "
                    "çıktısında da görünür kalır -- CBC/CTR/GCM gibi modern modlarda bu olmaz).")

    if printable_ratio > 0.90 and relative_entropy < 0.75:
        classification = CLASS_TEXT
        note = (f"Entropi oranı %{relative_entropy*100:.0f} (bu boyut için ulaşılabilecek maksimuma göre, "
                f"düşük) + %{printable_ratio*100:.0f} yazdırılabilir -- düz metin gibi görünüyor, muhtemelen "
                "doğru decode edildi ama başka bir katman daha var olabilir (skorlama düşükse başka "
                "encoding/cipher dene).")
    elif printable_ratio > 0.90 and relative_entropy < 0.85:
        classification = CLASS_STRUCTURED
        note = (f"Entropi oranı %{relative_entropy*100:.0f} + %{printable_ratio*100:.0f} yazdırılabilir -- "
                "yapısal veri (JSON/XML/CSV gibi tekrarlı syntax karakterleri içeren metin) olabilir.")
    elif relative_entropy >= 0.85:
        classification = CLASS_COMPRESSED_OR_ENCRYPTED
        note = (f"Entropi oranı %{relative_entropy*100:.0f} (bu {n} byte'lık örneklem için ulaşılabilecek "
                f"teorik maksimuma göre -- mutlak entropi {ent:.2f} bit/byte, tavan {max_possible_entropy:.2f}) "
                "-- bu artık 'decode edilecek bir encoding' DEĞİL, byte değerleri neredeyse tekdüze dağılmış. "
                "Ya (a) gerçek şifrelenmiş veri (AES/ChaCha20 vb, anahtar olmadan kırılamaz), (b) sıkıştırılmış "
                "veri (gzip/zlib/zip), ya da (c) kriptografik olarak rastgele üretilmiş veri (nonce/salt/anahtar). "
                "Klasik şifre kırma teknikleriyle 'çözülmeye' çalışmak anlamsızdır.")
    elif relative_entropy >= 0.78:
        classification = CLASS_UNKNOWN
        note = f"Entropi oranı %{relative_entropy*100:.0f} -- orta-yüksek, kısmen yapısal (binary format header'ı gibi) olabilir, kesin ayrım için daha fazla veri lazım."
    else:
        classification = CLASS_UNKNOWN
        note = f"Entropi oranı %{relative_entropy*100:.0f}, %{printable_ratio*100:.0f} yazdırılabilir -- net bir sınıflandırma yapılamadı."

    return EntropyReport(
        entropy_bits_per_byte=round(ent, 3), length=n, classification=classification,
        note=note, ecb_repeat_found=ecb_found, ecb_repeat_note=ecb_note,
    )
