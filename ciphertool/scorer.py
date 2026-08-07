"""
Decode edilmis metnin "anlamli/okunabilir" olma ihtimalini puanlar.
Chi-kare harf frekans analizi + yaygin kelime eslesmesi + yazdirilabilirlik orani.
"""
import re
import string

# Kaynak: standart İngilizce harf frekans dağılımı (yüzde)
ENGLISH_FREQ = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23,
    'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03,
    'm': 2.41, 'n': 6.75, 'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99,
    's': 6.33, 't': 9.06, 'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15,
    'y': 1.97, 'z': 0.07,
}

# Kucuk bir ortak kelime seti (Ingilizce + Turkce) - hizli kontrol icin
COMMON_WORDS = {
    # English
    "the", "and", "you", "that", "was", "for", "are", "with", "this",
    "have", "from", "not", "but", "what", "all", "were", "when", "your",
    "can", "said", "there", "use", "each", "which", "she", "how", "will",
    "flag", "password", "user", "admin", "secret", "key", "token", "true",
    "false", "http", "https", "www", "com", "hello", "world", "test",
    # Turkish
    "ve", "bir", "bu", "için", "ile", "olan", "olarak", "değil", "gibi",
    "daha", "çok", "her", "ben", "sen", "biz", "şu", "ama", "de", "da",
    "mi", "mı", "ki", "ise", "kadar", "sonra", "önce", "merhaba", "dünya",
    "parola", "şifre", "kullanıcı", "yönetici",
    # German (Almanca)
    "der", "die", "und", "den", "von", "das", "mit", "sich", "des", "auf",
    "für", "ist", "im", "dem", "nicht", "ein", "eine", "als", "auch", "es",
    # Spanish (İspanyolca)
    "el", "la", "de", "que", "en", "un", "ser", "se", "no", "haber", "por",
    "con", "su", "para", "como", "estar", "tener", "le", "lo", "todo", "pero",
    # French (Fransızca)
    "le", "la", "de", "et", "un", "les", "que", "qui", "en", "dans", "pour",
    "par", "sur", "pas", "est", "des", "une", "plus", "avec", "il", "sont",
}

# En sik gorulen Ingilizce bigram'lar (yaklasik goreceli agirlik).
# Kaynak: genel Ingilizce metin istatistikleri, kaba yuvarlama.
ENGLISH_BIGRAMS = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99, "re": 1.85,
    "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35, "ti": 1.34, "es": 1.34,
    "or": 1.28, "te": 1.20, "of": 1.17, "ed": 1.17, "is": 1.13, "it": 1.12,
    "al": 1.09, "ar": 1.07, "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95,
    "se": 0.93, "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.76, "ri": 0.73,
    "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69, "ra": 0.69, "ce": 0.65,
    "li": 0.62, "ch": 0.60, "ll": 0.58, "be": 0.58, "ma": 0.57, "si": 0.55,
    "om": 0.55, "ur": 0.54,
}

_word_re = re.compile(r"[a-zA-ZçğıöşüÇĞİÖŞÜ]+")


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if c in string.printable)
    return printable / len(s)


def chi_squared_english(s: str) -> float:
    """Dusuk deger = Ingilizce harf dagilimina daha yakin."""
    letters = [c.lower() for c in s if c.isalpha() and c.lower() in ENGLISH_FREQ]
    n = len(letters)
    if n < 4:
        return 999.0  # yetersiz veri, guvenilmez
    counts = {}
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    chi2 = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        expected = expected_pct / 100.0 * n
        observed = counts.get(letter, 0)
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


def word_match_score(s: str) -> float:
    """Kelime eslesmesi puani. 2 harfli Turkce baglaclar ('de','da','mi'...) KISA
    rastgele ciktilarda (orn. bir sifre zincirinin yanlislikla urettigi 2 karakterlik
    string) tesadufen cok sik eslesip yanlis-pozitif yuksek skor uretiyordu - bu
    yuzden <3 harfli kelimeler kredi HAK ETMEZ, sadece >=3 harfli gercek kelime
    eslesmeleri sayilir."""
    words = _word_re.findall(s.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if len(w) >= 3 and w in COMMON_WORDS)
    return hits / max(len(words), 1)


def space_ratio(s: str) -> float:
    if not s:
        return 0.0
    return s.count(" ") / len(s)


def bigram_score(s: str) -> float:
    """0-25 arasi puan: ardisik harf ciftlerinin Ingilizce'de ne kadar yaygin oldugu."""
    letters = [c.lower() for c in s if c.isalpha()]
    if len(letters) < 4:
        return 0.0
    total, hits = 0, 0.0
    for i in range(len(letters) - 1):
        bg = letters[i] + letters[i + 1]
        total += 1
        hits += ENGLISH_BIGRAMS.get(bg, 0.0)
    if total == 0:
        return 0.0
    avg = hits / total
    return min(avg * 7.0, 25.0)


def index_of_coincidence(s: str) -> float:
    """Standart IC formulu. Ingilizce duz metin ~0.065-0.07, rastgele ~0.038."""
    from collections import Counter
    letters = [c.lower() for c in s if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def score_text(s: str) -> float:
    """
    0-100 arasi skor dondurur. Yuksek skor = daha okunabilir/anlamli metin.

    Onemli: kisa/seyrek harfli girdilerde (orn. bir hash'i yanlislikla Caesar/Affine
    ile "kirmaya" calisinca ortaya cikan yari-rastgele string) chi-kare + bigram
    testleri yanlislikla orta seviyede (35-45) puan verebiliyordu - bu YANLIS
    GUVEN veriyordu. Asagidaki "gurultu tavani" bunu onluyor: gercek kelime
    eslesmesi yoksa VE bigram sinyali zayifsa, toplam skor sert sekilde
    sinirlaniyor (noise ceiling).
    """
    if not s:
        return 0.0

    pr = printable_ratio(s)
    if pr < 0.85:
        return round(pr * 15, 2)

    letters = [c for c in s if c.isalpha()]
    n_letters = len(letters)

    chi2 = chi_squared_english(s)
    chi_score = max(0.0, 25.0 - min(chi2, 400) / 16.0)

    bg_score = bigram_score(s)
    word_score = word_match_score(s) * 25.0

    sp = space_ratio(s)
    space_score = 10.0 if 0.08 <= sp <= 0.30 else (5.0 if sp > 0 else 0.0)

    printable_score = pr * 15.0

    total = chi_score + bg_score + word_score + space_score + printable_score

    # KATI FALSE-POSITIVE FILTRESI (Kisa metinler icin):
    # Eger metin 15 karakterden kisaysa ve icinde hic gercek kelime eslesmediyse
    # bu muhtemelen rastgele bir string'tir, tesadufi chi/bigram puanlari ciddiye alinmamalidir.
    if len(s) < 15 and word_score == 0.0:
        total *= 0.2  # Cok sert ceza

    if total > 50.0 and word_score == 0.0 and bg_score < 5.0 and len(letters) < 15:
        total = 35.0

    # Yapısal veri bonusu: JSON, XML, URL, email decode edilmisse cok guclu sinyal
    struct_bonus = _structural_bonus(s)
    total += struct_bonus

    # Gurultu tavani: az harf var (hex/hash gibi kisa alfa oranli girdi), gercek
    # kelime eslesmesi yok ve bigram sinyali zayifsa -> bu buyuk ihtimalle
    # rastgele/anlamsiz cikti, chi-kare'nin sans eseri dusuk gelmesine ragmen
    # skoru 20'nin ustune cikarma.
    if word_score == 0 and bg_score < 8 and struct_bonus == 0:
        total = min(total, 18.0)
    # Cok az harf (n<10) uzerinden hesaplanan chi-kare/bigram istatistiksel
    # olarak guvenilmez - kelime eslesmesi yoksa ek tavan uygula.
    if n_letters < 10 and word_score == 0 and struct_bonus == 0:
        total = min(total, 15.0)

    return round(min(total, 100.0), 2)


def looks_like_binary_blob(raw_bytes: bytes) -> bool:
    """Yuksek entropili / rastgele veri mi? (sifreli veri veya sikistirilmis dosya belirtisi)"""
    if not raw_bytes:
        return False
    from collections import Counter
    import math
    counts = Counter(raw_bytes)
    n = len(raw_bytes)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy > 7.2  # 8'e yakin = neredeyse tam rastgele


# ---------------------------------------------------------------------------
# Yapısal veri tanıma — bunlar decode başarısını kuvvetle gösterir
# ---------------------------------------------------------------------------

def _structural_bonus(s: str) -> float:
    """JSON, XML, URL, email gibi yapisal formatlari taniyan bonus puanlayici.
    Bu veri tipleri decode edildiginde anlamli sonuc uretildiginin guclu kaniti.
    Maksimum +30 puan dondurur."""
    bonus = 0.0

    stripped = s.strip()

    # JSON object veya array
    if (stripped.startswith("{") and stripped.endswith("}")) or \
       (stripped.startswith("[") and stripped.endswith("]")):
        try:
            import json as _json
            _json.loads(stripped)
            bonus += 28.0  # gecerli JSON - cok gucu bir sinyal
        except Exception:
            # Gecerli JSON degil ama JSON-gibi goruntu
            if re.search(r'"[^"]+"\s*:', stripped):
                bonus += 12.0
    # XML/HTML
    elif re.search(r"<[a-zA-Z][a-zA-Z0-9]*[\s>]", stripped) and "</" in stripped:
        bonus += 20.0

    # URL'ler
    url_count = len(re.findall(r"https?://[^\s\"'<>]+", stripped))
    if url_count >= 1:
        bonus += min(url_count * 8.0, 20.0)

    # Email adresleri
    email_count = len(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", stripped))
    if email_count >= 1:
        bonus += min(email_count * 6.0, 15.0)

    # Base path / dosya yolu (Linux/Windows)
    if re.search(r"(/[a-zA-Z0-9_\-./]+){2,}", stripped) or \
       re.search(r"[A-Za-z]:\\[\\a-zA-Z0-9_\-. ]+", stripped):
        bonus += 8.0

    return min(bonus, 30.0)
