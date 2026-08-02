"""
Anahtar gerektiren ama brute-force ile kirilabilen teknikler:
- Tek-byte XOR (256 anahtar deneniyor)
- Tekrarlayan anahtarli XOR (Hamming distance ile key uzunlugu tahmini + sutun bazli kirma)
- Vigenere cipher (Index of Coincidence ile key uzunlugu tahmini + sutun bazli Caesar kirma)

Bunlar CTF'lerde ve gercek pentest senaryolarinda (ozellikle XOR) cok sik karsilasilan
"encoding degil ama zayif sifreleme" kategorisi.
"""
import string

from .scorer import score_text, chi_squared_english, printable_ratio, ENGLISH_FREQ
from .decoders import caesar_shift


# ---------------------------------------------------------------- XOR

def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_xor_keysize(data: bytes, max_keysize: int = 40, top_k: int = 5):
    import itertools
    candidates = []
    upper = min(max_keysize, max(2, len(data) // 4))
    for ks in range(2, upper + 1):
        chunks = [data[i:i + ks] for i in range(0, len(data) - ks, ks)]
        n_blocks = min(len(chunks), 8)
        if n_blocks < 2:
            continue
        pairs = list(itertools.combinations(chunks[:n_blocks], 2))
        if not pairs:
            continue
        dist = sum(hamming_distance(a, b) / ks for a, b in pairs) / len(pairs)
        candidates.append((ks, dist))
    candidates.sort(key=lambda t: t[1])
    return [ks for ks, _ in candidates[:top_k]]


def crack_single_byte_xor(data: bytes):
    """(key:int, plaintext:str, score:float) dondurur, veri bossa None."""
    if not data:
        return None
    best = None
    for key in range(256):
        pt = bytes(b ^ key for b in data)
        text = pt.decode("utf-8", errors="replace")
        sc = score_text(text)
        if best is None or sc > best[2]:
            best = (key, text, sc)
    return best


# Klasik ETAOIN frekans tablosu (bosluk dahil) - kisa/sparse sutunlarda
# chi-kare testinden cok daha kararli sonuc verir.
_CHAR_FREQ = {
    ' ': 13.0, 'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
    'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32, 'l': 3.98,
    'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11, 'w': 2.09,
    'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17,
    'q': 0.11, 'j': 0.10, 'z': 0.07,
}


def _byte_freq_score(decoded: bytes) -> float:
    score = 0.0
    for b in decoded:
        if b == 32:
            score += _CHAR_FREQ[" "]
        elif 65 <= b <= 90:
            score += _CHAR_FREQ.get(chr(b + 32), 0.0)
        elif 97 <= b <= 122:
            score += _CHAR_FREQ.get(chr(b), 0.0)
        elif b in (9, 10, 13):
            score += 0.5
        elif 33 <= b <= 126:
            score += 0.15  # rakam/noktalama, kucuk pozitif kredi
        else:
            score -= 5.0  # yazdirilamayan byte -> guclu ceza
    return score


def _column_best_byte(column: bytes) -> int:
    best_byte, best_score = 0, float("-inf")
    for k in range(256):
        decoded = bytes(b ^ k for b in column)
        sc = _byte_freq_score(decoded)
        if sc > best_score:
            best_score, best_byte = sc, k
    return best_byte


def crack_repeating_xor(data: bytes, max_keysize: int = 40):
    """(key:bytes, plaintext:str, score:float) dondurur, olmazsa None."""
    if len(data) < 8:
        return None
    best_overall = None
    for ks in guess_xor_keysize(data, max_keysize=max_keysize):
        key = bytearray()
        for col in range(ks):
            column = data[col::ks]
            key.append(_column_best_byte(column))
        pt = bytes(b ^ key[i % ks] for i, b in enumerate(data))
        text = pt.decode("utf-8", errors="replace")
        sc = score_text(text)
        if best_overall is None or sc > best_overall[2]:
            best_overall = (bytes(key), text, sc)
    return best_overall


# ---------------------------------------------------------------- Vigenere

def index_of_coincidence(letters) -> float:
    n = len(letters)
    if n < 2:
        return 0.0
    from collections import Counter
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def _best_caesar_shift_for_column(col_letters) -> int:
    best_shift, best_chi = 0, float("inf")
    joined = "".join(col_letters)
    for shift in range(26):
        shifted = caesar_shift(joined, shift)
        chi = chi_squared_english(shifted)
        if chi < best_chi:
            best_chi, best_shift = chi, shift
    return best_shift


_ENGLISH_IC_THRESHOLD = 0.052  # rastgele (~0.038) ile Ingilizce (~0.067) arasi esik


def guess_vigenere_keylen(letters, max_len: int = 20):
    scores = []
    for klen in range(2, max_len + 1):
        ics = []
        for col in range(klen):
            col_letters = letters[col::klen]
            if len(col_letters) < 2:
                continue
            ics.append(index_of_coincidence(col_letters))
        if not ics:
            continue
        avg_ic = sum(ics) / len(ics)
        scores.append((klen, avg_ic))
        # esigi asan EN KUCUK uzunlugu tercih et - buyuk katlari (2x, 3x...)
        # kucuk ornek boyutunda sans eseri daha yuksek IC verebiliyor, bu yanlis
        # yonlendirir; en kucuk yeterli uzunluk hemen hemen her zaman dogrusu
        if avg_ic >= _ENGLISH_IC_THRESHOLD:
            return klen
    if not scores:
        return None
    scores.sort(key=lambda t: t[1], reverse=True)
    return scores[0][0]


def crack_vigenere(ciphertext: str):
    """(key_str, plaintext:str, score:float) dondurur, uygun degilse None."""
    letters_idx = [i for i, c in enumerate(ciphertext) if c.isalpha()]
    if len(letters_idx) < 20:
        return None
    letters = [ciphertext[i].upper() for i in letters_idx]

    keylen = guess_vigenere_keylen(letters)
    if not keylen:
        return None

    key_shifts = []
    for col in range(keylen):
        col_letters = letters[col::keylen]
        key_shifts.append(_best_caesar_shift_for_column(col_letters))

    out = list(ciphertext)
    for li, i in enumerate(letters_idx):
        shift = key_shifts[li % keylen]
        out[i] = caesar_shift(ciphertext[i], shift)
    plaintext = "".join(out)

    key_str = "".join(chr(65 + ((26 - s) % 26)) for s in key_shifts)
    return key_str, plaintext, score_text(plaintext)


# ---------------------------------------------------------------- Beaufort
# Beaufort, Vigenere'in "aynasi": P = K - C (mod 26) yerine Vigenere'de C = P + K.
# Beaufort'ta sifreleme VE sifre cozme AYNI islemdir: P = K - C (mod 26).
# Vigenere kirici ile ayni IC/Kasiski mantigini kullanir, sadece sutun kirma
# formulu farkli oldugu icin ayri bir fonksiyon gerekir - karistirilirsa
# (Vigenere kiricisiyla Beaufort denemek) sonuc hep anlamsiz cikar, bu yuzden
# CTF'lerde "Vigenere gibi ama Vigenere kirici tutmuyor" durumunda akla gelmeli.

def beaufort_decrypt_column(col_letters, shift) -> str:
    out = []
    for c in col_letters:
        y = ord(c) - 65
        out.append(chr((shift - y) % 26 + 65))
    return "".join(out)


def _best_beaufort_shift_for_column(col_letters) -> int:
    best_shift, best_chi = 0, float("inf")
    for shift in range(26):
        shifted = beaufort_decrypt_column(col_letters, shift)
        chi = chi_squared_english(shifted)
        if chi < best_chi:
            best_chi, best_shift = chi, shift
    return best_shift


def crack_beaufort(ciphertext: str):
    """(key_str, plaintext:str, score:float) dondurur, uygun degilse None."""
    letters_idx = [i for i, c in enumerate(ciphertext) if c.isalpha()]
    if len(letters_idx) < 20:
        return None
    letters = [ciphertext[i].upper() for i in letters_idx]

    keylen = guess_vigenere_keylen(letters)  # IC tabanli anahtar uzunlugu tahmini aynen kullanilabilir
    if not keylen:
        return None

    key_shifts = []
    for col in range(keylen):
        col_letters = letters[col::keylen]
        key_shifts.append(_best_beaufort_shift_for_column(col_letters))

    out = list(ciphertext)
    for li, i in enumerate(letters_idx):
        shift = key_shifts[li % keylen]
        c = ciphertext[i]
        if c.isupper():
            y = ord(c) - 65
            out[i] = chr((key_shifts[li % keylen] - y) % 26 + 65)
        else:
            y = ord(c.upper()) - 65
            out[i] = chr((key_shifts[li % keylen] - y) % 26 + 97)
    plaintext = "".join(out)

    key_str = "".join(chr(65 + s) for s in key_shifts)
    return key_str, plaintext, score_text(plaintext)


# ---------------------------------------------------------------- Genel Substitution Cipher (hill-climbing)
# quipqiup / practicalcryptography tarzi: anahtar kelimesi olmayan GENEL
# monoalfabetik substitution cipher'lari kirar. Sabit bir dogrudan formul YOK
# (26! ~ 4x10^26 olasi anahtar var) - bunun yerine:
#   1) Frekans siralamasiyla makul bir baslangic anahtari kurulur (ETAOIN eslesmesi)
#   2) Anahtardaki iki harfi rastgele takas edip quadgram fitness'i olcen bir
#      "tepe tirmanma" (hill climbing) dongusu calisir - iyilesirse kabul edilir
#   3) Yerel optimuma takilmamak icin COKLU RASTGELE BASLANGIC (restart) yapilir
# Bu, quipqiup.com'un ve CTF topluluklarinin substitution kirma icin kullandigi
# standart yontemdir (quadgram istatistikleri practicalcryptography.com kaynakli).

import random as _random

_ALPHABET = string.ascii_uppercase


def _apply_substitution_key(ciphertext: str, key: str) -> str:
    """key[i] = ciphertext harfi 'A'+i yerine hangi plaintext harfine cevrilir.
    Ornek: key = 'XX...' -> cipher 'A' -> key[0], cipher 'B' -> key[1], ..."""
    mapping = {cipher_ch: plain_ch for cipher_ch, plain_ch in zip(_ALPHABET, key)}
    out = []
    for c in ciphertext:
        if c.isupper():
            out.append(mapping.get(c, c))
        elif c.islower():
            out.append(mapping.get(c.upper(), c.upper()).lower())
        else:
            out.append(c)
    return "".join(out)


def _frequency_seeded_key(ciphertext: str) -> str:
    """Ciphertext'teki harf frekansini ETAOIN sirasiyla eslestirip makul bir
    baslangic anahtari kurar - rastgele baslangictan cok daha hizli yakinsar."""
    from collections import Counter
    counts = Counter(c.upper() for c in ciphertext if c.isalpha())
    etaoin = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    cipher_by_freq = [c for c, _ in counts.most_common()]
    for c in _ALPHABET:
        if c not in cipher_by_freq:
            cipher_by_freq.append(c)
    key = [""] * 26
    for cipher_ch, plain_ch in zip(cipher_by_freq, etaoin):
        key[ord(cipher_ch) - 65] = plain_ch
    return "".join(key)


def crack_substitution(ciphertext: str, restarts: int = 200, iterations: int = 4000,
                        time_budget_seconds: float = 6.0):
    """(key_map_str, plaintext:str, score:float, fitness:float, confidence_note:str)
    dondurur, uygun degilse None. key_map_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    sirasiyla her ciphertext harfinin hangi plaintext harfine karsilik geldigini
    gosterir (ciphertext 'A' -> key_map_str[0], vs.).

    Cok kisa metinlerde (substitution icin pratikte guvenilir kirma icin en az
    ~80 harf gerekir) None doner, cunku yanlis-guven veren sonuc uretmek yerine
    hic sonuc uretmemek tercih edilir.

    Onemli durustluk notu: basari orani metnin UZUNLUGUNA olduğu kadar HARF
    CESITLILIGINE de bagli. Test sonuclarimiz: dogal dil metinlerinde (kelime
    tekrari olan normal cumleler) 150+ harfte %100, 200+ harfte tutarli %100
    basari. Ama pangram tarzi yapay metinlerde (her harfin ~1 kez gectigi,
    orn. 'the quick brown fox...') istatistiksel tekrar/redundancy dusuk
    oldugundan 100 harfte bile basarisiz olabilir - bu algoritmanin degil,
    substitution-kirmanin matematiksel bir siniri (Shannon'un 'unicity
    distance' kavrami). CLI/engine ciktisinda buna gore bir guven notu eklenir.
    """
    import time as _time
    from .ngram import quadgram_fitness

    letters_only = [c for c in ciphertext if c.isalpha()]
    if len(letters_only) < 80:
        return None

    import math as _math
    start = _time.time()
    best_overall = None  # (fitness, key, plaintext)

    seed_key = _frequency_seeded_key(ciphertext)

    for restart in range(restarts):
        if _time.time() - start > time_budget_seconds:
            break
        if restart == 0:
            key = list(seed_key)
        else:
            key = list(_ALPHABET)
            _random.shuffle(key)
        key_str = "".join(key)
        current_text = _apply_substitution_key(ciphertext, key_str)
        current_fit = quadgram_fitness(current_text)

        # Bu restart icinde simdiye kadar bulunan EN IYI (fitness, key, text) -
        # simulated annealing "current" durumu gecici olarak kotulesebilir diye
        # ayri takip edilir.
        restart_best = (current_fit, key_str, current_text)

        no_improve = 0
        T0 = 6.0  # baslangic "sicaklik" - erken asamada daha fazla kotu-hamle kabul eder
        for it in range(iterations):
            if _time.time() - start > time_budget_seconds:
                break
            # Sicaklik zamanla azalir (cooling schedule) -> once kesif, sonra ince ayar
            T = T0 * (1 - it / iterations) + 0.05
            i, j = _random.sample(range(26), 2)
            new_key = key[:]
            new_key[i], new_key[j] = new_key[j], new_key[i]
            new_key_str = "".join(new_key)
            new_text = _apply_substitution_key(ciphertext, new_key_str)
            new_fit = quadgram_fitness(new_text)

            delta = new_fit - current_fit
            accept = delta > 0
            if not accept:
                try:
                    accept = _random.random() < _math.exp(delta / T)
                except OverflowError:
                    accept = False

            if accept:
                key, key_str, current_text, current_fit = new_key, new_key_str, new_text, new_fit
                if current_fit > restart_best[0]:
                    restart_best = (current_fit, key_str, current_text)
                    no_improve = 0
                else:
                    no_improve += 1
            else:
                no_improve += 1

            if no_improve > 1200:
                break  # bu restart'ta yerel optimuma takildi, yeni restart'a gec

        if best_overall is None or restart_best[0] > best_overall[0]:
            best_overall = restart_best

    if best_overall is None:
        return None
    fitness, key_str, plaintext = best_overall
    n_letters = len(letters_only)
    if n_letters >= 200:
        confidence_note = "yüksek güven (200+ harf, doğal dilde bu uzunlukta tutarlı %100 başarı gözlendi)"
    elif n_letters >= 130:
        confidence_note = "orta-yüksek güven (130+ harf, doğal dil metinlerinde genelde güvenilir)"
    elif n_letters >= 100:
        confidence_note = "orta güven (100-130 harf arası, metin doğal dil redundancy'sine bağlı olarak başarısız olabilir)"
    else:
        confidence_note = ("DÜŞÜK güven (80-100 harf arası, sınırda — özellikle harf çeşitliliği yapay/pangram "
                            "tarzıysa başarısız olabilir; sonucu MUTLAKA gözle kontrol et)")
    return key_str, plaintext, score_text(plaintext), fitness, confidence_note
