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
