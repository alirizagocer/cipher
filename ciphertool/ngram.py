"""
Gercek Ingilizce quadgram (4-harf grubu) istatistiklerine dayali fitness fonksiyonu.

Kaynak: practicalcryptography.com'un klasik "english_quadgrams.txt" korpusu
(Tolstoy'un "War and Peace" dahil buyuk bir Ingilizce metin derlemesinden
sayilmis ~389.000 farkli quadgram, ~4.2 milyar toplam sayim). Bu, substitution
cipher kirmada chi-kare/bigram'dan cok daha guvenilir bir sinyal - cunku harf
DIZILIMINI (orn. "TION", "THE " cok yaygin; "QXKZ" neredeyse hic yok) dikkate
aliyor, sadece tekil harf frekansini degil.

Skor = log10(P(quadgram)) toplami. Yuksek (0'a yakin, negatif) skor = daha
Ingilizce-benzeri metin. Bulunmayan quadgram'lar icin "floor" (cok kucuk bir
olasilik varsayimi) kullanilir - boylece hic gorulmemis bir dizilim sifir
olasilik degil, sadece cok dusuk olasilik alir (Laplace smoothing mantigi).
"""
import gzip
import importlib.resources as _resources
import string
from functools import lru_cache


@lru_cache(maxsize=1)
def _load_quadgrams():
    """(gram->log10_prob dict, floor_log10_prob) dondurur. Lazy-load + cache."""
    scores = {}
    try:
        data = _resources.files("ciphertool").joinpath("data", "quadgrams.txt.gz")
        with data.open("rb") as fh:
            raw = gzip.decompress(fh.read()).decode("utf-8")
    except Exception:
        raw = ""
    for line in raw.splitlines():
        if not line:
            continue
        try:
            gram, score = line.split(" ")
            scores[gram] = float(score)
        except Exception:
            continue
    # Hic gorulmemis quadgram icin: standart pratik, "0.01 sayim varmis gibi"
    # cok kucuk bir olasilik atamak (Laplace/add-k smoothing). Toplam sayim
    # yaklasik 4.22 milyar oldugundan floor ~ log10(0.01/4.22e9)
    floor = -11.6
    return scores, floor


def quadgram_fitness(text: str) -> float:
    """Metnin ne kadar 'Ingilizce-benzeri' oldugunu quadgram log-olabilirlik
    toplamiyla olcer. Yuksek (0'a yakin negatif) = daha Ingilizce.
    Normalize EDILMEZ (uzunluga bagli buyur) - hill-climbing icin onemli olan
    MUTLAK deger degil, ayni uzunluktaki farkli anahtarlar arasindaki SIRALAMA."""
    scores, floor = _load_quadgrams()
    letters = [c for c in text.upper() if c in string.ascii_uppercase]
    if len(letters) < 4:
        return floor * 4
    s = "".join(letters)
    total = 0.0
    for i in range(len(s) - 3):
        total += scores.get(s[i:i + 4], floor)
    return total


def quadgram_fitness_per_char(text: str) -> float:
    """Uzunluktan bagimsiz karsilastirma icin karakter basina normalize skor."""
    letters = sum(1 for c in text if c.isalpha())
    if letters < 4:
        return -99.0
    return quadgram_fitness(text) / max(letters - 3, 1)
