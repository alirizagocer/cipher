"""
Columnar Transposition Cipher kirma (anahtar kelimesiz).

Klasik yontem: duz metin C sutunlu bir izgaraya SATIR SATIR yazilir (son satir
eksik kalabilir), sonra sutunlar BELLI BIR SIRAYLA (anahtar kelimenin harf
sirasindan turetilir) uc uca eklenerek sifreli metin elde edilir. Bu CTF'lerde
Rail Fence'ten sonra en yaygin ikinci transposition cipher turudur.

Anahtar KELIMESI bilinmedigi icin sutun SAYISINI (2-12 arasi dener) ve sutun
OKUMA SIRASINI (permutasyon) BRUTE-FORCE + quadgram fitness ile bulur:
- Kucuk sutun sayilari (<=8): TUM permutasyonlar denenir (8! = 40320, hizli)
- Buyuk sutun sayilari (9-12): hill-climbing (substitution kiricidaki ayni
  mantik - rastgele iki sutunu takas edip fitness iyilesirse kabul et)
"""
import itertools
import random
import time as _time
from typing import List, Optional, Tuple

from .ngram import quadgram_fitness
from .scorer import score_text


def _column_lengths(total_len: int, n_cols: int) -> List[int]:
    """Grid'e SATIR SATIR yazildiginda her sutunun kac karakter aldigini
    dondurur. Standart konvansiyon: L = total_len, R = ceil(L/n_cols),
    remainder = L % n_cols. remainder==0 ise tum sutunlar R karakter alir;
    aksi halde ILK 'remainder' sutun R karakter, geri kalanlar R-1 alir
    (cunku son satir soldan sagdan doldurulur ve saga dogru eksik kalir)."""
    R = -(-total_len // n_cols)  # ceil division
    remainder = total_len % n_cols
    if remainder == 0:
        return [R] * n_cols
    return [R if i < remainder else R - 1 for i in range(n_cols)]


def decrypt_columnar(ciphertext: str, order: List[int]) -> str:
    """order: sifreli metnin sutunlarinin ORIJINAL grid'deki hangi sutun
    indeksine (0-tabanli) karsilik geldigini belirten sira listesi.
    Ornek: order=[2,0,1] -> ciphertext'in ilk parcasi grid'in 2. sutunu,
    ikinci parcasi 0. sutunu, ucuncu parcasi 1. sutunu doldurur."""
    n_cols = len(order)
    lengths_by_original_index = _column_lengths(len(ciphertext), n_cols)

    columns = [None] * n_cols
    pos = 0
    for original_col_idx in order:
        length = lengths_by_original_index[original_col_idx]
        columns[original_col_idx] = ciphertext[pos:pos + length]
        pos += length

    R = -(-len(ciphertext) // n_cols)
    out = []
    for row in range(R):
        for col in range(n_cols):
            if columns[col] is not None and row < len(columns[col]):
                out.append(columns[col][row])
    return "".join(out)


def _brute_force_permutations(ciphertext: str, n_cols: int, deadline: float):
    best = None  # (fitness, order, text)
    for perm in itertools.permutations(range(n_cols)):
        if _time.time() > deadline:
            break
        text = decrypt_columnar(ciphertext, list(perm))
        fit = quadgram_fitness(text)
        if best is None or fit > best[0]:
            best = (fit, list(perm), text)
    return best


def _hillclimb_permutation(ciphertext: str, n_cols: int, deadline: float,
                            restarts: int = 30):
    best_overall = None
    while _time.time() < deadline and restarts > 0:
        restarts -= 1
        order = list(range(n_cols))
        random.shuffle(order)
        text = decrypt_columnar(ciphertext, order)
        fit = quadgram_fitness(text)
        no_improve = 0
        while no_improve < 150 and _time.time() < deadline:
            i, j = random.sample(range(n_cols), 2)
            new_order = order[:]
            new_order[i], new_order[j] = new_order[j], new_order[i]
            new_text = decrypt_columnar(ciphertext, new_order)
            new_fit = quadgram_fitness(new_text)
            if new_fit > fit:
                order, text, fit = new_order, new_text, new_fit
                no_improve = 0
            else:
                no_improve += 1
        if best_overall is None or fit > best_overall[0]:
            best_overall = (fit, order, text)
    return best_overall


def crack_columnar_transposition(ciphertext: str, min_cols: int = 2, max_cols: int = 12,
                                  time_budget_seconds: float = 4.0):
    """(n_cols, order, plaintext, score, fitness) dondurur, uygun degilse None.
    Bosluk/noktalama KORUNARAK calisir (harfleri degil, TUM karakterleri
    sutunlara dagitir) - cunku transposition cipher genelde bosluklari da
    karistirir, bu yuzden substitution'daki gibi sadece harfleri filtrelemek
    yanlis olur.

    En az 20 karakter gerektirir (daha kisa metinlerde sutun sayisi/permutasyon
    kombinasyonlari arasinda anlamli ayrim yapilamaz).
    """
    text = ciphertext.strip()
    if len(text) < 20:
        return None

    deadline = _time.time() + time_budget_seconds
    best_overall = None  # (fitness, n_cols, order, plaintext)

    for n_cols in range(min_cols, min(max_cols, len(text) - 1) + 1):
        if _time.time() > deadline:
            break
        if n_cols <= 8:
            result = _brute_force_permutations(text, n_cols, deadline)
        else:
            result = _hillclimb_permutation(text, n_cols, deadline)
        if result is None:
            continue
        fit, order, decoded = result
        if best_overall is None or fit > best_overall[0]:
            best_overall = (fit, n_cols, order, decoded)

    if best_overall is None:
        return None
    fitness, n_cols, order, plaintext = best_overall
    return n_cols, order, plaintext, score_text(plaintext), fitness
