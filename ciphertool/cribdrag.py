"""
Crib-dragging (bilinen-parcayla saldiri) modulu.

Kullanim senaryosu: kullanici "muhtemelen icerisinde 'flag{' ya da 'the ' geciyor"
gibi bir ipucu verebilir. Bu modul:
  - Crib'i ciphertext boyunca kaydirir (sliding window)
  - Her pozisyonda crib ile XOR alindiginda ortaya cikan "anahtar parcasi"ni cikarir
  - O anahtar parcasini tum ciphertext'e uygulayip quadgram ile okunabilir mi diye bakar
  - En iyi adayi dondurur

Bu bir "tespit" ozelligidir: dogru crib dogru anahtara -\u003e dogrulayan metin uretir.
XOR icin calisir; Vigenere icin ise sadece crib'in dusup dusmedigi pozisyonda
anahtar parcasini cekariz.

CTF'lerde cok yaygin: "flag{" crib'i ile 90+ karakterlik XOR-sifreli verilerde
bile anahtar tam olarak kurtarilabildigi gosterilmistir.
"""
from typing import Optional, List, Tuple

from .scorer import score_text


def _xor_crib_at_position(data: bytes, crib: bytes, pos: int) -> Optional[bytes]:
    """data[pos:pos+len(crib)] XOR crib = anahtar parcasi. data yetersizse None."""
    end = pos + len(crib)
    if end > len(data):
        return None
    return bytes(data[pos + i] ^ crib[i] for i in range(len(crib)))


def _extend_key_guess(data: bytes, key_fragment: bytes, frag_pos: int) -> bytes:
    """Anahtar parcasinin 'frag_pos' pozisyonundan basladigini varsayarak
    tum ciphertext'e uygulayacak kadar uzun bir anahtar olusturmaya calisir.
    Anahtar periyodik oldugu varsayimiyla yayilir.
    """
    key_len = len(key_fragment)
    # frag_pos mod key_len = 0 olacak sekilde ayarlayip tam periyodik uygula
    # Farkli offsetleri deneyip en iyi quadgram veren offset'i sec
    return key_fragment  # cagiran fonksiyon offset loop'u yapar


def xor_crib_drag(
    data: bytes,
    crib: bytes,
    top_n: int = 5,
) -> List[Tuple[int, bytes, str, float]]:
    """XOR crib-dragging.

    Crib'i data boyunca kaydirir. Her pozisyon icin:
      1. Crib XOR data[pos:pos+len(crib)] = anahtar parcasi
      2. Anahtar parcasini farkli key-length varsayimlariyla (1..40) tum
         ciphertext'e uygula
      3. Quadgram fitness ile en iyi uretimi sec

    Donus degeri: [(pos, key_guess, plaintext_guess, fitness)] azalan fitness'a gore.
    pos = crib'in basladigi byte pozisyonu.
    """
    from .ngram import quadgram_fitness
    from .crack import guess_xor_keysize

    if not data or not crib:
        return []

    best: List[Tuple[float, int, bytes, str]] = []  # (fitness, pos, key, plaintext)

    crib_len = len(crib)
    data_len = len(data)

    for pos in range(data_len - crib_len + 1):
        key_fragment = _xor_crib_at_position(data, crib, pos)
        if key_fragment is None:
            continue

        # Farkli anahtar uzunluklari dene: crib uzunlugundan data/4'e kadar
        # Ancak crib_len'den kucuk uzunluklar mantikli degil (crib kendisi bir ipucu)
        # Su an: sadece key uzunlugu = crib uzunlugu (saf XOR crib drag)
        # ve bilinen keysize adaylarini da dene (hamming distance listesi)
        candidate_keylens = [crib_len]
        try:
            candidate_keylens += guess_xor_keysize(data, max_keysize=40, top_k=3)
        except Exception:
            pass
        # tekrari kaldir, sirala
        candidate_keylens = sorted(set(candidate_keylens))

        for klen in candidate_keylens:
            if klen < 1 or klen > len(data) // 2:
                continue
            # Anahtar parcasini klen'e gore hizala:
            # pos % klen -> bu fragment klen-periyodik anahtarin hangi offset'inden basliyor
            offset = pos % klen
            # Anahtar parcasindan klen boyutunda bir anahtar guess'i turet:
            # fragment klen'den kisaysa padding yok, sadece bildiklerimizi yerles
            key_arr = bytearray(klen)
            for i in range(min(crib_len, klen)):
                key_arr[(offset + i) % klen] = key_fragment[i]
            # Bilinmeyen byte'lar 0 kalir -- bunlar plaintext'te 0^cipher = cipher olarak gorulur
            # (kismen bozuk metin uretir ama crib pozisyonu dogru cozunecek)
            key_bytes = bytes(key_arr)
            pt_bytes = bytes(data[i] ^ key_bytes[i % klen] for i in range(data_len))
            try:
                pt = pt_bytes.decode("utf-8", errors="replace")
            except Exception:
                pt = pt_bytes.decode("latin-1", errors="replace")
            fit = quadgram_fitness(pt)
            best.append((fit, pos, key_bytes, pt))

    if not best:
        return []

    best.sort(key=lambda t: t[0], reverse=True)
    seen_keys = set()
    results = []
    for fit, pos, key, pt in best:
        k_id = (pos, key)
        if k_id not in seen_keys:
            seen_keys.add(k_id)
            results.append((pos, key, pt, fit))
        if len(results) >= top_n:
            break
    return results


def vigenere_crib_drag(
    ciphertext: str,
    crib: str,
    top_n: int = 5,
) -> List[Tuple[int, str, str, float]]:
    """Vigenere/Beaufort icin crib-dragging (karakter alaninda, sadece alfabetik).

    Crib'i ciphertext'in alfabetik karakter dizisi boyunca kaydirir.
    Her pozisyonda Vigenere: K = C - P (mod 26) -> anahtar parcasini turetir,
    sonra bu anahtar parcasiyla tum metni cozmeye calisir.

    Donus: [(char_pos, key_guess_str, plaintext_guess, fitness)]
    char_pos = sadece alfabetik sayim icindeki pozisyon (0-indexed).
    """
    from .ngram import quadgram_fitness

    ct_letters = [(i, c.upper()) for i, c in enumerate(ciphertext) if c.isalpha()]
    if not ct_letters or not crib:
        return []

    crib_upper = crib.upper()
    crib_alpha = [c for c in crib_upper if c.isalpha()]
    if not crib_alpha:
        return []

    crib_len = len(crib_alpha)
    n_ct = len(ct_letters)

    best: List[Tuple[float, int, str, str]] = []

    for pos in range(n_ct - crib_len + 1):
        # K[i] = (C[pos+i] - P[i]) mod 26
        key_fragment = []
        valid = True
        for i in range(crib_len):
            c_ord = ord(ct_letters[pos + i][1]) - 65
            p_ord = ord(crib_alpha[i]) - 65
            k_ord = (c_ord - p_ord) % 26
            key_fragment.append(chr(k_ord + 65))
        if not valid:
            continue

        key_str = "".join(key_fragment)

        # Bu anahtar parcasiyla farkli key uzunluklari dene
        for klen in range(1, min(crib_len + 1, 21)):
            # key_fragment ilk klen karakterini al, tum metne uygula
            key_part = key_str[:klen]
            out = list(ciphertext)
            for j, (orig_idx, ct_ch) in enumerate(ct_letters):
                k = ord(key_part[j % klen]) - 65
                c_val = ord(ct_ch) - 65
                pt_ch = chr((c_val - k) % 26 + 65)
                if ciphertext[orig_idx].islower():
                    pt_ch = pt_ch.lower()
                out[orig_idx] = pt_ch
            plaintext = "".join(out)
            fit = quadgram_fitness(plaintext)
            best.append((fit, pos, key_part, plaintext))

    if not best:
        return []

    best.sort(key=lambda t: t[0], reverse=True)
    seen = set()
    results = []
    for fit, pos, key, pt in best:
        uid = (pos, key)
        if uid not in seen:
            seen.add(uid)
            results.append((pos, key, pt, fit))
        if len(results) >= top_n:
            break
    return results


COMMON_CRIBS = [
    b"http://", b"https://", b"<?php", b"flag{", b"MZ\x90\x00",
    b"\x89PNG\r\n\x1a\n", b"PK\x03\x04", b"%PDF-", b'{"', b"<?xml"
]

def auto_crib_drag_xor(data: bytes, min_score: float = -10.0) -> List[Tuple[bytes, bytes, str, float]]:
    """Otomatik bilinen-parca denemesi yapar. Yalnizca guclu sonuclari dondurur.
    Return: [(key, crib_used, text, quadgram_score)]
    """
    results = []
    if len(data) < 10:
        return results
    for crib in COMMON_CRIBS:
        if len(data) < len(crib):
            continue
        hits = xor_crib_drag(data, crib, top_n=1)
        for _, key, text, fit in hits:
            if fit >= min_score:
                results.append((key, crib, text, fit))
    return sorted(results, key=lambda x: x[3], reverse=True)
