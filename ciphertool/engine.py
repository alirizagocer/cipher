"""
Coklu katman decode motoru: bilinen tum decoder'lari dener, sonuclari skorlar,
okunabilir sonuc bulana kadar (max derinlik) zincirleme devam eder.

v2 eklentileri:
- Dosya imzasi (magic byte) tespiti: her adimda decode edilen veri bir dosya mi
  (PNG/ZIP/PDF/ELF...) diye bakar, oyleyse yuksek puanla isaretleyip bildirir.
- Pahali analizler (XOR brute-force, Vigenere kirma, Rail Fence, Affine) sadece
  kok dugumde (orijinal girdide) calisir - performans icin.
- Node/zaman butcesi: cok buyuk/karmasik girdilerde sonsuz dallanmayi engeller.
"""
import base64
import binascii
import re
import time
import heapq
from dataclasses import dataclass
from typing import List, Optional

from .decoders import (
    SINGLE_SHOT_DECODERS, BYTES_DECODERS, try_all_caesar, try_all_affine,
    try_all_rail_fence,
)
from .scorer import score_text
from .filesig import detect_file_signature
from .crack import (
    crack_single_byte_xor, crack_repeating_xor, crack_vigenere, crack_beaufort,
    crack_substitution,
)
from .transposition import crack_columnar_transposition
from .hashid import identify_hash
from .entropy import analyze_entropy, CLASS_COMPRESSED_OR_ENCRYPTED


@dataclass
class Candidate:
    chain: List[str]
    text: str
    score: float
    kind: str = "chain"  # "chain" | "original" | "file"


NODE_BUDGET = 3500
TIME_BUDGET_SECONDS = 6.0

# Bu decoder'lar basarili oldugunda sadece alfabe/uzunluk degil GERCEK YAPISAL
# dogrulama da yapiyor (orn. JSON parse basarili) - bu yuzden basarili olduklarinda
# rastgele gurultunun tesadufen alabilecegi skordan daha yuksek bir taban puan hak ederler.
HIGH_CONFIDENCE_DECODERS = {"JWT"}
HIGH_CONFIDENCE_FLOOR = 88.0


def _is_meaningfully_different(a: str, b: str) -> bool:
    return a.strip() != b.strip() and len(b.strip()) > 0


def _hash_skip_level(raw: str) -> str:
    """'none' | 'ciphers_only' | 'all' dondurur.
    - 'all': yapisal olarak KESIN bir hash/KDF formati (bcrypt, argon2, md5crypt...)
      -> hicbir decode/cipher denemesi anlamli degil, hepsi atlanir.
    - 'ciphers_only': sadece uzunluktan tahmin edilen belirsiz hex hash adayi
      -> klasik sifre kirma (Caesar/Vigenere/XOR/Affine) atlanir ama encoding
      denemelerine (Base64 vb.) izin verilir, cunku ayni hex string teorik
      olarak baska bir seyin encode edilmis hali de olabilir.
    - 'none': hash/KDF'ye benzemiyor, normal tarama yapilir.
    """
    s = raw.strip()
    candidates = identify_hash(s)
    if not candidates:
        return "none"
    if any(c.certain for c in candidates):
        return "all"
    stripped = re.sub(r"\s", "", s)
    if re.fullmatch(r"[0-9A-Fa-f]+", stripped):
        return "ciphers_only"
    return "none"


def _check_file_signature(text: str):
    """Metni yaygin byte-encoding'lerle decode edip dosya imzasi arar.
    Eslesirse (decoder_adi, dosya_turu, byte_uzunlugu) dondurur, yoksa None."""
    for name, fn in BYTES_DECODERS:
        try:
            raw = fn(text)
        except Exception:
            raw = None
        if raw and len(raw) >= 4:
            sig = detect_file_signature(raw)
            if sig:
                return name, sig, len(raw)
    try:
        s2 = text.strip().replace(" ", "")
        if s2 and len(s2) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s2):
            raw = binascii.unhexlify(s2)
            if len(raw) >= 4:
                sig = detect_file_signature(raw)
                if sig:
                    return "Hex (Base16)", sig, len(raw)
    except Exception:
        pass
    return None


def _check_entropy_root(raw: str):
    """Raw girdiyi bilinen byte-encoding'lerle decode edip entropi analizi
    yapar. Yuksek entropili (gercek sifreleme/sikistirma/rastgele veri
    isareti) sonuclari (decoder_adi, EntropyReport) olarak dondurur. Dosya
    imzasi zaten eslesen decode'lari ATLAR - o zaten baska bir mekanizmayla
    (dosya tespiti) daha net aciklaniyor, entropi notuyla tekrar etmeye
    gerek yok."""
    hits = []
    seen_bytes = set()
    for name, fn in BYTES_DECODERS:
        try:
            b = fn(raw)
        except Exception:
            b = None
        if b and len(b) >= 32 and b not in seen_bytes:
            seen_bytes.add(b)
            if detect_file_signature(b):
                continue  # dosya olarak zaten tespit edildi, entropi notu gereksiz
            rep = analyze_entropy(b)
            if rep.classification == CLASS_COMPRESSED_OR_ENCRYPTED:
                hits.append((name, rep))
    try:
        s2 = raw.strip().replace(" ", "")
        if s2 and len(s2) % 2 == 0 and len(s2) >= 64 and all(c in "0123456789abcdefABCDEF" for c in s2):
            b = binascii.unhexlify(s2)
            if b not in seen_bytes and not detect_file_signature(b):
                rep = analyze_entropy(b)
                if rep.classification == CLASS_COMPRESSED_OR_ENCRYPTED:
                    hits.append(("Hex (Base16)", rep))
    except Exception:
        pass
    return hits


class _Budget:
    def __init__(self):
        self.nodes = 0
        self.start = time.time()

    def exhausted(self) -> bool:
        return self.nodes > NODE_BUDGET or (time.time() - self.start) > TIME_BUDGET_SECONDS


def explore(raw: str, max_depth: int = 3, top_n: int = 12) -> List[Candidate]:
    seen_texts = set()
    results: List[Candidate] = []
    budget = _Budget()

    # Hash/KDF gibi gorunen girdilerde gereksiz/anlamsiz decode denemelerini atla
    skip_level = _hash_skip_level(raw)  # "none" | "ciphers_only" | "all"
    skip_all = skip_level == "all"
    skip_ciphers = skip_level in ("all", "ciphers_only")

    def a_star_search(start_text: str):
        pq = []
        counter = 0
        start_score = score_text(start_text)
        heapq.heappush(pq, (-start_score, 0, counter, [], start_text))
        counter += 1

        while pq:
            if budget.exhausted():
                break

            priority, depth, _, chain, text = heapq.heappop(pq)

            if text in seen_texts:
                continue
            seen_texts.add(text)
            budget.nodes += 1

            file_hit = _check_file_signature(text)
            if file_hit:
                dec_name, filetype, nbytes = file_hit
                note = (f"[DOSYA TESPİT EDİLDİ] {dec_name} ile decode edilince "
                        f"{filetype} imzasına uyuyor ({nbytes} byte). Bu metin değil, "
                        f"binary bir dosya — diske yazıp açman lazım.")
                results.append(Candidate(chain=list(chain) + [f"{dec_name} -> dosya"],
                                          text=note, score=93.0, kind="file"))
                continue

            base_score = score_text(text)
            if chain and chain[-1] in HIGH_CONFIDENCE_DECODERS:
                base_score = max(base_score, HIGH_CONFIDENCE_FLOOR)
            if chain:
                results.append(Candidate(chain=list(chain), text=text, score=base_score, kind="chain"))

            if depth >= max_depth:
                continue

            if skip_all:
                continue

            for name, fn, kind in SINGLE_SHOT_DECODERS:
                if budget.exhausted():
                    break
                if skip_ciphers and kind == "cipher":
                    continue
                try:
                    out = fn(text)
                except Exception:
                    out = None
                if out and _is_meaningfully_different(text, out) and out not in seen_texts:
                    out_score = score_text(out)
                    # A* heuristic: Derinlik basina ufak bir ceza uygulayarak kisa cozumleri ve gercekten cok iyi olan derin cozumleri onceliklendirir.
                    priority_score = out_score - (depth * 5.0)
                    heapq.heappush(pq, (-priority_score, depth + 1, counter, chain + [name], out))
                    counter += 1

            if skip_ciphers:
                continue

            try:
                caesar_results = try_all_caesar(text)
                scored = sorted(((sh, out, score_text(out)) for sh, out in caesar_results),
                                 key=lambda t: t[2], reverse=True)
                for shift, out, sc in scored[:2]:
                    if budget.exhausted():
                        break
                    if _is_meaningfully_different(text, out) and out not in seen_texts:
                        priority_score = sc - (depth * 5.0)
                        heapq.heappush(pq, (-priority_score, depth + 1, counter, chain + [f"Caesar (shift {shift})"], out))
                        counter += 1
            except Exception:
                pass

    a_star_search(raw.strip())

    if not skip_ciphers:
        _run_expensive_analyzers(raw.strip(), results)
    else:
        reason = ("Girdi yapısal olarak KESIN bir hash/KDF formatına uyuyor (bkz. Karakter Seti Analizi)."
                   if skip_all else
                   "Girdi, uzunluğuyla bilinen bir hash formatına (MD5/SHA1/SHA256 ailesi vb.) uyuyor.")
        results.append(Candidate(
            chain=["(klasik şifre kırma denemeleri atlandı)"],
            text=f"{reason} Hash'ler tek yönlüdür; Caesar/Vigenère/Beaufort/XOR/Affine gibi klasik "
                 "şifre kırma teknikleriyle 'çözülmeye' çalışılması anlamsız gürültü üretir, o yüzden atlandı.",
            score=5.0, kind="info"))

    try:
        # ONEMLI: entropi uyarisi SADECE hicbir decoder anlamli/okunabilir bir
        # sonuc BULAMADIYSA gosterilir. Yoksa yanlis-alfabe denemeleri (orn.
        # duz Base64 metnini Base85/Base91 gibi YANLIS bir decoder'la da
        # "deneyip" o da bir cikti uretince, o cikti dogal olarak rastgele
        # gorunur ve entropi yuksek cikar - bu GERCEK sifreleme degil, sadece
        # yanlis decoder uygulanmis olmasi. Test ederken bunu yakaladim: gercek
        # bir Base64 metni dogru cozulmusken, Base85 yanlis-alfabe denemesi
        # "yuksek entropi -> sifreli" diye YANLIS UYARI veriyordu ve hatta
        # dogru cevabin ONUNE geciyordu. Simdi: eger herhangi bir chain/file
        # sonucu zaten anlamli skor (>=40) aldiysa, entropi uyarilari tamamen
        # bastiriliyor.
        #
        # AYRICA: skip_ciphers True ise (girdi hash/KDF'ye benziyor) entropi
        # kontrolunu HIC calistirmiyoruz - ayni yanlis-alfabe sorunu bir bcrypt
        # hash'inde de olusuyordu (Base85/Base91 ile "denenince" rastgele
        # gorunumlu cikti -> yanlis "yuksek entropi" alarmi). Bir hash zaten
        # Karakter Seti Analizi'nde acikca tanimlandigi icin, ayrica entropi
        # notu eklemek sadece gurultu ve potansiyel yanlis-alarm demek.
        best_existing_score = max((c.score for c in results if c.kind in ("chain", "file")), default=0.0)
        if not skip_ciphers and best_existing_score < 40.0:
            for decoder_name, rep in _check_entropy_root(raw.strip()):
                ecb_extra = f" {rep.ecb_repeat_note}" if rep.ecb_repeat_found else ""
                note = (f"[YÜKSEK ENTROPİ] {decoder_name} ile decode edilince {rep.length} byte, "
                        f"{rep.entropy_bits_per_byte:.2f} bit/byte entropi çıktı. {rep.note}{ecb_extra}")
                results.append(Candidate(
                    chain=[f"{decoder_name} -> entropi analizi"],
                    text=note, score=68.0, kind="entropy"))
    except Exception:
        pass

    results.append(Candidate(chain=["(decode uygulanmadı - orijinal metin)"], text=raw.strip(),
                              score=score_text(raw.strip()), kind="original"))

    best_by_text = {}
    for c in results:
        key = c.text.strip()
        existing = best_by_text.get(key)
        if existing is None:
            best_by_text[key] = c
        elif c.kind == "file" and existing.kind != "file":
            best_by_text[key] = c
        elif existing.kind != "file" and len(c.chain) < len(existing.chain):
            best_by_text[key] = c

    ranked = sorted(best_by_text.values(), key=lambda c: c.score, reverse=True)
    return ranked[:top_n]


def _bytes_from_text_guess(text: str) -> Optional[bytes]:
    """XOR analizleri icin en olasi byte temsiline cevirir: once hex, sonra base64,
    sonra dogrudan latin-1 (ham byte olarak)."""
    s2 = text.strip()
    stripped = s2.replace(" ", "").replace("\n", "")
    if stripped and len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        try:
            return binascii.unhexlify(stripped)
        except Exception:
            pass
    try:
        pad = (-len(stripped)) % 4
        return base64.b64decode(stripped + "=" * pad, validate=True)
    except Exception:
        pass
    try:
        return s2.encode("latin-1")
    except Exception:
        return None


def _run_expensive_analyzers(raw: str, results: List[Candidate]):
    # Substitution (4.5s) ve Columnar Transposition (3.5s) kirma, en pahali
    # iki analiz - eger recurse() asamasinda zaten guclu bir duz-metin adayi
    # bulunduysa (skor >=55, yani net bir cevap var), bunlari calistirmaya
    # gerek yok. Bu hem performansi ciddi arttirir (tek sorguda ~8sn tasarruf)
    # hem de zaten dogru olan sonucun yaninda alakasiz "belki de transposition"
    # gurultusu eklemeyi engeller - net cevap varken ek arama yapmak
    # dogrulugu degil sadece gecikmeyi arttirir.
    already_solved = max((c.score for c in results if c.kind in ("chain", "file")), default=0.0) >= 55.0

    data = _bytes_from_text_guess(raw)
    if data and 2 <= len(data) <= 20000:
        try:
            single = crack_single_byte_xor(data)
            if single:
                key, text, sc = single
                results.append(Candidate(
                    chain=[f"XOR tek-byte kırma (anahtar=0x{key:02x})"],
                    text=text, score=sc))
        except Exception:
            pass
        try:
            rep = crack_repeating_xor(data)
            if rep:
                key, text, sc = rep
                key_display = key.hex()
                try:
                    key_ascii = key.decode("ascii")
                    if key_ascii.isprintable():
                        key_display = f'"{key_ascii}" (hex: {key.hex()})'
                except Exception:
                    pass
                results.append(Candidate(
                    chain=[f"XOR tekrarlayan-anahtar kırma (anahtar tahmini: {key_display})"],
                    text=text, score=sc))
        except Exception:
            pass

    try:
        vig = crack_vigenere(raw)
        if vig:
            key_str, text, sc = vig
            results.append(Candidate(
                chain=[f"Vigenère kırma (anahtar tahmini: {key_str})"],
                text=text, score=sc))
    except Exception:
        pass

    try:
        beau = crack_beaufort(raw)
        if beau:
            key_str, text, sc = beau
            results.append(Candidate(
                chain=[f"Beaufort kırma (anahtar tahmini: {key_str})"],
                text=text, score=sc))
    except Exception:
        pass

    try:
        letters_only_len = sum(1 for c in raw if c.isalpha())
        if letters_only_len >= 10:
            rail_results = try_all_rail_fence(raw)
            best = max(rail_results, key=lambda t: score_text(t[1])) if rail_results else None
            if best:
                rails, text = best
                sc = score_text(text)
                results.append(Candidate(chain=[f"Rail Fence (rails={rails})"], text=text, score=sc))
    except Exception:
        pass

    try:
        letters_only_len = sum(1 for c in raw if c.isalpha())
        if letters_only_len >= 8:
            affine_results = try_all_affine(raw)
            best = max(affine_results, key=lambda t: score_text(t[1])) if affine_results else None
            if best:
                (a, b), text = best
                sc = score_text(text)
                results.append(Candidate(chain=[f"Affine kırma (a={a}, b={b})"], text=text, score=sc))
    except Exception:
        pass

    try:
        letters_only_len = sum(1 for c in raw if c.isalpha())
        if not already_solved and letters_only_len >= 80:  # substitution kirma icin pratikte guvenilir minimum
            sub = crack_substitution(raw, time_budget_seconds=4.5)
            if sub:
                key_str, text, sc, fitness, confidence_note = sub
                results.append(Candidate(
                    chain=[f"Substitution kırma (hill-climbing, {confidence_note})"],
                    text=text, score=sc))
    except Exception:
        pass

    try:
        if not already_solved and len(raw.strip()) >= 20:
            trans = crack_columnar_transposition(raw, time_budget_seconds=3.5)
            if trans:
                n_cols, order, text, sc, fitness = trans
                results.append(Candidate(
                    chain=[f"Columnar Transposition kırma ({n_cols} sütun, sıra={order})"],
                    text=text, score=sc))
    except Exception:
        pass
