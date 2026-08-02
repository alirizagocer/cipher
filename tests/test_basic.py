"""
Basit sanity testleri. Calistirmak icin: python3 -m pytest tests/ (pytest gerekir)
veya: python3 tests/test_basic.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import base64 as _b64
import json as _json

from ciphertool.engine import explore
from ciphertool.decoders import (
    try_base64, try_hex, try_rot13, try_atbash, try_morse, try_base32,
    try_jwt, try_html_entities, try_unicode_escape, try_polybius,
    try_base45, try_base36, caesar_shift,
)
from ciphertool.crack import (
    crack_single_byte_xor, crack_repeating_xor, crack_vigenere, crack_beaufort,
    crack_substitution,
)
from ciphertool.transposition import crack_columnar_transposition
from ciphertool.filesig import detect_file_signature
from ciphertool.hashid import identify_hash
from ciphertool.entropy import analyze_entropy, detect_ecb_repetition, CLASS_COMPRESSED_OR_ENCRYPTED
import hashlib as _hashlib


def top_text(raw, **kw):
    cands = explore(raw, **kw)
    return cands[0].text if cands else None


def test_base64():
    assert try_base64("SGVsbG8=") == "Hello"


def test_hex():
    assert try_hex("48656c6c6f") == "Hello"


def test_rot13():
    assert try_rot13("Uryyb") == "Hello"


def test_atbash():
    assert try_atbash(try_atbash("Hello")) == "Hello"


def test_morse():
    assert try_morse(".... . .-.. .-.. ---") == "HELLO"


def test_base32():
    import base64 as b
    encoded = b.b32encode(b"Hello World").decode()
    assert try_base32(encoded) == "Hello World"


def test_engine_ranks_correct_answer_first():
    result = top_text("SGVsbG8gV29ybGQh")
    assert result == "Hello World!"


def test_xor_single_byte():
    pt = b"This is a secret message that should be recovered by brute force!"
    ct = bytes(b ^ 0x42 for b in pt)
    res = crack_single_byte_xor(ct)
    assert res[0] == 0x42
    assert res[1] == pt.decode()


def test_xor_repeating_key():
    plain = ("It was the best of times, it was the worst of times, it was the "
              "age of wisdom, it was the age of foolishness, it was the epoch "
              "of belief, it was the epoch of incredulity, it was the season "
              "of Light, it was the season of Darkness, it was the spring of "
              "hope, it was the winter of despair, we had everything before us.")
    pt = plain.encode("ascii")
    key = b"DICKENS"
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))
    res = crack_repeating_xor(ct)
    # bulunan anahtar dogru anahtarin bir tekrari olabilir (orn. 'DICKENSDICKENS')
    # onemli olan decode edilen metnin dogru olmasi
    assert res[1] == plain
    assert key in res[0] or res[0] in key


def test_vigenere_crack():
    def encrypt(text, key):
        out, ki = [], 0
        for c in text:
            if c.isalpha():
                shift = ord(key[ki % len(key)].upper()) - 65
                base = 65 if c.isupper() else 97
                out.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    plain = ("It was the best of times it was the worst of times it was the age "
              "of wisdom it was the age of foolishness it was the epoch of belief "
              "it was the epoch of incredulity it was the season of light it was "
              "the season of darkness it was the spring of hope it was the winter "
              "of despair we had everything before us we had nothing before us")
    ct = encrypt(plain, "KEY")
    res = crack_vigenere(ct)
    assert res is not None
    assert res[1].lower() == plain.lower()


def test_file_signature_detection():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    assert detect_file_signature(png) == "PNG image"
    assert detect_file_signature(b"not a file") is None


def test_jwt_decode():
    header = _b64.urlsafe_b64encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = _b64.urlsafe_b64encode(_json.dumps({"user": "ali"}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}.sig"
    out = try_jwt(token)
    assert out is not None
    assert "HS256" in out and "ali" in out


def test_html_entities():
    assert try_html_entities("Hello&nbsp;World &amp; more") == "Hello\xa0World & more"


def test_unicode_escape():
    assert try_unicode_escape("\\u0048\\u0065\\u006c\\u006c\\u006f") == "Hello"


def test_engine_finds_png_via_base64():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30
    b64 = _b64.b64encode(png).decode()
    cands = explore(b64, max_depth=2, top_n=5)
    assert any(c.kind == "file" for c in cands)


def test_hashid_bcrypt_is_certain():
    fake_bcrypt = "$2b$12$KIXQ7z8j3n5f6h1k2l3m4uO9pQ8rT7vW6xY5zA4bC3dE2fG1hI0jK"
    cands = identify_hash(fake_bcrypt)
    assert cands and cands[0].name == "bcrypt" and cands[0].certain
    assert cands[0].confidence >= 95


def test_hashid_md5crypt_is_certain():
    cands = identify_hash("$1$abcdefgh$somehashvaluehere1234567890")
    assert cands and cands[0].name == "md5crypt" and cands[0].certain


def test_hashid_django_pbkdf2_is_certain():
    cands = identify_hash("pbkdf2_sha256$260000$somesalt$somehashbase64==")
    assert cands and cands[0].name == "Django PBKDF2-SHA256" and cands[0].certain


def test_hashid_32hex_lists_all_candidates_individually():
    md5_hex = _hashlib.md5(b"test").hexdigest()
    cands = identify_hash(md5_hex)
    names = [c.name for c in cands]
    # Her aday ayri ayri isimlendirilmis olmali, tek bir "bunlardan biri" cumlesi degil
    assert "MD5" in names and "NTLM" in names and "MD4" in names
    assert not any(c.certain for c in cands)  # sadece uzunluktan -> kesin degil
    assert cands[0].name == "MD5"  # en yaygin oldugu icin en yuksek agirlik


def test_hashid_64hex_sha256_top_candidate():
    sha256_hex = _hashlib.sha256(b"test").hexdigest()
    cands = identify_hash(sha256_hex)
    assert cands[0].name == "SHA256"
    assert cands[0].confidence > cands[1].confidence  # net siralama var


def test_hashid_40hex_sha1_top_candidate():
    sha1_hex = _hashlib.sha1(b"test").hexdigest()
    cands = identify_hash(sha1_hex)
    assert cands[0].name == "SHA1"


def test_hashid_ntlm_uppercase_hint_shifts_confidence():
    md5_hex = _hashlib.md5(b"test").hexdigest()
    upper_cands = {c.name: c.confidence for c in identify_hash(md5_hex.upper())}
    lower_cands = {c.name: c.confidence for c in identify_hash(md5_hex)}
    # Buyuk harf hex girdide NTLM guveni artmali, MD5 guveni hafif azalmali
    assert upper_cands["NTLM"] > lower_cands["NTLM"]
    assert upper_cands["MD5"] < lower_cands["MD5"]


def test_hashid_kerberoasting_is_certain():
    fake = "$krb5tgs$23$user$realm$*app*$" + "a" * 100
    cands = identify_hash(fake)
    assert cands and "Kerberoasting" in cands[0].name and cands[0].certain


def test_hashid_apache_apr1_is_certain():
    cands = identify_hash("$apr1$abcd1234$somehashvaluehere1234567890")
    assert cands and cands[0].name.startswith("Apache") and cands[0].certain


def test_hashid_generic_32hex_not_falsely_flagged_as_cisco_or_oracle():
    # Onceki bir hatada asiri genis regex'ler herhangi bir uzun hex string'i
    # yanlislikla "Cisco Type 7" / "Oracle" olarak KESIN isaretliyordu - bunu
    # engelleyen regresyon testi.
    md5_hex = _hashlib.md5(b"random").hexdigest()
    cands = identify_hash(md5_hex)
    names = [c.name for c in cands]
    assert not any("Cisco" in n or "Oracle" in n for n in names)
    assert not any(c.certain for c in cands)


def test_polybius_square():
    # HELLO -> H=23 E=15 L=31 L=31 O=34
    assert try_polybius("23 15 31 31 34") == "HELLO"


def test_base45():
    # RFC 9285 ornek: "AB" -> "BB8"
    assert try_base45("BB8") == "AB"


def test_base36_roundtrip():
    import string as _s
    n = int.from_bytes(b"Hi", "big")
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    x, out = n, []
    while x:
        x, r = divmod(x, 36)
        out.append(digits[r])
    encoded = "".join(reversed(out))
    assert try_base36(encoded) == "Hi"


def test_beaufort_crack_roundtrip():
    # Beaufort: C = K - P (mod 26), decrypt de ayni formul: P = K - C (mod 26)
    def beaufort_encrypt(pt, key):
        out = []
        ki = 0
        for c in pt:
            if c.isalpha():
                p = ord(c.upper()) - 65
                k = ord(key[ki % len(key)]) - 65
                out.append(chr((k - p) % 26 + 65))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    plaintext = ("THISISASECRETMESSAGEENCODEDWITHBEAUFORTCIPHERANDSHOULDBELONGENOUGH"
                 "TOALLOWTHEINDEXOFCOINCIDENCETOFINDTHEKEYLENGTHRELIABLYINTESTS")
    key = "KEY"
    ct = beaufort_encrypt(plaintext, key)
    result = crack_beaufort(ct)
    assert result is not None
    _, decoded, score = result
    assert decoded.replace(" ", "") == plaintext.replace(" ", "")


def test_substitution_crack_hillclimbing():
    import random as _r
    import string as _s
    plaintext = ("IN CRYPTOGRAPHY A SUBSTITUTION CIPHER IS A METHOD OF ENCRYPTING "
                 "IN WHICH UNITS OF PLAINTEXT ARE REPLACED WITH THE CIPHERTEXT IN A "
                 "DEFINED MANNER WITH THE HELP OF A KEY THE RECEIVER DECIPHERS THE "
                 "TEXT BY PERFORMING THE INVERSE SUBSTITUTION USING THE SAME KEY "
                 "THIS TECHNIQUE HAS BEEN USED FOR CENTURIES IN VARIOUS FORMS")
    alphabet = list(_s.ascii_uppercase)
    shuffled = alphabet[:]
    _r.seed(42)
    _r.shuffle(shuffled)
    enc_map = dict(zip(alphabet, shuffled))
    ciphertext = "".join(enc_map.get(c, c) for c in plaintext)

    result = crack_substitution(ciphertext, time_budget_seconds=6.0)
    assert result is not None
    _, decoded, score, fitness, confidence_note = result
    assert decoded.replace(" ", "") == plaintext.replace(" ", "")


def test_substitution_crack_too_short_returns_none():
    assert crack_substitution("SHORT TEXT HERE") is None


def test_entropy_random_data_classified_as_encrypted():
    import os as _os
    b = _os.urandom(128)
    rep = analyze_entropy(b)
    assert rep.classification == CLASS_COMPRESSED_OR_ENCRYPTED


def test_entropy_english_text_classified_as_plain():
    text = (b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG WHILE THE FIVE BOXING "
            b"WIZARDS JUMP QUICKLY ACROSS THE FIELD TODAY IN THE AFTERNOON SUN")
    rep = analyze_entropy(text)
    assert rep.classification != CLASS_COMPRESSED_OR_ENCRYPTED


def test_entropy_ecb_repetition_detected():
    block = b"AAAAAAAAAAAAAAAA"  # 16 byte, ECB'de ayni plaintext -> ayni ciphertext bloklari
    data = block + b"BBBBBBBBBBBBBBBB" + block + block
    found, n_repeated, total = detect_ecb_repetition(data)
    assert found is True
    assert n_repeated >= 1


def test_engine_flags_high_entropy_data_not_legit_encoding():
    import os as _os
    import base64 as _b64_2
    random_b64 = _b64_2.b64encode(_os.urandom(96)).decode()
    results = explore(random_b64, max_depth=2, top_n=10)
    top = max(results, key=lambda r: r.score)
    assert top.kind == "entropy"


def test_columnar_transposition_crack():
    from ciphertool.transposition import decrypt_columnar, _column_lengths

    def encrypt_columnar(plaintext, order):
        n_cols = len(order)
        lengths = _column_lengths(len(plaintext), n_cols)
        R = -(-len(plaintext) // n_cols)
        grid = [[None] * n_cols for _ in range(R)]
        idx = 0
        for row in range(R):
            for col in range(n_cols):
                if idx < len(plaintext) and row < lengths[col]:
                    grid[row][col] = plaintext[idx]
                    idx += 1
        out = []
        for original_col in order:
            for row in range(R):
                if grid[row][original_col] is not None:
                    out.append(grid[row][original_col])
        return "".join(out)

    plaintext = ("ATTACK AT DAWN NEAR THE OLD BRIDGE BRING ALL YOUR EQUIPMENT "
                 "AND MEET AT THE USUAL PLACE BEFORE SUNRISE")
    key_order = [3, 0, 4, 1, 2]
    ciphertext = encrypt_columnar(plaintext, key_order)

    result = crack_columnar_transposition(ciphertext, time_budget_seconds=4.0)
    assert result is not None
    n_cols, order, decoded, score, fitness = result
    assert decoded == plaintext


def test_engine_does_not_flag_legit_base64_text_as_encrypted():
    import base64 as _b64_2
    text = "The secret meeting will happen tonight near the old bridge by the river"
    b64 = _b64_2.b64encode(text.encode()).decode()
    results = explore(b64, max_depth=2, top_n=10)
    top = max(results, key=lambda r: r.score)
    assert top.kind == "chain"
    assert "secret meeting" in top.text.lower()


def test_engine_certain_hash_has_no_entropy_noise():
    # Regresyon: bcrypt gibi KESIN tespit edilen bir hash'te, yanlis-alfabe
    # decode denemeleri (Base85/Base91) rastgele gorunumlu cikti uretip
    # yanlislikla "yuksek entropi -> sifreli" gurultusu ekliyordu. Artik
    # skip_ciphers=True oldugunda entropi kontrolu de tamamen devre disi.
    fake_bcrypt = "$2b$12$KIXQ7z8j3n5f6h1k2l3m4uO9pQ8rT7vW6xY5zA4bC3dE2fG1hI0jK"
    results = explore(fake_bcrypt, max_depth=2, top_n=10)
    assert not any(r.kind == "entropy" for r in results)


def test_a1z26():
    from ciphertool.decoders import try_a1z26
    assert try_a1z26("8-5-12-12-15") == "HELLO"
    assert try_a1z26("8 5 12 12 15") == "HELLO"
    assert try_a1z26("812") is None  # ayirici yok


def test_nato_phonetic():
    from ciphertool.decoders import try_nato_phonetic
    assert try_nato_phonetic("HOTEL ECHO LIMA LIMA OSCAR") == "HELLO"


def test_vigenere_crack_multi_candidate_short_key():
    # Kisa anahtarli (3 harf) + orta uzunluklu metinde tek-IC-tahmini bazen
    # yanlis uzunluga gidebiliyordu - coklu aday + quadgram dogrulamasi
    # bunu duzeltiyor mu diye kontrol eden regresyon testi.
    def vigenere_encrypt(pt, key):
        out = []
        ki = 0
        for c in pt:
            if c.isalpha():
                k = ord(key[ki % len(key)].upper()) - 65
                out.append(caesar_shift(c, -k))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    plaintext = ("THE WEATHER TODAY IS QUITE PLEASANT WITH CLEAR SKIES AND A GENTLE "
                 "BREEZE COMING FROM THE WEST WE SHOULD GO FOR A WALK IN THE PARK")
    ct = vigenere_encrypt(plaintext, "KEY")
    result = crack_vigenere(ct)
    assert result is not None
    _, decoded, score = result
    assert decoded.replace(" ", "").upper() == plaintext.replace(" ", "").upper()


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"OK   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} test gecti")
    sys.exit(1 if failed else 0)
