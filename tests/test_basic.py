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
from ciphertool.crack import crack_single_byte_xor, crack_repeating_xor, crack_vigenere, crack_beaufort
from ciphertool.filesig import detect_file_signature
from ciphertool.hashid import identify_hash
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
