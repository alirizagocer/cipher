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
    try_jwt, try_html_entities, try_unicode_escape,
)
from ciphertool.crack import crack_single_byte_xor, crack_repeating_xor, crack_vigenere
from ciphertool.filesig import detect_file_signature


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
