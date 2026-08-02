import re

from .hashid import identify_hash, format_hash_report


def analyze_charset(s: str) -> list:
    """Hizli goz gezdirme icin karakter seti / uzunluk gozlemleri dondurur (str liste)."""
    notes = []
    s2 = s.strip()
    length = len(s2)
    notes.append(f"Uzunluk: {length} karakter")

    stripped_ws = re.sub(r"\s", "", s2)

    if re.fullmatch(r"[0-9A-Fa-f]+", stripped_ws) and len(stripped_ws) % 2 == 0:
        notes.append("Sadece hex karakterler (0-9a-f), çift uzunluk -> güçlü Hex/Base16 adayı")

    if re.fullmatch(r"[01\s]+", s2) and len(stripped_ws) % 8 == 0 and len(stripped_ws) > 0:
        notes.append("Sadece 0/1, 8'in katı -> Binary adayı")

    if re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped_ws) and len(stripped_ws) % 4 == 0:
        if "=" in s2:
            notes.append("Base64 alfabesi + '=' padding -> güçlü Base64 adayı")
        else:
            notes.append("Base64 alfabesine uyuyor (padding yok, olabilir)")

    if re.fullmatch(r"[A-Za-z0-9\-_]+=*", stripped_ws) and len(stripped_ws) % 4 == 0 and ("-" in s2 or "_" in s2):
        notes.append("URL-safe Base64 alfabesi (-, _) -> olası Base64url")

    if re.fullmatch(r"[A-Z2-7]+=*", stripped_ws.upper()) and len(stripped_ws) % 8 == 0:
        notes.append("Base32 alfabesi (A-Z, 2-7) -> olası Base32")

    b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if stripped_ws and all(c in b58 for c in stripped_ws) and not re.fullmatch(r"[0-9]+", stripped_ws):
        notes.append("0/O/I/l karakterleri YOK, karışık case -> olası Base58 (bitcoin/ipfs tarzı)")

    if re.fullmatch(r"[.\-\s/]+", s2) and ("." in s2 or "-" in s2):
        notes.append("Sadece nokta/tire/boşluk -> Morse code adayı")

    if re.fullmatch(r"[ABab\s]+", s2) and len(stripped_ws) % 5 == 0 and len(stripped_ws) > 0:
        notes.append("Sadece A/B harfleri, 5'in katı -> Bacon Cipher adayı")

    # Hash/KDF tespiti artik ayri bir modulde (hashid.py): yapisal olarak kesin
    # formatlar (bcrypt/argon2/md5crypt/... prefix'leri) tek aday olarak, sadece
    # uzunluktan tahmin edilen durumlar ise TUM adaylar ayri ayri isimlendirilip
    # gercek-dunya yayginligina gore siralanarak dondurulur. "Bunlardan biri"
    # diye gecistiren tek cumle YOK - detay icin analyze_hash() / CLI'daki
    # "Hash/KDF Tespiti" bolumune bak.
    hash_candidates = identify_hash(s2)
    if hash_candidates:
        for line in format_hash_report(hash_candidates, top_n=5):
            notes.append(line)
        notes.append("(Not: hash'ler tek yönlüdür, decode/dönüştürme yapılamaz -- burada yapılan sadece "
                     "hangi algoritma olduğunu tespit etmek, kırmak değil.)")

    parts = s2.split(".")
    if len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_\-]+", p) for p in parts if p):
        notes.append("Üç parça, nokta ile ayrılmış, Base64url alfabesi -> JWT (JSON Web Token) olabilir")

    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", s2):
        notes.append("8-4-4-4-12 tire formatı -> UUID/GUID (şifre değil, kimlik numarası)")

    if re.fullmatch(r"[A-Za-z\s.,!?'\";:]+", s2):
        notes.append("Sadece harf + noktalama, boşluklar korunmuş -> klasik şifre (Caesar/Substitution/Vigenère) ihtimali yüksek")

    upper_ratio = sum(1 for c in s2 if c.isupper()) / max(sum(1 for c in s2 if c.isalpha()), 1)
    if upper_ratio > 0.95 and any(c.isalpha() for c in s2):
        notes.append("Metin tamamen büyük harf -> bazı klasik şifrelerde (özellikle CTF) yaygın bir sunum biçimi")

    eq_count = s2.count("=")
    if eq_count > 0 and s2.rstrip().endswith("="):
        notes.append(f"Sonda '=' padding karakteri ({eq_count} adet) -> Base64/Base32 işareti")

    if not notes[1:]:
        notes.append("Belirgin bir standart kalıba uymuyor -> otomatik decoder taramasına bakılmalı, katmanlı/özel şifreleme olabilir")

    return notes
