import re

from .hashid import identify_hash, format_hash_report


# ---------------------------------------------------------------------------
# Format imzasi tespiti yardimci fonksiyonlari
# Hash tespitine benzer mantik: yapisal olarak KESIN taninan formlar.
# ---------------------------------------------------------------------------

def _detect_pem(s: str):
    """-----BEGIN ... ----- blogu: sertifika/anahtar PEM formati."""
    m = re.search(r"-----BEGIN ([A-Z ]+)-----", s)
    if m:
        return f"PEM bloğu tespit edildi: '-----BEGIN {m.group(1)}-----' → X.509 sertifika / RSA/EC anahtar / CSR / DH parametresi olabilir. Şifre değil, kriptografik materyal."
    return None


def _detect_iban(s: str):
    """IBAN: 2 harf ülke kodu + 2 check digit + 11-30 alfanumerik."""
    # Boşluk ve tireler kaldırılmış formda kontrol
    clean = re.sub(r"[\s\-]", "", s.strip()).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{4,30}", clean):
        return None
    # Basit IBAN Luhn kontrolü (mod 97): ülke+check sona taşı, A=10..Z=35
    rearranged = clean[4:] + clean[:4]
    numeric = ""
    for c in rearranged:
        if c.isdigit():
            numeric += c
        else:
            numeric += str(ord(c) - 55)
    if int(numeric) % 97 == 1:
        return f"IBAN formatı tespit edildi ({clean[:2]} — ülke kodu, Mod97 doğrulaması ✓) → Uluslararası banka hesap numarası, şifre değil."
    return None


def _detect_luhn_card(s: str):
    """Kredi kartı: 13-19 rakam, Luhn algoritması doğrulaması."""
    clean = re.sub(r"[\s\-]", "", s.strip())
    if not re.fullmatch(r"\d{13,19}", clean):
        return None
    # Luhn algoritması
    total = 0
    reverse = clean[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    if total % 10 == 0:
        # Ek: ilk birkaç rakamdan kart tipini tahmin et
        prefixes = [
            ("4", "Visa"),
            ("51", "Mastercard"), ("52", "Mastercard"), ("53", "Mastercard"),
            ("54", "Mastercard"), ("55", "Mastercard"),
            ("34", "AmEx"), ("37", "AmEx"),
            ("6011", "Discover"), ("65", "Discover"),
            ("35", "JCB"),
        ]
        card_type = "bilinmeyen kart"
        for pfx, name in prefixes:
            if clean.startswith(pfx):
                card_type = name
                break
        return f"Kredi kartı numarası olabilir (Luhn doğrulaması ✓, {len(clean)} rakam, olası tip: {card_type}) → Kişisel veri, şifre değil."
    return None


def _detect_mac(s: str):
    """MAC adresi: 6 grup 2 hex, ':' veya '-' ile ayrılmış."""
    if re.fullmatch(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", s.strip()):
        return "MAC adresi formatı → Ağ arayüz kimliği, şifre değil."
    return None


def _detect_ipv6(s: str):
    """Basit IPv6 tespiti (tam veya kısaltılmış)."""
    s2 = s.strip()
    # Çok basit kontrol: ':' içeren ve sadece hex + ':' karakterlerinden oluşan
    if ":" not in s2:
        return None
    if not re.fullmatch(r"[0-9A-Fa-f:]+", s2):
        return None
    parts = s2.split(":")
    if len(parts) < 3 or len(parts) > 8:
        return None
    if all(re.fullmatch(r"[0-9A-Fa-f]{0,4}", p) for p in parts):
        return "IPv6 adresi olabilir → Ağ adresi, şifre değil."
    return None


def _detect_uuencode_header(s: str):
    """uuencode blok başlığı."""
    if re.match(r"^begin \d{3} \S+", s.strip(), re.IGNORECASE):
        return "uuencode bloğu (begin + mod + dosyaadı) → Unix uuencode kodlaması tespit edildi."
    return None


def _detect_pem_fingerprint(s: str):
    """SHA256 parmak izi formatı (hex gruplar, ':' ile)."""
    clean = s.strip()
    if re.fullmatch(r"([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}", clean):
        return "TLS/X.509 sertifika SHA256 parmak izi formatı (32 grup 2-hex ':' ile) → Sertifika parmak izi, şifre değil."
    if re.fullmatch(r"([0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}", clean):
        return "TLS/X.509 sertifika SHA1 parmak izi formatı (20 grup 2-hex ':' ile) → Sertifika parmak izi, şifre değil."
    return None


FORMAT_DETECTORS = [
    _detect_pem,
    _detect_iban,
    _detect_luhn_card,
    _detect_mac,
    _detect_ipv6,
    _detect_uuencode_header,
    _detect_pem_fingerprint,
]


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

    # Format imzasi tespiti: PEM, IBAN, kredi karti, MAC, IPv6 vb.
    # Hash tespitine benzer mantik: yapisal olarak KESIN taninan yapilar.
    for detector in FORMAT_DETECTORS:
        try:
            result = detector(s2)
            if result:
                notes.append(result)
        except Exception:
            pass

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
