"""
Pattern-tabanli hash / kimlik dogrulama formati tespit motoru.

Iki katmanli calisir:
1) PREFIX_PATTERNS: yapisal olarak KESIN olan imzalar ($2b$, $argon2id$, JWT vb.)
   -> confidence 90-99, tek aday, "kesin" diye isaretlenir.
2) LENGTH_CANDIDATES: sadece hex uzunluguna bakarak ayirt edilemeyen durumlar
   -> ayni uzunluktaki TUM olasi algoritmalar TEK TEK isimlendirilir ve
   gercek-dunya yayginligina gore agirliklandirilmis bir "tahmini olasilik"
   yuzdesi verilir. Asla "bunlardan biri" gibi tek cumleyle gecistirilmez -
   her aday kendi satirinda, kendi yuzdesiyle listelenir.

Not: Yuzdeler kanit degil, istatistiksel oncelik siralamasidir (ornegin MD5,
gercek dunyada Haval-128'den kat kat daha sik goruldugu icin daha yuksek
baslar). Ayirt etmenin tek kesin yolu context (nereden geldigi, hangi sistem
uretti) oldugundan, arac bunu acikca belirtir.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class HashCandidate:
    name: str
    confidence: float          # 0-100
    certain: bool               # True = yapisal olarak dogrulanmis (prefix/format)
    note: str = ""
    example_context: str = ""   # nerede/nasil kullanildigina dair kisa ipucu


# ---------------------------------------------------------------------------
# 1) YAPISAL OLARAK KESIN OLAN FORMATLAR (prefix / delimiter tabanli)
# ---------------------------------------------------------------------------
# Her biri (regex, isim, confidence, not, context)
PREFIX_PATTERNS = [
    (r"^\$2[aby]\$\d{2}\$", "bcrypt", 99,
     "'$2a$/$2b$/$2y$' + cost faktoru -> bcrypt imzasi, format olarak kesin.",
     "Genellikle web uygulamalarinda kullanici parolasi hash'i (PHP/Node/Ruby)."),
    (r"^\$1\$", "md5crypt", 98,
     "'$1$' -> eski Unix crypt(3) MD5 varyanti.",
     "Eski /etc/shadow girdileri."),
    (r"^\$5\$", "sha256crypt", 98,
     "'$5$' -> Unix crypt(3) SHA-256 varyanti.",
     "Modern /etc/shadow (Linux)."),
    (r"^\$6\$", "sha512crypt", 98,
     "'$6$' -> Unix crypt(3) SHA-512 varyanti, en yaygin modern /etc/shadow formati.",
     "Linux /etc/shadow varsayilani (Debian/Ubuntu/RHEL)."),
    (r"^\$7\$", "scrypt", 95,
     "'$7$' -> scrypt KDF imzasi.", ""),
    (r"^\$argon2(id|i|d)\$", "Argon2", 99,
     "'$argon2id$/$argon2i$/$argon2d$' -> Argon2 (2015 Password Hashing Competition kazanani), format kesin.",
     "Modern parola depolama standardi."),
    (r"^\$y\$", "yescrypt", 96,
     "'$y$' -> yescrypt, guncel Linux dagitimlarinda ($6$ yerine) varsayilan.", ""),
    (r"^\$P\$|^\$H\$", "phpass (WordPress/phpBB)", 95,
     "'$P$'/'$H$' -> phpass tabanli portable hash (WordPress, phpBB, Drupal 7).", ""),
    (r"^\{SSHA\}", "SSHA (Salted SHA, base64)", 95,
     "'{SSHA}' etiketi -> LDAP tarzi salted SHA1, base64 encoded.", "LDAP/OpenLDAP kullanici dizinleri."),
    (r"^\{SHA\}", "SHA (base64, LDAP)", 95,
     "'{SHA}' etiketi -> duz SHA1, base64 encoded (salt yok).", "LDAP."),
    (r"^\{crypt\}", "crypt() wrapper", 90,
     "'{crypt}' etiketi -> icindeki deger crypt(3) ciktisi.", ""),
    (r"^sha1\$.+\$[0-9a-f]{40}$", "Django SHA1 (salted)", 96,
     "'sha1$salt$hash' -> eski Django parola formati.", "Django <1.4."),
    (r"^pbkdf2_sha256\$", "Django PBKDF2-SHA256", 97,
     "'pbkdf2_sha256$iterasyon$salt$hash' -> Django varsayilan parola hash'i.", "Django >=1.4."),
    (r"^\$pbkdf2(-sha\d+)?\$", "PBKDF2 (genel)", 95,
     "'$pbkdf2$' / '$pbkdf2-sha256$' -> PBKDF2 KDF imzasi.", ""),
    (r"^[0-9a-fA-F]{32}:[a-zA-Z0-9]{1,32}$", "Hash:Salt formatı (32-hex + salt)", 60,
     "32 hex + ':' + salt -> muhtemelen MD5/NTLM + ayri salt (cracker araclari icin tipik format).", ""),
]

# JWT ayrica charset.py'da tespit ediliyor, burada tekrar etmiyoruz.

# ---------------------------------------------------------------------------
# 2) SADECE HEX UZUNLUGUNA BAKARAK AYIRT EDILEMEYEN DURUMLAR
# ---------------------------------------------------------------------------
# hex_len -> [(isim, tahmini_agirlik, not)]
# Agirliklar gercek-dunya yayginligina gore KABA bir siralama - kanit degil.
LENGTH_CANDIDATES = {
    8:  [
        ("CRC32", 55, "Checksum, kriptografik hash DEGIL. Dosya bütünlüğü/ZIP'te sık görülür."),
        ("Adler-32", 20, "zlib/PNG'de kullanılan checksum."),
        ("CRC32B", 15, "PHP crc32() varyantı."),
        ("Snefru (kısaltılmış/nadir)", 10, "Nadiren görülür."),
    ],
    16: [
        ("CRC64", 40, "Checksum amaçlı, kriptografik değil."),
        ("Half-MD5 (kırpılmış)", 30, "Bazı sistemler MD5'i kısaltarak saklar."),
        ("Tiger-64 (nadir)", 15, ""),
        ("Diğer kırpılmış hash", 15, "Herhangi bir hash'in ilk 16 hex karakteri olabilir."),
    ],
    32: [
        ("MD5", 55, "En yaygın 32-hex hash — eski sistemler, dosya checksum, cache key olarak hâlâ çok yaygın."),
        ("NTLM", 20, "Windows/Active Directory parola hash'i, formatı MD5 ile birebir aynı (ayırt edilemez)."),
        ("MD4", 8, "NTLM'in temeli, nadiren doğrudan görülür."),
        ("RIPEMD-128", 7, "Nadir, bazı Avrupa bankacılık sistemlerinde."),
        ("Haval-128", 5, "Çok nadir, eski Unix araçlarında."),
        ("Tiger-128 (kırpılmış)", 5, "Nadir."),
    ],
    40: [
        ("SHA1", 80, "En yaygın 40-hex hash — git commit ID'leri, eski parola sistemleri, TLS parmak izleri."),
        ("RIPEMD-160", 12, "Bitcoin adres türetmede kullanılır (ama genelde base58'e çevrilir, çıplak hex nadir)."),
        ("Tiger-160", 5, "Nadir."),
        ("HAS-160", 3, "Kore standardı, çok nadir."),
    ],
    56: [
        ("SHA224", 65, "SHA-2 ailesinin kısa varyantı."),
        ("SHA3-224", 25, "Keccak tabanlı, daha az yaygın ama artan kullanım."),
        ("RIPEMD-224", 10, "Nadir."),
    ],
    64: [
        ("SHA256", 78, "En yaygın 64-hex hash — modern parola sistemleri, blockchain, TLS sertifikaları, git (yeni)."),
        ("SHA3-256", 10, "Keccak tabanlı, NIST standardı ama SHA256 kadar yaygın değil."),
        ("BLAKE2s-256", 5, "Performans odaklı sistemlerde (örn. bazı checksum araçları)."),
        ("GOST R 34.11-94", 4, "Rusya standardı, nadiren batı sistemlerinde görülür."),
        ("Snefru-256", 3, "Çok nadir, tarihsel."),
    ],
    96: [
        ("SHA384", 85, "SHA-2 ailesi, TLS sertifikalarında SHA256'dan sonra en yaygın."),
        ("SHA3-384", 15, "Keccak tabanlı, daha az yaygın."),
    ],
    128: [
        ("SHA512", 72, "En yaygın 128-hex hash — modern yüksek güvenlik sistemleri, /etc/shadow (sha512crypt farklı format)."),
        ("Whirlpool", 13, "Bazı dosya bütünlük araçlarında (örn. bazı Linux checksum yardımcı programları)."),
        ("SHA3-512", 10, "Keccak tabanlı NIST standardı."),
        ("Skein-512", 5, "Çok nadir, akademik/deneysel kullanım."),
    ],
}

# Bcrypt/argon2 gibi olmayan ama base64 kodlu (hex degil) hash formatlari icin
# ek bir ipucu: uzunluk + karakter seti kombinasyonu
BASE64_HASH_HINTS = [
    (r"^[A-Za-z0-9+/]{27}=$", "SHA256 (base64 encoded, 32 byte)", 60,
     "Base64'e cevrilmis 32 byte -> genelde SHA256 hash'inin base64 gosterimi (hex degil)."),
    (r"^[A-Za-z0-9+/]{43}=$", "SHA256 (base64, padding'siz varyant)", 55, ""),
    (r"^[A-Za-z0-9+/]{20}=$", "SHA1 (base64 encoded, 20 byte)", 55,
     "Base64'e cevrilmis 20 byte -> SHA1'in base64 gosterimi olabilir."),
]


def identify_hash(s: str) -> List[HashCandidate]:
    """Verilen string icin olasi hash/format adaylarini KESIN ve TAHMINI olarak
    ayri ayri isimlendirip dondurur. Her zaman ayri satirlar - asla tek cumleye
    sikistirilmis 'bunlardan biri' seklinde degil."""
    s2 = s.strip()
    results: List[HashCandidate] = []

    # --- Katman 1: yapisal olarak kesin prefix/format eslesmeleri ---
    matched_certain = False
    for pattern, name, conf, note, ctx in PREFIX_PATTERNS:
        if re.match(pattern, s2):
            results.append(HashCandidate(name=name, confidence=conf, certain=True,
                                          note=note, example_context=ctx))
            matched_certain = True

    if matched_certain:
        # Kesin format bulunduysa uzunluk-tabanli belirsiz adaylari EKLEMEYIZ -
        # zaten net cevap var, gurultu katmiyoruz.
        return sorted(results, key=lambda c: c.confidence, reverse=True)

    # --- Katman 2: sadece hex ise, uzunluk tabanli ayrilmis aday listesi ---
    stripped = re.sub(r"\s", "", s2)
    is_hex = bool(re.fullmatch(r"[0-9A-Fa-f]+", stripped)) and len(stripped) > 0
    if is_hex and len(stripped) in LENGTH_CANDIDATES:
        length = len(stripped)
        candidates = LENGTH_CANDIDATES[length]

        # Ek sinyal: NTLM ciktisi genelde buyuk harf hex olarak paylasilir
        # (mimikatz/hashcat ciktilarinda), MD5 ise cogunlukla kucuk harf.
        # Bu ZAYIF bir sinyal, agirliklari hafifce iter, kesinlik iddia etmez.
        upper_hint = stripped.isupper() and any(c.isalpha() for c in stripped)

        for name, weight, note in candidates:
            conf = float(weight)
            adj_note = note
            if length == 32 and upper_hint:
                if name == "NTLM":
                    conf += 8
                    adj_note += " (Girdi tamamen büyük harf hex — NTLM çıktıları genelde bu şekilde paylaşılır, hafif +sinyal.)"
                elif name == "MD5":
                    conf -= 5
            results.append(HashCandidate(
                name=name, confidence=round(min(conf, 99), 1), certain=False,
                note=adj_note))
        results.sort(key=lambda c: c.confidence, reverse=True)
        return results

    # --- Katman 3: base64 gorunumlu ama hex olmayan hash ipuclari ---
    for pattern, name, conf, note in BASE64_HASH_HINTS:
        if re.fullmatch(pattern, s2):
            results.append(HashCandidate(name=name, confidence=conf, certain=False, note=note))

    return sorted(results, key=lambda c: c.confidence, reverse=True)


def format_hash_report(candidates: List[HashCandidate], top_n: int = 5) -> List[str]:
    """CLI/JSON disinda insanin okuyacagi duz metin satirlari uretir."""
    if not candidates:
        return []
    lines = []
    certain = [c for c in candidates if c.certain]
    if certain:
        lines.append("KESIN TESPIT (yapisal formattan, %{:.0f}+ guven):".format(min(c.confidence for c in certain)))
        for c in certain:
            lines.append(f"  -> {c.name}  [%{c.confidence:.0f}]  {c.note}")
        return lines

    lines.append(f"Uzunluk/format tek basina KESIN ayirt etmiyor -- en olasi {min(top_n, len(candidates))} aday "
                  f"gercek-dunya yayginligina gore siralandi (yuzdeler kanit degil, oncelik sirasidir):")
    for i, c in enumerate(candidates[:top_n], 1):
        lines.append(f"  {i}. {c.name}  -- tahmini olasilik: %{c.confidence:.0f}   {c.note}")
    lines.append("  Kesin ayirt etmek icin: verinin hangi sistemden geldigine bak "
                  "(orn. Windows/AD dumpu ise NTLM, git ise SHA1, TLS sertifikasi ise SHA256/384 agir basar).")
    return lines
