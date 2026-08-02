"""
Her decoder: (isim, fonksiyon) seklinde. Fonksiyon basarisiz olursa None döner.
Girdi: str  ->  Cikti: str veya None

Base-ailesi fonksiyonlarin `_bytes` varyantlari (try_base64_bytes gibi) raw bytes
dondurur - bunlar hem metne cevirme hem de dosya imzasi (magic byte) tespiti icin
motor (engine.py) tarafindan kullanilir.
"""
import base64
import binascii
import codecs
import html
import json
import quopri
import re
import string
import urllib.parse

# ---------------------------------------------------------------- Base aileler
# Her biri icin "_bytes" varyanti (raw bytes veya None) + text sarmalayicisi.

def try_base64_bytes(s: str):
    s2 = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    if not s2 or len(s2) < 4 or not re.fullmatch(r"[A-Za-z0-9+/=]+", s2):
        return None
    pad = (-len(s2)) % 4
    try:
        return base64.b64decode(s2 + "=" * pad, validate=False)
    except Exception:
        return None


def try_base64(s: str):
    raw = try_base64_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


def try_base64_urlsafe_bytes(s: str):
    s2 = s.strip().replace("\n", "").replace(" ", "")
    if not s2 or len(s2) < 4 or not re.fullmatch(r"[A-Za-z0-9_\-=]+", s2):
        return None
    pad = (-len(s2)) % 4
    try:
        return base64.urlsafe_b64decode(s2 + "=" * pad)
    except Exception:
        return None


def try_base64_urlsafe(s: str):
    raw = try_base64_urlsafe_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


def try_base32_bytes(s: str):
    s2 = s.strip().replace("\n", "").replace(" ", "").upper()
    if not s2 or len(s2) < 8 or not re.fullmatch(r"[A-Z2-7=]+", s2):
        return None
    pad = (-len(s2)) % 8
    try:
        return base64.b32decode(s2 + "=" * pad)
    except Exception:
        return None


def try_base32(s: str):
    raw = try_base32_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


def try_base85_bytes(s: str):
    s2 = s.strip()
    if not s2 or len(s2) < 5:
        return None
    try:
        return base64.b85decode(s2)
    except Exception:
        pass
    try:
        return base64.a85decode(s2)
    except Exception:
        return None


def try_base85(s: str):
    raw = try_base85_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def try_base58_bytes(s: str):
    s2 = s.strip()
    if not s2 or len(s2) < 4 or not all(c in _B58_ALPHABET for c in s2):
        return None
    try:
        num = 0
        for c in s2:
            num = num * 58 + _B58_ALPHABET.index(c)
        raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        n_leading = len(s2) - len(s2.lstrip("1"))
        return b"\x00" * n_leading + raw
    except Exception:
        return None


def try_base58(s: str):
    raw = try_base58_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


_B91_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                  "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
_B91_DECODE_MAP = {c: i for i, c in enumerate(_B91_ALPHABET)}


def try_base91_bytes(s: str):
    s2 = s.strip()
    if not s2 or len(s2) < 4 or not all(c in _B91_DECODE_MAP for c in s2):
        return None
    try:
        v = -1
        b = 0
        n = 0
        out = bytearray()
        for c in s2:
            c_val = _B91_DECODE_MAP[c]
            if v < 0:
                v = c_val
            else:
                v += c_val * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n >= 8:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1
        if v >= 0:
            out.append((b | (v << n)) & 255)
        return bytes(out) if out else None
    except Exception:
        return None


def try_base91(s: str):
    raw = try_base91_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


# Motorun (engine.py) dosya imzasi taramasi icin kullandigi tum bytes-decoder'lar
# (BYTES_DECODERS asagida, tum fonksiyonlar tanimlandiktan sonra kayit ediliyor)


# ---------------------------------------------------------------- Hex / Binary / Octal / Decimal

def try_hex(s: str):
    s2 = re.sub(r"(0x|\\x|,|\s)", "", s.strip())
    if not s2 or len(s2) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", s2):
        return None
    try:
        raw = binascii.unhexlify(s2)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def try_binary(s: str):
    s2 = re.sub(r"[\s,]", "", s.strip())
    if not s2 or len(s2) % 8 != 0 or not re.fullmatch(r"[01]+", s2):
        return None
    try:
        chars = [chr(int(s2[i:i+8], 2)) for i in range(0, len(s2), 8)]
        return "".join(chars)
    except Exception:
        return None


def try_octal(s: str):
    parts = re.split(r"[\s,]+", s.strip())
    parts = [p for p in parts if p]
    if not parts or not all(re.fullmatch(r"[0-7]{1,4}", p) for p in parts):
        return None
    try:
        chars = [chr(int(p, 8)) for p in parts]
        out = "".join(chars)
        return out if out.isprintable() or out.strip() else None
    except Exception:
        return None


def try_decimal(s: str):
    parts = re.split(r"[\s,]+", s.strip())
    parts = [p for p in parts if p]
    if not parts or not all(re.fullmatch(r"\d{1,3}", p) for p in parts):
        return None
    try:
        vals = [int(p) for p in parts]
        if not all(0 <= v <= 255 for v in vals):
            return None
        return "".join(chr(v) for v in vals)
    except Exception:
        return None


# ---------------------------------------------------------------- URL / HTML / Escape

def try_url_decode(s: str):
    if "%" not in s:
        return None
    try:
        out = urllib.parse.unquote(s)
        return out if out != s else None
    except Exception:
        return None


def try_html_entities(s: str):
    if "&" not in s or ";" not in s:
        return None
    try:
        out = html.unescape(s)
        return out if out != s else None
    except Exception:
        return None


def try_unicode_escape(s: str):
    if "\\u" not in s and "\\x" not in s:
        return None
    try:
        out = s.encode("utf-8").decode("unicode_escape")
        out = out.encode("latin-1", errors="ignore").decode("utf-8", errors="replace")
        return out if out != s else None
    except Exception:
        try:
            out = codecs.decode(s, "unicode_escape")
            return out if out != s else None
        except Exception:
            return None


def try_quoted_printable(s: str):
    if "=" not in s:
        return None
    if not re.search(r"=[0-9A-Fa-f]{2}", s):
        return None
    try:
        raw = quopri.decodestring(s.encode("utf-8", errors="ignore"))
        out = raw.decode("utf-8", errors="replace")
        return out if out != s else None
    except Exception:
        return None


def try_jwt(s: str):
    parts = s.strip().split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, _sig = parts
    if not header_b64 or not payload_b64:
        return None
    try:
        def _b64url_json(chunk):
            pad = (-len(chunk)) % 4
            raw = base64.urlsafe_b64decode(chunk + "=" * pad)
            return json.loads(raw.decode("utf-8"))

        header = _b64url_json(header_b64)
        payload = _b64url_json(payload_b64)
        if "alg" not in header and "typ" not in header:
            return None
        pretty = (
            f"[JWT tespit edildi]\n"
            f"header : {json.dumps(header, ensure_ascii=False)}\n"
            f"payload: {json.dumps(payload, ensure_ascii=False)}\n"
            f"(imza doğrulanmadı, sadece decode edildi - secret olmadan imza sahteleştirilemez)"
        )
        return pretty
    except Exception:
        return None


# ---------------------------------------------------------------- Klasik sifreler

def caesar_shift(s: str, shift: int) -> str:
    out = []
    for c in s:
        if c in string.ascii_uppercase:
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
        elif c in string.ascii_lowercase:
            out.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)


def try_rot13(s: str):
    return codecs.encode(s, "rot13")


def try_rot47(s: str):
    out = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            out.append(c)
    return "".join(out)


def try_rot5(s: str):
    """Sadece rakamlari 5 kaydirir (harfler aynen kalir)."""
    if not any(c.isdigit() for c in s):
        return None
    out = []
    for c in s:
        if c.isdigit():
            out.append(str((int(c) + 5) % 10))
        else:
            out.append(c)
    return "".join(out)


def try_rot18(s: str):
    """ROT13 (harfler) + ROT5 (rakamlar) birlikte."""
    rotated_letters = try_rot13(s)
    out = []
    for c in rotated_letters:
        if c.isdigit():
            out.append(str((int(c) + 5) % 10))
        else:
            out.append(c)
    return "".join(out)


def try_atbash(s: str):
    out = []
    for c in s:
        if c in string.ascii_uppercase:
            out.append(chr(90 - (ord(c) - 65)))
        elif c in string.ascii_lowercase:
            out.append(chr(122 - (ord(c) - 97)))
        else:
            out.append(c)
    return "".join(out)


_MORSE_TABLE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9',
}


def try_morse(s: str):
    s2 = s.strip()
    if not s2 or not re.fullmatch(r"[.\-\s/]+", s2):
        return None
    words = re.split(r"\s*/\s*|\s{2,}", s2)
    result_words = []
    for w in words:
        letters = w.strip().split()
        decoded = "".join(_MORSE_TABLE.get(l, "?") for l in letters if l)
        if decoded:
            result_words.append(decoded)
    out = " ".join(result_words)
    return out if out and "?" not in out else (out if out else None)


def try_reverse(s: str):
    return s[::-1]


def try_bacon(s: str):
    s2 = re.sub(r"[^ABab]", "", s.strip())
    if len(s2) < 5 or len(s2) % 5 != 0:
        return None
    alphabet = "ABCDEFGHIKLMNOPQRSTUWXYZ"  # klasik 24 harfli Bacon
    table = {}
    for i, ch in enumerate(alphabet):
        code = format(i, "05b").replace("0", "A").replace("1", "B")
        table[code] = ch
    out = []
    for i in range(0, len(s2), 5):
        chunk = s2[i:i+5].upper()
        out.append(table.get(chunk, "?"))
    result = "".join(out)
    return result if "?" not in result else None


# ---------------------------------------------------------------- Polybius square

_POLYBIUS_TABLE = {
    "11": "A", "12": "B", "13": "C", "14": "D", "15": "E",
    "21": "F", "22": "G", "23": "H", "24": "I", "25": "K",  # I/J birlesik
    "31": "L", "32": "M", "33": "N", "34": "O", "35": "P",
    "41": "Q", "42": "R", "43": "S", "44": "T", "45": "U",
    "51": "V", "52": "W", "53": "X", "54": "Y", "55": "Z",
}


def try_polybius(s: str):
    """5x5 Polybius square: her harf 2 rakamli (satir,sutun 1-5) koda karsilik gelir."""
    s2 = re.sub(r"[\s,\-]", "", s.strip())
    if not s2 or len(s2) % 2 != 0 or not re.fullmatch(r"[1-5]+", s2):
        return None
    if len(s2) < 6:
        return None
    out = []
    for i in range(0, len(s2), 2):
        pair = s2[i:i+2]
        out.append(_POLYBIUS_TABLE.get(pair, "?"))
    result = "".join(out)
    return result if "?" not in result else None


# ---------------------------------------------------------------- Base45 / Base36

_BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def try_base45_bytes(s: str):
    """RFC 9285 Base45 (QR kod / EU COVID sertifikalarinda kullanilir)."""
    s2 = s.strip().replace(" ", "")
    if not s2 or len(s2) < 2 or not all(c in _BASE45_ALPHABET for c in s2.upper()):
        return None
    s2 = s2.upper()
    try:
        out = bytearray()
        i = 0
        n = len(s2)
        while i < n:
            if n - i >= 3:
                c, d, e = s2[i], s2[i+1], s2[i+2]
                x = (_BASE45_ALPHABET.index(c) + _BASE45_ALPHABET.index(d) * 45
                     + _BASE45_ALPHABET.index(e) * 45 * 45)
                if x > 65535:
                    return None
                out.append(x // 256)
                out.append(x % 256)
                i += 3
            elif n - i == 2:
                c, d = s2[i], s2[i+1]
                x = _BASE45_ALPHABET.index(c) + _BASE45_ALPHABET.index(d) * 45
                if x > 255:
                    return None
                out.append(x)
                i += 2
            else:
                return None
        return bytes(out)
    except Exception:
        return None


def try_base45(s: str):
    raw = try_base45_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


def try_base36_bytes(s: str):
    """Base36 (0-9, A-Z) - buyuk sayilarin kompakt gosterimi icin kullanilir."""
    s2 = s.strip()
    if not s2 or len(s2) < 3 or not re.fullmatch(r"[0-9A-Za-z]+", s2):
        return None
    if s2.isdigit():
        return None  # sadece rakamsa decimal ile karisir, base36 olarak zorlama
    try:
        num = int(s2, 36)
        if num == 0:
            return None
        raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
        return raw
    except Exception:
        return None


def try_base36(s: str):
    raw = try_base36_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


# ---------------------------------------------------------------- Brute-force gerektiren klasik sifreler
# Bunlar engine.py tarafinda ayri ele alinir (en iyi parametreyi bulup tek aday dondururler)
# cunku anahtar uzayi buyuk / dinamik etiket gerektiriyor.

def affine_decrypt(s: str, a: int, b: int) -> str:
    try:
        a_inv = pow(a, -1, 26)
    except ValueError:
        return s
    out = []
    for c in s:
        if c in string.ascii_uppercase:
            y = ord(c) - 65
            out.append(chr((a_inv * (y - b)) % 26 + 65))
        elif c in string.ascii_lowercase:
            y = ord(c) - 97
            out.append(chr((a_inv * (y - b)) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)


_AFFINE_VALID_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


def try_all_affine(s: str):
    """Tum gecerli (a,b) kombinasyonlarini dener, ((a,b), sonuc) listesi dondurur."""
    results = []
    for a in _AFFINE_VALID_A:
        for b in range(26):
            results.append(((a, b), affine_decrypt(s, a, b)))
    return results


def rail_fence_decrypt(s: str, rails: int) -> str:
    if rails < 2 or rails >= len(s):
        return s
    fence = [[] for _ in range(rails)]
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    idx_cycle = [pattern[i % len(pattern)] for i in range(len(s))]
    for i, row in enumerate(idx_cycle):
        fence[row].append(i)
    order = [i for row in fence for i in row]
    result = [""] * len(s)
    for pos, ch in zip(order, s):
        result[pos] = ch
    return "".join(result)


def try_all_rail_fence(s: str, max_rails: int = 8):
    results = []
    for rails in range(2, max_rails + 1):
        results.append((rails, rail_fence_decrypt(s, rails)))
    return results


# ---------------------------------------------------------------- Kayit defteri

BYTES_DECODERS = [
    ("Base64", try_base64_bytes),
    ("Base64 (URL-safe)", try_base64_urlsafe_bytes),
    ("Base32", try_base32_bytes),
    ("Base85/Ascii85", try_base85_bytes),
    ("Base58", try_base58_bytes),
    ("Base91", try_base91_bytes),
    ("Base45", try_base45_bytes),
    ("Base36", try_base36_bytes),
]

SINGLE_SHOT_DECODERS = [
    ("Base64", try_base64, "encoding"),
    ("Base64 (URL-safe)", try_base64_urlsafe, "encoding"),
    ("Base32", try_base32, "encoding"),
    ("Base85/Ascii85", try_base85, "encoding"),
    ("Base58", try_base58, "encoding"),
    ("Base91", try_base91, "encoding"),
    ("Base45", try_base45, "encoding"),
    ("Base36", try_base36, "encoding"),
    ("Hex (Base16)", try_hex, "encoding"),
    ("Binary (8-bit)", try_binary, "encoding"),
    ("Octal", try_octal, "encoding"),
    ("Decimal (ASCII codes)", try_decimal, "encoding"),
    ("URL Encoding", try_url_decode, "encoding"),
    ("HTML Entities", try_html_entities, "encoding"),
    ("Unicode/Hex Escape (\\u, \\x)", try_unicode_escape, "encoding"),
    ("Quoted-Printable", try_quoted_printable, "encoding"),
    ("JWT", try_jwt, "encoding"),
    ("Polybius Square (5x5)", try_polybius, "cipher"),
    ("ROT13", try_rot13, "cipher"),
    ("ROT47", try_rot47, "cipher"),
    ("ROT5 (rakamlar)", try_rot5, "cipher"),
    ("ROT18 (ROT13+ROT5)", try_rot18, "cipher"),
    ("Atbash", try_atbash, "cipher"),
    ("Morse Code", try_morse, "cipher"),
    ("Bacon Cipher", try_bacon, "cipher"),
    ("Ters çevirme (reverse)", try_reverse, "cipher"),
]


def try_all_caesar(s: str):
    """25 shift'in hepsini dener, (shift, sonuc) listesi dondurur."""
    results = []
    for shift in range(1, 26):
        results.append((shift, caesar_shift(s, shift)))
    return results
