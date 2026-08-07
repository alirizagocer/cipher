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


# ---------------------------------------------------------------- A1Z26 (harf-sayi kodu)

def try_a1z26(s: str):
    """A1Z26: A=1, B=2, ..., Z=26. Genelde '-' veya bosluk ile ayrilmis sayilar
    olarak yazilir (orn. '8-5-12-12-15' -> 'HELLO'). CTF'lerde cok yaygin,
    basit ama tanimasi kolay bir kod."""
    s2 = s.strip()
    if not s2:
        return None
    for sep in ["-", ",", " ", "."]:
        if sep in s2:
            parts = [p for p in s2.split(sep) if p != ""]
            break
    else:
        return None  # ayiraci yoksa (orn "812") hangi sayinin nerede bittigi belirsiz, deneme
    if len(parts) < 3:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if not all(1 <= n <= 26 for n in nums):
        return None
    return "".join(chr(64 + n) for n in nums)


# ---------------------------------------------------------------- NATO fonetik alfabesi

_NATO_MAP = {
    "ALPHA": "A", "BRAVO": "B", "CHARLIE": "C", "DELTA": "D", "ECHO": "E",
    "FOXTROT": "F", "GOLF": "G", "HOTEL": "H", "INDIA": "I", "JULIET": "J",
    "JULIETT": "J", "KILO": "K", "LIMA": "L", "MIKE": "M", "NOVEMBER": "N",
    "OSCAR": "O", "PAPA": "P", "QUEBEC": "Q", "ROMEO": "R", "SIERRA": "S",
    "TANGO": "T", "UNIFORM": "U", "VICTOR": "V", "WHISKEY": "W", "XRAY": "X",
    "X-RAY": "X", "YANKEE": "Y", "ZULU": "Z",
}


def try_nato_phonetic(s: str):
    words = re.split(r"[\s,\-]+", s.strip().upper())
    words = [w for w in words if w]
    if len(words) < 3:
        return None
    out = []
    for w in words:
        if w not in _NATO_MAP:
            return None
        out.append(_NATO_MAP[w])
    return "".join(out)


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


# ---------------------------------------------------------------- uuencode

def try_uuencode_bytes(s: str):
    """Unix uuencode decode. Iki format desteklenir:
    1) Klasik: 'begin <mode> <filename>' / '...satırlar...' / 'end' blogu
    2) Satır-bazli: her satir 'M' ile baslayan [32-95] aralik karakterler (header yok)
       Bu ikinci format bazi CTF/pentest araclari tarafindan ham cikti olarak kullanilir."""
    import binascii as _bi
    s2 = s.strip()
    if not s2:
        return None
    # Format 1: tam blok (begin...end)
    if s2.lower().startswith("begin "):
        try:
            lines = s2.splitlines()
            # 'end' satirini bul
            end_idx = next((i for i, l in enumerate(lines) if l.strip().lower() == "end"), None)
            if end_idx is None:
                return None
            data_lines = lines[1:end_idx]
            out = bytearray()
            for line in data_lines:
                if not line.strip():
                    continue
                decoded = _bi.a2b_uu(line)
                out.extend(decoded)
            return bytes(out) if out else None
        except Exception:
            return None
    # Format 2: satır-bazli (header yok), her satir 'M' ile basliyor
    lines = [l for l in s2.splitlines() if l.strip()]
    if not lines:
        return None
    # Ilk satir 'M' ile baslamali ve sadece printable [32-96] karakterler icermeli
    if not lines[0].startswith('M'):
        return None
    if not all(all(32 <= ord(c) <= 96 for c in l.rstrip()) for l in lines):
        return None
    try:
        import binascii as _bi2
        out = bytearray()
        for line in lines:
            decoded = _bi2.a2b_uu(line)
            out.extend(decoded)
        result = bytes(out)
        return result if result else None
    except Exception:
        return None


def try_uuencode(s: str):
    raw = try_uuencode_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


# ---------------------------------------------------------------- z85 (ZeroMQ Base85)
# RFC standart degil, ama ZeroMQ/CZMQ ve bazi CTF'lerde kullaniliyor.
# Alfabe: 0-9 A-Z a-z !#$%&()*+-;<=>?@^_`{|}~

_Z85_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_Z85_DECODE_MAP = {c: i for i, c in enumerate(_Z85_CHARS)}


def try_z85_bytes(s: str):
    """ZeroMQ z85 decode. 5 karakterlik grup -> 4 byte."""
    s2 = s.strip()
    if not s2 or len(s2) % 5 != 0:
        return None
    if not all(c in _Z85_DECODE_MAP for c in s2):
        return None
    try:
        out = bytearray()
        for i in range(0, len(s2), 5):
            chunk = s2[i:i+5]
            val = 0
            for c in chunk:
                val = val * 85 + _Z85_DECODE_MAP[c]
            if val > 0xFFFFFFFF:
                return None
            out.extend(val.to_bytes(4, 'big'))
        return bytes(out)
    except Exception:
        return None


def try_z85(s: str):
    raw = try_z85_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


# ---------------------------------------------------------------- Base62
# URL kisalticilarda (bit.ly, t.co), UUID alternatiflerinde, API token'larda yaygin.
# Alfabe: 0-9 (10) + A-Z (26) + a-z (26) = 62 karakter.
# Base58'den farki: 0, O, I, l karakterlerini DE icerir.

_BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62_SET = set(_BASE62_CHARS)
_BASE62_MAP = {c: i for i, c in enumerate(_BASE62_CHARS)}


def try_base62_bytes(s: str):
    """Base62 -> bytes. Tum karakterler Base62 alfabesinde olmali (min 2 karakter)."""
    s2 = s.strip()
    if len(s2) < 2:
        return None
    if not all(c in _BASE62_SET for c in s2):
        return None
    # Salt rakam string'leri decimal ile cakisir, redet
    if s2.isdigit():
        return None
    n = 0
    for c in s2:
        n = n * 62 + _BASE62_MAP[c]
    if n == 0:
        return b"\x00"
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    return bytes(reversed(result))


def try_base62(s: str):
    raw = try_base62_bytes(s)
    if raw is None:
        return None
    try:
        decoded = raw.decode("utf-8")
        return decoded if decoded.isprintable() or "\n" in decoded else None
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------- Punycode (ACE / IDNA)
# Uluslararasi domain adlarini ASCII'ye donusturur.
# Phishing tespitinde, SOC analizinde kritik: xn-- prefix'li alan adlari
# goze normal gorunen fakat farkli Unicode karakterler kullanan sahte siteler olabilir.
# Ornek: xn--e1afmapc.xn--p1ai -> kinixud.ru gibi gorunebilir

def try_punycode(s: str):
    """Punycode decode. xn-- prefix icermeli. Hicbir degisiklik olmadiysa None doner."""
    s2 = s.strip()
    if not s2 or "xn--" not in s2.lower():
        return None
    try:
        parts = s2.split(".")
        decoded_parts = []
        changed = False
        for part in parts:
            if part.lower().startswith("xn--"):
                try:
                    decoded = part[4:].encode("ascii").decode("punycode")
                    decoded_parts.append(decoded)
                    changed = True
                except Exception:
                    decoded_parts.append(part)
            else:
                decoded_parts.append(part)
        if not changed:
            return None
        result = ".".join(decoded_parts)
        return result if result != s2 else None
    except Exception:
        return None


# ---------------------------------------------------------------- Zlib / Deflate
# Web protokollerinde (HTTP Content-Encoding), PNG/zip icinde, CTF'lerde yaygin.
# Raw zlib: zlib.decompress() ile. Raw deflate: wbits=-15.

def try_zlib_bytes(s: str):
    """Zlib-compressed veriyi (base64/hex ile encode edilmis olmali) decompress eder.
    Once ham string'i bytes'a cevirmek icin hex veya base64 decode dener."""
    import zlib
    s2 = s.strip()
    if not s2:
        return None
    # Hex decode dene
    try:
        stripped_ws = re.sub(r"\s", "", s2)
        if re.fullmatch(r"[0-9A-Fa-f]+", stripped_ws) and len(stripped_ws) % 2 == 0:
            raw = bytes.fromhex(stripped_ws)
            try:
                return zlib.decompress(raw)
            except zlib.error:
                try:
                    return zlib.decompress(raw, -15)  # raw deflate
                except zlib.error:
                    pass
    except Exception:
        pass
    # Base64 decode dene
    try:
        import base64 as _b64
        raw = _b64.b64decode(s2, validate=False)
        if len(raw) >= 4:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                try:
                    return zlib.decompress(raw, -15)  # raw deflate
                except zlib.error:
                    pass
    except Exception:
        pass
    return None


def try_zlib(s: str):
    raw = try_zlib_bytes(s)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


# ---------------------------------------------------------------- Hex Dump (xxd / hexdump formati)
# xxd, od, hexdump araclari bu formatla cikti uretir.
# Format: "00000000: 4865 6c6c 6f20 576f 726c 64  Hello World"
# Sadece hex kismi alinir, ASCII kismi atlanir.

def _parse_hex_dump_line(line: str):
    """Tek bir xxd satiri: offset:? + hex gruplar + ascii kisim -> bytes veya None."""
    line = line.strip()
    if not line:
        return None
    # Offset kismi varsa kaldir (sayilar + ":" veya boşluk + devam)
    # Olası formatlar: "00000000: 4865 6c6c" veya "0000000 110 145 154" (octal - od)
    if ":" in line:
        line = line.split(":", 1)[1]
    # ASCII kismi kaldir: son bosluk grubundan sonra gelen yazdirilabiir karakterler
    # Heuristic: son iki bosluktan sonra gelen alfanumerik blogu at
    hex_part = re.split(r"  +", line)[0].strip()
    # Hex karakterlerini topla
    hex_chars = re.sub(r"[^0-9A-Fa-f]", "", hex_part)
    if not hex_chars or len(hex_chars) % 2 != 0:
        return None
    try:
        return bytes.fromhex(hex_chars)
    except Exception:
        return None


def try_hex_dump_bytes(s: str):
    """xxd / hexdump / od ciktisini ham byte'lara cevirir."""
    lines = s.strip().splitlines()
    if len(lines) < 1:
        return None
    # Formatı kontrol et: en az bir satir xxd/hexdump gibi görünmeli
    # En az 2 satir veya tek satir ama offset + hex yapısı var
    valid_lines = []
    for line in lines:
        if not line.strip():
            continue
        # xxd formatı: "XXXXXXXX: XX XX XX..."
        if re.match(r"^[0-9a-fA-F]+:\s+[0-9a-fA-F ]+", line.strip()):
            valid_lines.append(line)
        # hexdump -C formatı: "00000000  48 65 6c 6c 6f  |Hello|"
        elif re.match(r"^[0-9a-fA-F]+\s+[0-9a-fA-F]{2}\s+", line.strip()):
            valid_lines.append(line)
    if len(valid_lines) < 1:
        return None
    result = bytearray()
    for line in valid_lines:
        chunk = _parse_hex_dump_line(line)
        if chunk:
            result.extend(chunk)
    return bytes(result) if result else None


def try_hex_dump(s: str):
    raw = try_hex_dump_bytes(s)
    if raw is None:
        return None
    try:
        decoded = raw.decode("utf-8", errors="replace")
        # Anlamsiz veri degilse dondur
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
        if len(decoded) == 0 or printable / len(decoded) < 0.70:
            return None
        return decoded
    except Exception:
        return None


# ---------------------------------------------------------------- Braille Unicode
# 6-nokta Braille: U+2800-U+283F arasi Unicode karakterler.
# 8-nokta genisletilmis Braille: U+2800-U+28FF.
# CTF'lerde ve erisebilirlik arastirmalarinda karsilasilan encoding.

# Grade 1 Braille -> ASCII haritalama (ITA/Amerikan standardi)
_BRAILLE_TO_CHAR = {
    "\u2800": " ",  # bos (bosluk)
    "\u2801": "a",
    "\u2803": "b",
    "\u2809": "c",
    "\u2819": "d",
    "\u2811": "e",
    "\u280b": "f",
    "\u281b": "g",
    "\u2813": "h",
    "\u280a": "i",
    "\u281a": "j",
    "\u2805": "k",
    "\u2807": "l",
    "\u280d": "m",
    "\u281d": "n",
    "\u2815": "o",
    "\u280f": "p",
    "\u281f": "q",
    "\u2817": "r",
    "\u280e": "s",
    "\u281e": "t",
    "\u2825": "u",
    "\u2827": "v",
    "\u283a": "w",
    "\u282d": "x",
    "\u283d": "y",
    "\u2835": "z",
    "\u2830": "0",
    "\u2802": "1",
    "\u2806": "2",
    "\u2812": "3",
    "\u2832": "4",
    "\u2822": "5",
    "\u2816": "6",
    "\u2836": "7",
    "\u2826": "8",
    "\u2834": "9",
    "\u2820": "",  # number indicator (sayı başlatıcı, atlanır)
    "\u2840": "",  # capital indicator (büyük harf başlatıcı, atlanır)
    "\u2804": ",",
    "\u2814": ";",
    "\u2828": ":",
    "\u2832": "!",  # override edilebilir
    "\u2818": ".",
    "\u2838": "?",
    "\u2824": "-",
    "\u2810": "\"",
    "\u2823": "(",
    "\u281c": ")",
}

_BRAILLE_RANGE = ("\u2800", "\u28ff")


def try_braille(s: str):
    """Unicode Braille karakterlerini ASCII metne decode eder.
    Girdinin en az %50'si Braille karakteri olmali."""
    s2 = s.strip()
    if not s2:
        return None
    braille_chars = [c for c in s2 if "\u2800" <= c <= "\u28ff"]
    if len(braille_chars) < 3:
        return None
    if len(braille_chars) / len(s2) < 0.50:
        return None  # kotu oran, gercek Braille degil
    result = []
    for c in s2:
        if "\u2800" <= c <= "\u28ff":
            mapped = _BRAILLE_TO_CHAR.get(c, "?")
            result.append(mapped)
        elif c in (" ", "\n", "\t"):
            result.append(c)
        # diger karakterleri atla
    decoded = "".join(result).strip()
    if not decoded or all(c in "? " for c in decoded):
        return None
    return decoded

# ---------------------------------------------------------------- yEnc (Usenet binary encoding)
# Newsgroup'larda binary dosyalari text olarak dagitmak icin kullanilir.
# Format: her byte'a 42 eklenir (mod 256); "=" escape karakteri sonrasinda
# byte XOR 64 yapilip 42 eklenir. Baslik: "=ybegin", bitis: "=yend".
# CTF'lerde ve eski newsgroup arsivlerinde karsilasilan bir encoding.

def try_yenc_bytes(s: str):
    """yEnc decode. =ybegin baslik satiri zorunlu. =yend opsiyonel.
    Bos veya baslik icermeyen girdilerde None doner."""
    s2 = s.strip()
    if not s2 or "=ybegin" not in s2.lower():
        return None
    lines = s2.splitlines()
    begin_idx = None
    end_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if stripped.startswith("=ybegin"):
            begin_idx = i
        elif stripped.startswith("=yend"):
            end_idx = i
            break
    if begin_idx is None:
        return None
    data_start = begin_idx + 1
    # =ypart satiri varsa atla
    if data_start < len(lines) and lines[data_start].strip().lower().startswith("=ypart"):
        data_start += 1
    data_end = end_idx if end_idx is not None else len(lines)
    if data_start >= data_end:
        return None
    out = bytearray()
    for line in lines[data_start:data_end]:
        i = 0
        while i < len(line):
            c = line[i]
            if c == "=":
                i += 1
                if i < len(line):
                    # Escaped byte: (ord(c) - 64 - 42) mod 256
                    # = sonraki karakterin degerini 64 ile XOR et, sonra 42 cikar
                    b = (ord(line[i]) - 64 - 42) % 256
                    out.append(b)
            else:
                b = (ord(c) - 42) % 256
                out.append(b)
            i += 1
    return bytes(out) if out else None


def try_yenc(s: str):
    raw = try_yenc_bytes(s)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


# ---------------------------------------------------------------- Baudot / ITA2 (5-bit teleprinter kodu)
# ITA2 (International Telegraph Alphabet No. 2) = modern Baudot standardi.
# Her karakter 5 bit (0-31 arasi). Iki "shift" durumu: LETTERS ve FIGURES.
# 11011 = FIGS shift, 11111 = LTRS shift.
# Giris formatlari: (1) boslukla ayrili 5'li binary gruplar "00001 10100 ..."
#                   (2) boslukla ayrili decimal degerler "1 20 ..."
#                   (3) bosluksuz 5'in kati binary string "0000110100..."
# CTF'lerde ve tarihi metin kodlamalarinda gorulebilir.

# ITA2 Letters shift tablosu (kod -> harf)
_ITA2_LETTERS = {
    0x00: "\0", 0x01: "E",  0x02: "\n", 0x03: "A",  0x04: " ",  0x05: "S",
    0x06: "I",  0x07: "U",  0x08: "\r", 0x09: "D",  0x0A: "R",  0x0B: "J",
    0x0C: "N",  0x0D: "F",  0x0E: "C",  0x0F: "K",  0x10: "T",  0x11: "Z",
    0x12: "L",  0x13: "W",  0x14: "H",  0x15: "Y",  0x16: "P",  0x17: "Q",
    0x18: "O",  0x19: "B",  0x1A: "G",  0x1B: None,  # FIGS
    0x1C: "M",  0x1D: "X",  0x1E: "V",  0x1F: None,  # LTRS
}

# ITA2 Figures shift tablosu
_ITA2_FIGURES = {
    0x00: "\0", 0x01: "3",  0x02: "\n", 0x03: "-",  0x04: " ",  0x05: "'",
    0x06: "8",  0x07: "7",  0x08: "\r", 0x09: "\x05", 0x0A: "4",  0x0B: "\a",
    0x0C: ",",  0x0D: "!",  0x0E: ":",  0x0F: "(",  0x10: "5",  0x11: "\"",
    0x12: ")",  0x13: "2",  0x14: "#",  0x15: "6",  0x16: "0",  0x17: "1",
    0x18: "9",  0x19: "?",  0x1A: "&",  0x1B: None,  # FIGS (no-op)
    0x1C: ".",  0x1D: "/",  0x1E: ";",  0x1F: None,  # LTRS
}

_FIGS_CODE = 0x1B
_LTRS_CODE = 0x1F


def _baudot_decode_codes(codes: list) -> str:
    """ITA2 kod listesini (0-31 arasi tamsayilar) decode eder."""
    out = []
    in_figures = False
    for code in codes:
        if code == _FIGS_CODE:
            in_figures = True
            continue
        if code == _LTRS_CODE:
            in_figures = False
            continue
        table = _ITA2_FIGURES if in_figures else _ITA2_LETTERS
        ch = table.get(code)
        if ch is None:
            continue  # gecersiz/kontrol karakteri
        if ch == "\0" or ch == "\r":
            continue  # NUL ve CR'yi atla
        out.append(ch)
    return "".join(out)


def try_baudot(s: str):
    """ITA2/Baudot decode. 3 format desteklenir:
    1) Boslukla ayrili 5-bitlik binary gruplar: '00001 00011 ...'
    2) Bosluksuz 5'in kati binary string: '0000100011...'
    3) Boslukla ayrili decimal degerler (0-31 arasi): '1 3 5 ...'
    En az 3 gecerli karakter uretilmezse None doner."""
    s2 = s.strip()
    if not s2:
        return None

    codes = []

    # Format 1: boslukla ayrili 5-bitlik binary gruplar
    parts = s2.split()
    if parts and all(re.fullmatch(r"[01]{5}", p) for p in parts) and len(parts) >= 3:
        codes = [int(p, 2) for p in parts]

    # Format 2: bosluksuz binary (5'in kati uzunluk)
    elif re.fullmatch(r"[01]+", s2) and len(s2) % 5 == 0 and len(s2) >= 15:
        codes = [int(s2[i:i+5], 2) for i in range(0, len(s2), 5)]

    # Format 3: decimal degerler (0-31 arasi)
    elif parts and all(re.fullmatch(r"\d{1,2}", p) for p in parts) and len(parts) >= 3:
        try:
            vals = [int(p) for p in parts]
            if all(0 <= v <= 31 for v in vals):
                codes = vals
        except ValueError:
            return None
    else:
        return None

    if not codes:
        return None

    result = _baudot_decode_codes(codes)
    # En az 3 anlamli karakter olmali (NUL/kontrol haric)
    meaningful = [c for c in result if c.strip() or c in (" ",)]
    if len(meaningful) < 3:
        return None
    return result.strip() if result.strip() else None


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
    ("Base62", try_base62_bytes),
    ("uuencode", try_uuencode_bytes),
    ("z85 (ZeroMQ)", try_z85_bytes),
    ("yEnc", try_yenc_bytes),
    ("Zlib/Deflate", try_zlib_bytes),
    ("Hex Dump (xxd/hexdump)", try_hex_dump_bytes),
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
    ("Base62", try_base62, "encoding"),
    ("uuencode", try_uuencode, "encoding"),
    ("z85 (ZeroMQ)", try_z85, "encoding"),
    ("yEnc", try_yenc, "encoding"),
    ("Baudot/ITA2 (5-bit)", try_baudot, "encoding"),
    ("Zlib/Deflate", try_zlib, "encoding"),
    ("Hex Dump (xxd/hexdump)", try_hex_dump, "encoding"),
    ("Punycode (IDNA/ACE)", try_punycode, "encoding"),
    ("Braille (Unicode Grade 1)", try_braille, "encoding"),
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
    ("A1Z26 (harf-sayı kodu)", try_a1z26, "cipher"),
    ("NATO Fonetik Alfabesi", try_nato_phonetic, "cipher"),
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
