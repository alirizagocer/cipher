"""
Decode edilen veri metin degil de bir dosya mi (PNG, ZIP, PDF, ELF...) tespit eder.
CyberChef'in "Detect File Type" ozelliginin offline karsiligi.
"""

_SIGNATURES = [
    # ----- Görseller -----
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image (87a)"),
    (b"GIF89a", "GIF image (89a)"),
    (b"RIFF", None),           # özel: alt-tip WAVE/WEBP/AVI ayrı kontrol edilecek
    (b"BM", "BMP image"),
    (b"\x00\x00\x01\x00", "ICO icon file"),
    (b"\x00\x00\x02\x00", "CUR cursor file"),
    (b"II\x2a\x00", "TIFF image (little-endian)"),
    (b"MM\x00\x2a", "TIFF image (big-endian)"),
    (b"8BPS", "Adobe Photoshop PSD"),
    (b"\x00\x00\x00\x0cjP  ", "JPEG 2000 image"),
    (b"\xff\x4f\xff\x51", "JPEG 2000 codestream"),

    # ----- Belgeler -----
    (b"%PDF-", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Eski MS Office (.doc/.xls/.ppt) - OLE2"),
    (b"%!PS", "PostScript belgesi"),
    (b"\x1b%-12345X@PJL", "PCL printer language"),

    # ----- Arşivler -----
    (b"PK\x03\x04", "ZIP archive (docx/xlsx/pptx/jar/apk da olabilir)"),
    (b"PK\x05\x06", "ZIP archive (bos)"),
    (b"PK\x07\x08", "ZIP archive (spanned)"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07\x00", "RAR archive (v4)"),
    (b"Rar!\x1a\x07\x01\x00", "RAR archive (v5)"),
    (b"\xfd7zXZ\x00", "XZ archive"),
    (b"\x28\xb5\x2f\xfd", "Zstandard (zstd) archive"),
    (b"\x5d\x00\x00\x00", "LZMA archive"),
    (b"\x1f\x9d", "LZW compressed (.Z)"),
    (b"MSCF", "Microsoft Cabinet (.cab)"),
    (b"\xd0\xcf\x11\xe0", "OLE Compound File"),
    # TAR: offset 257'de "ustar" var, ilk baytlardan ayırt edilemez ama yaygın magic
    # ISO 9660: offset 32769'da CD001 -- cok uzun, basit kontrolle zor

    # ----- Çalıştırılabilir / Binary -----
    (b"\x7fELF", "ELF executable/binary (Linux/Unix)"),
    (b"MZ", "Windows PE executable (.exe/.dll/.sys)"),
    (b"\xca\xfe\xba\xbe", "Java class file veya Mach-O fat binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O binary (32-bit, big-endian)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O binary (64-bit, big-endian)"),
    (b"\xce\xfa\xed\xfe", "Mach-O binary (32-bit, little-endian)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary (64-bit, little-endian)"),
    (b"\x00asm", "WebAssembly (wasm) module"),
    (b"dex\n", "Android DEX bytecode"),
    (b"dey\n", "Android ODEX bytecode"),

    # ----- Veritabanları -----
    (b"SQLite format 3\x00", "SQLite veritabani"),
    (b"\x00\x00\x00\x14\x00\x00\x00\x01", "Java KeyStore (JKS)"),

    # ----- Medya -----
    (b"ID3", "MP3 (ID3 etiketli)"),
    (b"\xff\xfb", "MP3 audio (no ID3)"),
    (b"\xff\xf3", "MP3 audio (no ID3, v2.5)"),
    (b"fLaC", "FLAC audio"),
    (b"OggS", "OGG media"),
    (b"\x00\x00\x00\x18ftyp", "MP4/M4A/M4V video"),
    (b"\x00\x00\x00\x14ftyp", "MP4 video (QuickTime/14)"),
    (b"FLV\x01", "Flash Video (.flv)"),
    (b"\x1a\x45\xdf\xa3", "Matroska/WebM video (MKV)"),

    # ----- Diğer -----
    (b"\xef\xbb\xbf", "UTF-8 BOM (Byte Order Mark)"),
    (b"\xff\xfe", "UTF-16 LE BOM"),
    (b"\xfe\xff", "UTF-16 BE BOM"),
    (b"<?xml", "XML document"),
    (b"<!DOCTYPE html", "HTML document"),
    (b"<!doctype html", "HTML document"),
    (b"<html", "HTML document"),
    (b"{\n", None),  # JSON — özel kontrol
    (b'{"', "JSON data"),
    (b"[{", "JSON array data"),
]

# RIFF alt-tip haritası
_RIFF_SUBTYPES = {
    b"WAVE": "WAV audio",
    b"AVI ": "AVI video",
    b"WEBP": "WebP image",
    b"RMID": "MIDI (RIFF wrapped)",
}


def detect_file_signature(raw: bytes):
    """Eslesirse dosya_turu_adi string'i, eslesmezse None doner."""
    if not raw or len(raw) < 2:
        return None

    # RIFF ozel durum: alt-tip 8-12 arasi
    if raw[:4] == b"RIFF" and len(raw) >= 12:
        subtype = raw[8:12]
        return _RIFF_SUBTYPES.get(subtype, "RIFF container")

    for sig, name in _SIGNATURES:
        if name is None:
            continue
        if raw[:len(sig)] == sig:
            return name

    # TAR: offset 257'de "ustar" varsa
    if len(raw) >= 262 and raw[257:262] == b"ustar":
        return "TAR archive"

    # ISO 9660 CD image: offset 32769'da "CD001"
    if len(raw) >= 32774 and raw[32769:32774] == b"CD001":
        return "ISO 9660 CD image"

    return None
