"""
Decode edilen veri metin degil de bir dosya mi (PNG, ZIP, PDF, ELF...) tespit eder.
CyberChef'in "Detect File Type" ozelliginin offline karsiligi.
"""

_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image (87a)"),
    (b"GIF89a", "GIF image (89a)"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (docx/xlsx/pptx/jar da olabilir)"),
    (b"PK\x05\x06", "ZIP archive (boş)"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07\x00", "RAR archive (v4)"),
    (b"Rar!\x1a\x07\x01\x00", "RAR archive (v5)"),
    (b"\x7fELF", "ELF executable/binary"),
    (b"MZ", "Windows PE executable (.exe/.dll)"),
    (b"\xca\xfe\xba\xbe", "Java class dosyası (veya Mach-O fat binary)"),
    (b"SQLite format 3\x00", "SQLite veritabanı"),
    (b"ID3", "MP3 (ID3 etiketli)"),
    (b"\x00\x00\x00\x18ftyp", "MP4 video"),
    (b"OggS", "OGG media"),
    (b"%!PS", "PostScript belgesi"),
    (b"\x25\x21", "PostScript (kısa imza)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Eski MS Office (.doc/.xls/.ppt)"),
]


def detect_file_signature(raw: bytes):
    """Eslesirse (dosya_turu_adi, guven) tuple'i, eslesmezse None doner."""
    if not raw or len(raw) < 2:
        return None
    for sig, name in _SIGNATURES:
        if raw.startswith(sig):
            return name
    # RIFF/WAV/AVI ozel durum: ilk 4 byte RIFF, 8-12 arasi tip
    if raw[:4] == b"RIFF" and len(raw) >= 12:
        subtype = raw[8:12]
        if subtype == b"WAVE":
            return "WAV audio"
        if subtype == b"AVI ":
            return "AVI video"
        return "RIFF container"
    return None
