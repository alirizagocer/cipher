import argparse
import json
import sys
import html

from . import __version__
from .charset import analyze_charset
from .engine import explore
from .hashid import identify_hash


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"
MAGENTA = "\033[35m"


def color(txt, c, use_color):
    return f"{c}{txt}{RESET}" if use_color else txt


def score_bar(score: float, width: int = 20) -> str:
    filled = int(round(score / 100 * width))
    return "█" * filled + "░" * (width - filled)


def truncate(s: str, n: int = 100) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "..."


def main():
    parser = argparse.ArgumentParser(
        prog="identify",
        description="Bilinmeyen encode/cipher edilmiş metni analiz eder, olası çözüm adaylarını skorlayıp sıralar.",
    )
    parser.add_argument("--version", action="version", version=f"identify {__version__}")
    parser.add_argument("text", nargs="?", help="Analiz edilecek metin. Verilmezse stdin'den okunur.")
    parser.add_argument("-f", "--file", help="Metni dosyadan oku")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maksimum decode zinciri derinliği (varsayılan: 3)")
    parser.add_argument("-n", "--top", type=int, default=10, help="Gösterilecek maksimum aday sayısı (varsayılan: 10)")
    parser.add_argument("--no-color", action="store_true", help="Renkli çıktıyı kapat")
    parser.add_argument("--full", action="store_true", help="Decode edilmiş metni kısaltmadan tam göster")
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON olarak yazdır (scripting için)")
    parser.add_argument("--html", action="store_true", help="Sonuçları HTML formatında yazdırır.")
    parser.add_argument(
        "--crib",
        metavar="METIN",
        help=(
            "Crib-dragging saldirisi icin bilinen parca. Girdi XOR/Vigenere ile "
            "sifreliyse ve icinde bu parcayi biliyorsan anahtari buradan turetmeyi dener."
        ),
    )
    parser.add_argument(
        "--context",
        choices=["ctf", "windows", "linux", "web", "pentest"],
        default=None,
        help=(
            "Domain-spesifik analiz bağlamı. Hash güven puanlarını ve ipuçlarını "
            "bu bağlama göre ayarlar. Seçenekler: "
            "ctf (tüm klasik şifreler önce), "
            "windows (NTLM/Kerberos/AD formatları), "
            "linux (sha512crypt/md5crypt/shadow dosyası), "
            "web (JWT/API key/session token), "
            "pentest (AD saldırı formatları, Kerberoasting vb.)."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Detaylı çıktı: her aday için skor bileşenlerini ve karar gerekçesini göster.",
    )
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    elif args.text:
        raw = args.text
    else:
        if sys.stdin.isatty():
            parser.print_help()
            sys.exit(1)
        raw = sys.stdin.read()

    raw = raw.strip()
    if not raw:
        print("Boş girdi.", file=sys.stderr)
        sys.exit(1)

    use_color = not args.no_color and sys.stdout.isatty()

    # Context-aware ipucu notları
    context_hints = []
    if args.context:
        ctx_map = {
            "ctf": [
                "CTF BAGLAMI: Klasik sifrelere ve encoding zincirine oncelik verildi.",
                "CTF'lerde yaygin: Base64, ROT13, XOR, Caesar, Vigenere, Morse, Bacon, A1Z26.",
                "CTF flag formati: flag{...}, CTF{...}, picoCTF{...} gibi kaliplara dikkat.",
            ],
            "windows": [
                "WINDOWS BAGLAMI: NTLM, Net-NTLMv2, Kerberos hash formatlari oncelikli.",
                "32-hex -> NTLM ihtimali yuksek (MD5 ile ayirt edilemez ama Windows ortaminda NTLM cok daha yaygin).",
                "Kerberoasting/AS-REP roasting formatlari: $krb5tgs$23$, $krb5asrep$23$ prefix'ine bak.",
                "MsCacheV2: $DCC2$ prefix. DPAPI blob: base64 + yuksek entropi.",
            ],
            "linux": [
                "LINUX BAGLAMI: /etc/shadow formatlari oncelikli.",
                "Modern Linux: $6$ (sha512crypt) veya $y$ (yescrypt). Eski: $1$ (md5crypt).",
                "40-hex SHA1 yerine ssh fingerprint olabilir (ssh-keygen -l).",
            ],
            "web": [
                "WEB BAGLAMI: JWT, API key, session token, OAuth token oncelikli.",
                "3 kisim nokta ayirimli + eyJ basli -> JWT (JSON Web Token).",
                "ghp_, AKIA, AIza, sk_live_, xoxb- gibi prefix'li string'ler API key adayi.",
                "Bearer/Basic auth header: Authorization: Bearer <token>.",
            ],
            "pentest": [
                "PENTEST BAGLAMI: AD saldiri formatlari, credential dump, pass-the-hash.",
                "LM:NTLM cift (32hex:32hex) -> SAM/secretsdump.py ciktisi.",
                "Kerberoasting: $krb5tgs$23$ | AS-REP: $krb5asrep$23$ (hashcat/john dogrudan calisir).",
                "NetNTLMv2: username::domain:challenge:hash formati.",
                "MsCacheV2 (domain cached credentials): $DCC2$10240#user#hash.",
            ],
        }
        context_hints = ctx_map.get(args.context, [])

    charset_notes = analyze_charset(raw)
    candidates = explore(raw, max_depth=args.depth, top_n=args.top)

    # Hash tespitini ayrı yapılandırılmış formda al (JSON şeması için)
    hash_candidates_raw = identify_hash(raw.strip())

    # Crib-dragging (varsa)
    crib_results = []
    if args.crib:
        crib = args.crib
        import binascii as _bi
        from .engine import _bytes_from_text_guess
        from .cribdrag import xor_crib_drag, vigenere_crib_drag

        # XOR crib drag
        data = _bytes_from_text_guess(raw)
        if data:
            try:
                xor_hits = xor_crib_drag(data, crib.encode("utf-8", errors="replace"), top_n=3)
                for pos, key, pt, fitness in xor_hits:
                    try:
                        key_display = key.decode("ascii") if key.isascii() else key.hex()
                    except Exception:
                        key_display = key.hex()
                    crib_results.append({
                        "type": "XOR",
                        "crib_position": pos,
                        "key_guess": key_display,
                        "plaintext": pt,
                        "fitness": round(fitness, 2),
                    })
            except Exception:
                pass

        # Vigenère crib drag
        try:
            vig_hits = vigenere_crib_drag(raw, crib, top_n=3)
            for pos, key, pt, fitness in vig_hits:
                crib_results.append({
                    "type": "Vigenère",
                    "crib_position_alpha": pos,
                    "key_guess": key,
                    "plaintext": pt,
                    "fitness": round(fitness, 2),
                })
        except Exception:
            pass

    if args.json:
        payload = {
            "charset_notes": charset_notes,
            "hash_candidates": [
                {
                    "name": c.name,
                    "confidence": c.confidence,
                    "certain": c.certain,
                    "note": c.note,
                    "example_context": c.example_context,
                }
                for c in hash_candidates_raw
            ],
            "candidates": [
                {"rank": i + 1, "chain": c.chain, "text": c.text, "score": c.score, "kind": c.kind}
                for i, c in enumerate(candidates)
            ],
        }
        if crib_results:
            payload["crib_drag_results"] = crib_results
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    if args.html:
            print("<html><head><meta charset='utf-8'></head><body>")
            print("<h2>Karakter Seti Notları</h2><ul>")
            
            for note in charset_notes:
                # Notların içindeki olası tehlikeli karakterleri temizle
                safe_note = html.escape(note)
                print(f"<li>{safe_note}</li>")
                
            print("</ul><h2>Adaylar</h2><table border='1'>")
            print("<tr><th>Sıra</th><th>Zincir</th><th>Metin</th><th>Skor</th><th>Tür</th></tr>")
            
            for i, c in enumerate(candidates):
                # Zinciri list formundan metin formuna çevir (hex -> base64)
                chain_str = " -> ".join(c.chain) if c.chain else "(orijinal)"
                
                # Çözülen metnin içindeki HTML taglarını zararsız hale getir
                safe_text = html.escape(c.text)
                
                print(f"<tr><td>{i+1}</td><td>{chain_str}</td><td>{safe_text}</td><td>{c.score}</td><td>{c.kind}</td></tr>")
                
            print("</table></body></html>")
            return

    print(color("=== Karakter Seti Analizi ===", BOLD + CYAN, use_color))
    for note in charset_notes:
        print(f"  - {note}")

    # Context ipuçları (varsa)
    if context_hints:
        print()
        ctx_label = (args.context or "").upper()
        print(color(f"=== Context: [{ctx_label}] Analiz Ipuclari ===", BOLD + YELLOW, use_color))
        for hint in context_hints:
            print(f"  {color('>', YELLOW, use_color)} {hint}")

    # Crib-dragging sonuçları (varsa)
    if crib_results:
        print()
        print(color(f"=== Crib-Dragging Sonuçları (crib: '{args.crib}') ===", BOLD + MAGENTA, use_color))
        for i, r in enumerate(crib_results, 1):
            cipher_type = r["type"]
            key = r.get("key_guess", "?")
            fit = r.get("fitness", 0)
            pos = r.get("crib_position") or r.get("crib_position_alpha", "?")
            pt = r.get("plaintext", "")
            print(f"  #{i} [{cipher_type}] pozisyon={pos}  anahtar-tahmini={key!r}  fitness={fit:.1f}")
            print(f"       {truncate(pt, 120)}")
        print()

    print()
    print(color("=== Otomatik Decode Denemeleri (skora göre sıralı) ===", BOLD + CYAN, use_color))

    if not candidates:
        print(color("Hiçbir decode denemesi sonuç üretmedi.", RED, use_color))
        return

    for i, c in enumerate(candidates, 1):
        score = c.score
        if c.kind == "file":
            sc_color = MAGENTA
        elif score >= 65:
            sc_color = GREEN
        elif score >= 35:
            sc_color = YELLOW
        else:
            sc_color = DIM

        chain_str = " -> ".join(c.chain) if c.chain else "(orijinal)"
        text_preview = c.text if args.full else truncate(c.text, 140)

        print(f"{color(f'#{i}', BOLD, use_color)} "
              f"[{color(f'{score:5.1f}', sc_color, use_color)}] "
              f"{color(score_bar(score), sc_color, use_color)}"
              f"{color('  [DOSYA]', MAGENTA, use_color) if c.kind == 'file' else ''}")
        print(f"    {color('Zincir:', DIM, use_color)} {chain_str}")
        print(f"    {color('Çıktı :', DIM, use_color)} {text_preview}")
        print()

    print(color("İpucu: en yüksek skorlu satır çoğunlukla doğru çözümdür. "
                 "Skor 35'in altındaysa muhtemelen yanlış yoldasın ya da veri gerçek "
                 "şifreleme (AES/RSA/XOR w/ key) ile korunuyor. --json ile scripting için "
                 "makine-okunabilir çıktı alabilirsin. --crib 'bilinen_metin' ile "
                 "crib-dragging saldırısı deneyebilirsin.", DIM, use_color))


if __name__ == "__main__":
    main()
