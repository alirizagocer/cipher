import argparse
import json
import sys
import html

from . import __version__
from .charset import analyze_charset
from .engine import explore


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
    charset_notes = analyze_charset(raw)
    candidates = explore(raw, max_depth=args.depth, top_n=args.top)

    if args.json:
        payload = {
            "charset_notes": charset_notes,
            "candidates": [
                {"rank": i + 1, "chain": c.chain, "text": c.text, "score": c.score, "kind": c.kind}
                for i, c in enumerate(candidates)
            ],
        }
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
                 "makine-okunabilir çıktı alabilirsin.", DIM, use_color))


if __name__ == "__main__":
    main()
