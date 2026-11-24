"""Build the dashboard's two bundled fonts from pinned google/fonts sources.

The dashboard loads no font from elsewhere (CSP font-src 'self'), so it ships subsets of two
variable fonts, both under the SIL Open Font License 1.1: Noto Sans KR for text and JetBrains Mono
for identifiers. Noto Sans KR keeps the 2,350 Hangul syllables of KS X 1001, Latin, the
punctuation and signs the console uses, and every character of the dashboard's templates and of
depbee's own sources, so a message always has its glyphs; anything else (a rare syllable in a
folder name) is drawn by the next font of the stack. JetBrains Mono keeps Latin and those signs:
Hangul in an identifier falls back to the Noto subset. coverage.txt lists the code points of the
Noto subset; tests/test_dashboard_theme.py fails when a new message needs one it lacks.

Needs fontTools and brotli (development only, not a depbee dependency):

    python -m pip install fonttools==4.55.3 brotli==1.1.0
    python scripts/build_dashboard_fonts.py <folder with the four downloaded sources>

Without a folder the sources are downloaded from the pinned commit; either way their SHA-256 is
checked before anything is written.
"""

import argparse
import hashlib
import io
import sys
import urllib.request
from pathlib import Path

from fontTools import subset

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "depbee"
OUT = PACKAGE / "dashboard" / "static" / "fonts"
COMMIT = "06bfe0d62a98375cb09c942fa18e68bd32cff057"  # google/fonts main, 2026-11-20
RAW = f"https://raw.githubusercontent.com/google/fonts/{COMMIT}/ofl"
# source file: (path under ofl/, SHA-256)
SOURCES = {
    "NotoSansKR[wght].ttf": (
        "notosanskr/NotoSansKR%5Bwght%5D.ttf",
        "194018e6b2b293a7964f037b25c0249ce1418bc9ab3c971060a03aa57861e252",
    ),
    "OFL-NotoSansKR.txt": (
        "notosanskr/OFL.txt",
        "1c05c68c34f9708415aada51f17e1b0092d2cea709bf4a94cd38114f9e73d7d9",
    ),
    "JetBrainsMono[wght].ttf": (
        "jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf",
        "48715a42ec242c21e9f02692891e147d022299a52e48d5e413e1a942193ffeda",
    ),
    "OFL-JetBrainsMono.txt": (
        "jetbrainsmono/OFL.txt",
        "b2fe5e8987594e9ffd1d2ca52a2f5d73eb8335243893c5d6254b5ad69269591d",
    ),
}
# Latin, Latin-1, general punctuation, the won and euro signs, arrows, the minus, check and
# cross marks, CJK symbols and the Hangul compatibility jamo.
SIGNS = [
    (0x20, 0x7E), (0xA0, 0xFF), (0x2010, 0x2027), (0x2030, 0x203A), (0x20A9, 0x20A9),
    (0x20AC, 0x20AC), (0x2190, 0x2199), (0x2212, 0x2212), (0x2713, 0x2715), (0x3000, 0x3003),
    (0x3008, 0x3011), (0x3131, 0x318E),
]  # fmt: skip


def ks_x_1001() -> set[int]:
    """The 2,350 Hangul syllables of KS X 1001 (EUC-KR rows 0xB0 to 0xC8)."""
    return {
        ord(bytes([row, cell]).decode("euc-kr"))
        for row in range(0xB0, 0xC9)
        for cell in range(0xA1, 0xFF)
    }


def own_text() -> set[int]:
    """Every character of the dashboard's templates and of depbee's sources above ASCII."""
    paths = [*(PACKAGE / "dashboard" / "templates").glob("*.html"), *PACKAGE.rglob("*.py")]
    return {ord(c) for path in paths for c in path.read_text("utf-8") if ord(c) > 0x7E}


def ranges(points: set[int]) -> list[str]:
    """points as sorted U+XXXX or U+XXXX-U+YYYY lines."""
    lines, ordered = [], sorted(points)
    start = previous = ordered[0]
    for point in [*ordered[1:], None]:
        if point is not None and point == previous + 1:
            previous = point
            continue
        lines.append(f"U+{start:04X}" if start == previous else f"U+{start:04X}-U+{previous:04X}")
        if point is not None:
            start = previous = point
    return lines


def fetched(folder: Path | None, name: str) -> bytes:
    path, digest = SOURCES[name]
    data = (
        (folder / name).read_bytes() if folder else urllib.request.urlopen(f"{RAW}/{path}").read()
    )
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{name}: SHA-256 is not the pinned one")
    return data


def build(source: bytes, target: Path, points: set[int]) -> tuple[int, set[int]]:
    """Subset the font source (variable axes kept) to points as WOFF2 at target: its size in
    bytes and the code points it has glyphs for (some of points may not be in the source)."""
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = ["*"]
    options.name_IDs = ["*"]
    options.notdef_outline = True
    font = subset.load_font(io.BytesIO(source), options)
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=points)
    subsetter.subset(font)
    kept = set(font.getBestCmap())
    subset.save_font(font, str(target), options)
    return target.stat().st_size, kept


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sources", nargs="?", type=Path, help="folder with the four sources")
    folder = parser.parse_args().sources
    data = {name: fetched(folder, name) for name in SOURCES}
    signs = {p for low, high in SIGNS for p in range(low, high + 1)}
    text = signs | ks_x_1001() | own_text()
    OUT.mkdir(parents=True, exist_ok=True)
    noto, kept = build(data["NotoSansKR[wght].ttf"], OUT / "NotoSansKR-depbee.woff2", text)
    mono, _ = build(data["JetBrainsMono[wght].ttf"], OUT / "JetBrainsMono-depbee.woff2", signs)
    for name in ("OFL-NotoSansKR.txt", "OFL-JetBrainsMono.txt"):
        (OUT / name).write_bytes(data[name])
    lines = ranges(kept)
    (OUT / "coverage.txt").write_text("".join(f"{line}\n" for line in lines), "utf-8", newline="\n")
    print(f"NotoSansKR-depbee.woff2 {noto} bytes, {len(kept)} code points")
    lacking = sorted(own_text() - kept)
    if lacking:
        print("not in Noto Sans KR:", " ".join(f"U+{p:04X} {chr(p)}" for p in lacking))
    print(f"JetBrainsMono-depbee.woff2 {mono} bytes, {len(signs)} code points")


if __name__ == "__main__":
    main()
