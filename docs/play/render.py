#!/usr/bin/env python3
"""Rebuild local brand/Play artwork: python3 docs/play/render.py [--check].

Requires Chromium, Pillow and the Lato / DejaVu Sans Mono fonts. No network,
credentials or publishing. Raw device captures are kept unchanged in raw/.
"""
import base64
import html
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
BRAND = HERE.parent / "brand"
PAD = 88  # This Chromium build subtracts its window chrome from --window-size.

TOKENS = """
:root{--base:#0e1110;--surface:#181e1a;--ink:#f0f2ed;--muted:#b3bcb5;
--accent:#9ee6ad;--line:#303a33;--font:'Lato',sans-serif;
--mono:'DejaVu Sans Mono',monospace;--small:24px;--body:32px;--display:80px;
--space:8px;--radius:32px;--shadow:none}
"""
HTML = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>FlutterGuard — __LABEL__</title><style>__TOKENS__
*{box-sizing:border-box;margin:0}html{background:var(--base)}
body{width:1080px;height:1920px;overflow:hidden;color:var(--ink);font-family:var(--font);padding:64px 80px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:56px}
.brand{display:flex;align-items:center;gap:16px;font-size:32px;font-weight:700}
.brand img{width:64px;height:64px}.index{font:var(--small) var(--mono);color:var(--muted)}
h1{font-size:var(--display);line-height:1.05;letter-spacing:-2px;font-weight:900;max-width:920px}
h1 em{color:var(--accent);font-style:normal}
p{font-size:var(--body);line-height:1.4;color:var(--muted);margin-top:24px;max-width:880px}
.evidence{font:var(--small) var(--mono);color:var(--accent);margin-top:32px;padding-top:24px;border-top:1px solid var(--line)}
.stage{height:1176px;margin-top:40px;display:flex;justify-content:center;align-items:flex-start}
.phone{width:__PHONEW__px;max-height:100%;border:2px solid var(--line);border-radius:var(--radius);overflow:hidden;background:var(--surface)}
.phone img{display:block;width:100%}
footer{position:absolute;top:1840px;left:80px;right:80px;background:var(--base);padding-top:16px;font:20px var(--mono);color:var(--muted);border-top:1px solid var(--line)}
</style><body><header><div class="brand"><img src="__MARK__" alt="">FlutterGuard</div><span class="index">__INDEX__ / 06</span></header>
<h1>__TITLE__</h1><p>__SUB__</p><div class="evidence">__EVIDENCE__</div>
<div class="stage"><div class="phone"><img src="__IMG__" alt="Actual FlutterGuard screen"></div></div>
<footer>OFFLINE APK RESEARCH · ANDROID</footer></body></html>"""


def data_uri(path):
    mime = "image/svg+xml" if path.suffix == ".svg" else "image/png"
    return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode()


def shot(page, png, width, height):
    tmp = png.with_name(png.stem + ".tmp.png")
    subprocess.run([
        shutil.which("chromium") or shutil.which("chromium-browser") or "chromium", "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
        "--force-device-scale-factor=1", "--default-background-color=00000000",
        f"--window-size={width},{height + PAD}", f"--screenshot={tmp}", page.as_uri(),
    ], check=True, capture_output=True)
    with Image.open(tmp) as image:
        image.convert("RGB").crop((0, 0, width, height)).save(png)
    tmp.unlink()


def render_shots(work):
    for index, s in enumerate(json.loads((HERE / "shots.json").read_text()), 1):
        raw = HERE / "raw" / s["raw"]
        with Image.open(raw) as image:
            # Captured at 1080x2400. Strip only ROM chrome and documented scroll offset.
            assert image.size == (1080, 2400), (raw, image.size)
            image.crop((0, 96 + s.get("cropTop", 0), 1080, 2268)).save(work / "screen.png")
        page_html = HTML
        values = {
            "TOKENS": TOKENS, "LABEL": s["slug"], "INDEX": f"{index:02}",
            "TITLE": s["title"], "SUB": html.escape(s["sub"]),
            "EVIDENCE": html.escape(s["evidence"]), "PHONEW": str(s.get("phoneWidth", 760)),
            "MARK": data_uri(BRAND / "favicon.svg"), "IMG": data_uri(work / "screen.png"),
        }
        for key, value in values.items():
            page_html = page_html.replace(f"__{key}__", value)
        page = work / "shot.html"
        page.write_text(page_html)
        shot(page, HERE / "screenshots" / f"fg-{s['slug']}.png", 1080, 1920)


def logos():
    source = ET.parse(BRAND / "favicon.svg").getroot()
    ns = {"s": "http://www.w3.org/2000/svg"}
    paths = "".join(f'<path d="{p.attrib["d"]}" fill="{p.attrib["fill"]}"/>'
                    for p in source.findall("s:path", ns))
    (BRAND / "mark.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="FlutterGuard">'
        + paths + '</svg>\n')
    for mode, background, ink in [("dark", "#0e1110", "#f0f2ed"), ("light", "#f0f2ed", "#0e1110")]:
        (BRAND / f"logo-{mode}.svg").write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" width="560" height="112" viewBox="0 0 560 112" role="img" aria-label="FlutterGuard">'
            f'<rect width="560" height="112" fill="{background}"/>'
            f'<g transform="translate(16 24)"><rect width="64" height="64" rx="10" fill="#0e1110"/>{paths}</g>'
            f'<text x="104" y="72" font-family="Lato, sans-serif" font-size="44" font-weight="700" fill="{ink}">FlutterGuard</text></svg>\n')


def path_bounds(d):
    """Bounding box of an SVG path using only absolute/relative M, L, H, V and Z."""
    nums = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", d)]
    tokens = re.findall(r"[MLHVZmlhvz]|-?\d+(?:\.\d+)?", d)
    x = y = sx = sy = 0.0
    lo_x = lo_y = float("inf")
    hi_x = hi_y = float("-inf")
    cmd = None
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.isalpha():
            cmd = t
            i += 1
            if cmd == "Z" or cmd == "z":
                x, y = sx, sy
                continue
            continue
        rel = cmd.islower()
        c = cmd.upper()
        if c == "H":
            x = (x + float(t)) if rel else float(t)
            i += 1
        elif c == "V":
            y = (y + float(t)) if rel else float(t)
            i += 1
        elif c in "ML":
            px, py = float(tokens[i]), float(tokens[i + 1])
            x, y = (x + px, y + py) if rel else (px, py)
            i += 2
            if c == "M":
                sx, sy = x, y
                cmd = "l" if rel else "L"
        else:
            raise AssertionError("Unsupported path command: " + cmd)
        lo_x, hi_x = min(lo_x, x), max(hi_x, x)
        lo_y, hi_y = min(lo_y, y), max(hi_y, y)
    assert nums, d
    return lo_x, lo_y, hi_x, hi_y


def check():
    """Runnable regression gate: identity, real safe-zone transform, palette, output pixels."""
    ns = {"s": "http://www.w3.org/2000/svg"}
    root = ET.parse(BRAND / "favicon.svg").getroot()
    source = root.findall("s:path", ns)
    a = "{http://schemas.android.com/apk/res/android}"
    android = ET.parse(HERE.parents[1] / "app/src/main/res/drawable/ic_launcher_foreground.xml").getroot()
    paths = list(android.iter("path"))
    assert len(source) == len(paths) == 2
    normalize = lambda value: value.replace(",", "").replace(" ", "")
    for svg, vector in zip(source, paths):
        assert normalize(svg.attrib["d"]) == normalize(vector.attrib[a + "pathData"])
        assert svg.attrib["fill"] == vector.attrib[a + "fillColor"]

    # Safe zone: transform from the drawable itself, not from constants copied by hand.
    group = next(android.iter("group"))
    scale_x = float(group.attrib[a + "scaleX"])
    scale_y = float(group.attrib[a + "scaleY"])
    shift_x = float(group.attrib[a + "translateX"])
    shift_y = float(group.attrib[a + "translateY"])
    view_w = float(android.attrib[a + "viewportWidth"])
    view_h = float(android.attrib[a + "viewportHeight"])
    assert view_w == view_h, android.attrib
    safe_radius = view_w * 66 / 108 / 2  # Android's 66dp safe circle inside the 108dp layer.
    corners = set()
    for vector in paths:
        lo_x, lo_y, hi_x, hi_y = path_bounds(vector.attrib[a + "pathData"])
        corners |= {(lo_x, lo_y), (hi_x, lo_y), (lo_x, hi_y), (hi_x, hi_y)}
    for x, y in corners:
        mapped_x, mapped_y = x * scale_x + shift_x, y * scale_y + shift_y
        assert (mapped_x - view_w / 2) ** 2 + (mapped_y - view_h / 2) ** 2 < safe_radius ** 2, (x, y)

    # The launcher background must be the favicon's own tile colour.
    tile = next(e for e in root.iter("{http://www.w3.org/2000/svg}rect")).attrib["fill"].lower()
    colour = ET.parse(HERE.parents[1] / "app/src/main/res/values/ic_launcher_background.xml")
    declared = colour.getroot().find("color").text.strip().lower()
    assert tile == declared, (tile, declared)

    expected = {HERE / "icon-512.png": (512, 512), HERE / "feature-1024x500.png": (1024, 500)}
    expected.update({p: (1080, 1920) for p in (HERE / "screenshots").glob("fg-*.png")})
    assert len(expected) == 8, "Expected six phone screenshots"
    for path, size in expected.items():
        with Image.open(path) as image:
            assert image.size == size, (path, image.size)
            assert image.mode == "RGB"
    for path in (HERE / "screenshots").glob("fg-*.png"):
        with Image.open(path) as image:
            # A blank or mis-shifted render collapses to a handful of colours.
            colours = image.resize((270, 480)).getcolors(maxcolors=1 << 20)
            assert colours and len(colours) > 200, (path, len(colours or []))
    with Image.open(HERE / "icon-512.png") as icon:
        assert icon.getpixel((0, 0)) == (14, 17, 16)
        assert icon.getpixel((144, 128)) == (240, 242, 237)
        assert icon.getpixel((320, 352)) == (158, 230, 173)
    print("PASS: source geometry/colours, derived Android safe zone, tile colour, "
          "six screenshots, feature graphic and Play icon")


def main():
    if sys.argv[1:] == ["--check"]:
        check()
        return
    if sys.argv[1:]:
        raise SystemExit("Usage: render.py [--check]")
    logos()
    with tempfile.TemporaryDirectory(prefix="fg-brand-") as tmp:
        render_shots(pathlib.Path(tmp))
    shot(HERE / "icon.html", HERE / "icon-512.png", 512, 512)
    shot(HERE / "feature.html", HERE / "feature-1024x500.png", 1024, 500)
    check()


if __name__ == "__main__":
    main()
