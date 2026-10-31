#!/usr/bin/env python3
"""Render Play Store phone screenshots (1080x1920) from raw device captures.

Raw captures arrive at 1080x2400 with a status bar carrying the ROM's clock and
network stats, so the bar is cropped before framing. Output is HTML rendered by
headless Chromium: real text layout beats PIL text compositing.
"""
import json
import pathlib
import subprocess
import sys

from PIL import Image

HERE = pathlib.Path("/tmp/opencode/play")
OUT = HERE / "out"
# Headless Chromium paints only (window_height - 88) rows, leaving the rest at
# the body colour, so every shot asks for H+PAD and crops back to H. The extra
# rows are not laid out, which keeps the CSS viewport exactly H.
PAD = 88
CROP_TOP = 96      # status bar incl. LineageOS stats overlay
CROP_BOTTOM = 96   # gesture nav bar

HTML = """<!doctype html><html><head><meta charset="utf-8"><style>
  @page { margin: 0 }
  * { margin: 0; padding: 0; box-sizing: border-box }
  /* Chromium's viewport is shorter than --window-size, so painting the
     background on body leaves an unpainted strip at the bottom. The canvas
     comes from the html element; put it there. */
  html { background: #070A0F;
    background-image:
      radial-gradient(1200px 700px at 50% -8%, rgba(34,211,238,0.22), rgba(7,10,15,0) 62%),
      radial-gradient(900px 600px at 88% 105%, rgba(34,211,238,0.10), rgba(7,10,15,0) 60%); }
  body {
    width: 1080px; height: 1920px; overflow: hidden;
    font-family: 'Lato', 'Noto Sans', sans-serif;
    color: #EAF6FF;
    display: flex; flex-direction: column;
    padding: 96px 84px 0 84px;
  }
  .brand { display: flex; align-items: center; gap: 16px; margin-bottom: 44px }
  .mark { width: 40px; height: 40px; border-radius: 12px;
          background: linear-gradient(160deg, #22D3EE, #0E7490);
          box-shadow: 0 0 32px rgba(34,211,238,.45) }
  .brand span { font-size: 27px; font-weight: 500; letter-spacing: .14em;
                text-transform: uppercase; color: #7FA3B8 }
  h1 { font-size: 82px; line-height: 1.06; font-weight: 900; letter-spacing: -1.6px;
       color: #F2FBFF }
  h1 em { font-style: normal; color: #22D3EE }
  p { margin-top: 26px; font-size: 33px; line-height: 1.4; font-weight: 500;
      color: #8FB3C7; max-width: 900px }
  .chips { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 40px }
  .chip { font-size: 26px; font-weight: 500; letter-spacing: .01em; color: #9FE8F7;
          border: 1px solid rgba(34,211,238,.30); background: rgba(34,211,238,.08);
          border-radius: 999px; padding: 12px 24px; white-space: nowrap }
  .stage { margin-top: auto; display: flex; justify-content: center; align-items: flex-end }
  .phone { width: __PHONEW__; border-radius: 46px; overflow: hidden; position: relative;
           border: 1px solid rgba(148,233,255,.20);
           box-shadow: 0 -10px 90px rgba(34,211,238,.16), 0 40px 120px rgba(0,0,0,.75);
           /* the frame only shows the top of the screen, so it bleeds off the bottom */
           margin-bottom: -140px }
  .phone img { display: block; width: 100% }
  .notch { position: absolute; top: 16px; left: 50%; transform: translateX(-50%);
           width: 128px; height: 10px; border-radius: 6px; background: rgba(7,10,15,.55) }
</style></head><body>
  <div class="brand"><div class="mark"></div><span>FlutterGuard</span></div>
  <h1>__TITLE__</h1>
  <p>__SUB__</p>
  <div class="chips">__CHIPS__</div>
  <div class="stage"><div class="phone"><img src="__IMG__"></div></div>
</body></html>"""


def shot(page: pathlib.Path, png: pathlib.Path, w: int, h: int) -> None:
    tmp = png.with_name(png.stem + ".tmp.png")
    subprocess.run(
        ["chromium", "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
         "--force-device-scale-factor=1", f"--window-size={w},{h + PAD}",
         f"--screenshot={tmp}", page.as_uri()],
        check=True, capture_output=True,
    )
    Image.open(tmp).convert("RGB").crop((0, 0, w, h)).save(png)
    tmp.unlink()


def frame(raw: pathlib.Path, slug: str, crop_top: int = 0) -> pathlib.Path:
    """Crop the ROM status/nav bars, plus an optional scroll offset.

    `crop_top` drops part of the scrollable content so a long section (a list
    far down the page) starts at the top of the frame instead of showing the
    tail of whatever came before it.
    """
    im = Image.open(raw)
    w, h = im.size
    im.crop((0, CROP_TOP + crop_top, w, h - CROP_BOTTOM)).save(OUT / f"{slug}-screen.png")
    return OUT / f"{slug}-screen.png"


def render(slug: str, title: str, sub: str, chips=(), phone_w: int = 660) -> pathlib.Path:
    html = HTML.replace("__TITLE__", title).replace("__SUB__", sub)
    # A shot whose crop is short would otherwise leave a dead gap above the
    # phone; widening the frame makes it taller and eats that space.
    html = html.replace("__PHONEW__", f"{phone_w}px")
    html = html.replace("__CHIPS__", "".join(f'<span class="chip">{c}</span>' for c in chips))
    html = html.replace("__IMG__", f"{slug}-screen.png")
    page = OUT / f"{slug}.html"
    page.write_text(html)
    png = OUT / f"fg-{slug}.png"
    shot(page, png, 1080, 1920)
    return png


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    shots = json.loads((HERE / "shots.json").read_text())
    for s in shots:
        raw = HERE / s["raw"]
        if not raw.exists():
            print(f"SKIP {s['slug']}: no {raw}")
            continue
        frame(raw, s["slug"], s.get("cropTop", 0))
        print("wrote", render(s["slug"], s["title"], s["sub"], s.get("chips", []), s.get("phoneWidth", 660)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
