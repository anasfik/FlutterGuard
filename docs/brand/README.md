# FlutterGuard identity

Canonical mark: <https://flutterguard.dev/favicon.svg>, retrieved 2026-10-31.
`favicon.svg` preserves the supplied geometry and colors without reinterpretation.

- Charcoal: `#0e1110`
- Ivory: `#f0f2ed`
- Mint: `#9ee6ad`
- Secondary text: `#b3bcb5`; divider: `#303a33`
- Marketing typography: Lato; technical labels: DejaVu Sans Mono.

All assets here are part of the FlutterGuard project and ship under the
repository's licence. The mark is original to this project. Lato is licensed under
the SIL Open Font License; DejaVu Sans Mono is under the Bitstream Vera licence.
Both are system fonts used for rendering only — no font file is redistributed.

Use `favicon.svg` as the rounded web tile, `mark.svg` for the transparent glyph,
and `logo-dark.svg` / `logo-light.svg` for horizontal lockups. Lockup text uses
Lato with a sans-serif fallback. Keep one square of clear space around the mark.
Do not stretch, rotate, add a shield, apply glow, or change the mint square.

The Android icon uses the exact two paths centered inside the adaptive safe zone.
Its charcoal background is a separate full-bleed layer; Android applies the mask.
Play's 512px icon is square and opaque; Play applies its own corner mask.

## Rebuild

From the repository root, with Chromium, Pillow, Lato and DejaVu Sans Mono installed:

```sh
python3 docs/play/render.py
python3 docs/play/render.py --check
```

This regenerates logo SVGs, the Play icon, 1024×500 feature graphic, and six
1080×1920 phone images. It does not upload, publish or require credentials.
`docs/play/raw/` contains unchanged captures from the physical Android device.
Frames remove ROM status/navigation chrome; the services frame additionally crops
the preceding scroll content as recorded in `shots.json`. Screens are not recolored
or reconstructed. These source captures predate this branding-only refresh;
the native app theme and scanner behavior are deliberately unchanged.
