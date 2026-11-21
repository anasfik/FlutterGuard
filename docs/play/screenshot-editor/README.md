# Play phone screenshots — editor recipe

The shipped `docs/play/screenshots/fg-01..06-*.png` (1080×1920) are generated from the
app-store-screenshots skill template, not hand-drawn HTML. To edit the deck:

1. Copy the skill template (`~/.config/opencode/skills/app-store-screenshots/template/`)
   to a scratch dir, then copy `app-store-screenshots.json` from this folder over the
   template's own file.
2. Add the FlutterGuard theme to the template's `src/lib/constants.ts` THEMES map:

   ```
   flutterguard: bg #f3f5ef, bgAlt #132d25, fg #132d25, fgAlt #f3f5ef,
   accent #285f42, muted #53675b, accentAlt #bce6a0
   ```

3. Source captures: `sources/` holds the current 1080×2304 crops (status bar trimmed
   from the raw 1080×2400 captures). Originals from the 0.4.0 on-device verification are
   in `../raw/0.4.0/`. Copy `sources/*.png` into the template's
   `public/screenshots/android/phone/en/` and `../icon-512.png` to `public/app-icon.png`.
4. `bun run build` then `bun dev`, open the editor, press **Export bundle**.
5. Export zip contains one 1080×1920 PNG per slide at
   `android/android/1080x1920/en/` — copy them over `docs/play/screenshots/fg-0N-*.png`
   (order: 01-inventory, 02-grade, 03-findings, 04-services, 05-settings, 06-privacy).
6. Upload: `python3 docs/play/upload.py --key <key> images --type phoneScreenshots
   --files <each png listed explicitly>`. List the six files; a `[1..6]` shell glob
   matches only `01` and `06` in zsh/bash and replaces the set with two images.

Deck facts: 6 slides, layouts hero / device-bottom / device-top / device-bottom /
device-top / device-bottom (no adjacent repeats), inverted on slides 3 and 6,
connectedCanvas false. Labels INVENTORY / GRADE / FINDINGS / ENDPOINTS / CONTROLS /
PRIVACY. Device-top slides carry caption transforms `{x:86.4,y:1363.2,width:907.2,
height:537.6}` so the caption clears the phone bezel. `export_run.py` is the headless
re-export helper (Playwright clicks Export bundle and saves the zip).

Source captures are 0.4.0 (2026-11-21, Redmi Note 9 Pro, LineageOS 22): confidence
groups ("8 confirmed · 9 leads · 6 inventory"), grade D, Settings → About shows
"0.4.0 (10)". Slide 4 label is ENDPOINTS because that screen shows recovered hosts and
candidate routes. Re-capture on-device if the UI or app version changes.
