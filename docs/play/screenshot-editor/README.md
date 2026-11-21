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

3. Source captures (1080×2400, real device, Nov 18 2026) live in `../raw/`. Flatten
   them to RGB into the template's
   `public/screenshots/android/phone/en/{01-inventory,02-grade,03-findings,04-services,05-settings,06-privacy}.png`
   and the icon to `public/app-icon.png`.
4. `bun run build` then `bun dev`, open the editor, press **Export bundle**.
5. Export zip contains one 1080×1920 PNG per slide at
   `android/android/1080x1920/en/` — copy them over `docs/play/screenshots/fg-0N-*.png`
   (order: 01-inventory, 02-grade, 03-findings, 04-services, 05-settings, 06-privacy).
6. Upload: `python3 docs/play/upload.py --key <key> images --type phoneScreenshots
   --files docs/play/screenshots/fg-0[1-6]-*.png`

Deck facts: 6 slides, layouts hero / device-bottom / device-top / device-bottom /
device-top / device-bottom (no adjacent repeats), inverted on slides 3 and 6,
connectedCanvas false. `export_run.py` is the headless re-export helper
(Playwright clicks Export bundle and saves the zip).

Captures predate 0.4.0 UI (flat severity list, no confidence groups). Re-capture
on-device before replacing them with new-UI versions.
