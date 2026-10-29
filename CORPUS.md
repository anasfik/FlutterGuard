# FlutterGuard test corpus

Eleven Flutter apps and one non-Flutter negative control, audited twice each: once by hand on the host
(`aapt2` + `unzip` + `strings` of `libapp.so`) and once by FlutterGuard on a
non-rooted phone. Every rule in `scan/rules/` exists because a manual finding
here proved the tool was blind to something. The host gold for each app lives
in `/tmp/opencode/man*/` and the device reports in `/tmp/opencode/survey/`.

APKs are kept out of the repo in `~/Downloads/.fgcorpus/{apks,apks2}`.

| App | Package | Build | Why it is in the corpus |
|---|---|---|---|
| Bztamy | `com.bzta.my` | debug / JIT | Kernel blob, no `libapp.so`, debuggable, live API |
| Kooul | `com.ora.customer` | AOT, 19 splits | Plaintext `.env.dev/.prod/.stage` in assets |
| LocalSend | `org.localsend.localsend_app` | AOT + Rust | `flutter_rust_bridge`, loopback HTTP server |
| Immich | `app.alextran.immich` | AOT | R8-flattened NSC trusting user CAs |
| Hiddify | `app.hiddify.com` | AOT | Proxy client, loopback-only cleartext |
| Obtainium | `dev.imranr.obtainium.fdroid` | AOT | Downloader: permissive NSC + user CAs |
| RustDesk | `com.carriez.flutter_hbb` | AOT + Rust | Well-built baseline, remote-desktop surface |
| Cake Wallet | `com.cakewallet.cake_wallet` | AOT + Rust/Go | Node-list YAMLs, pinned Ed25519 cert, 123 JNI |
| Spotube | `oss.krtirtho.spotube` | AOT + native | YouTube API key, permissive WebView flags |
| FluffyChat | `chat.fluffy.fluffychat` | AOT | Matrix E2EE, bundled ISRG roots, vodozemac |
| AppFlowy | `io.appflowy.appflowy` | AOT + Rust FFI | 12 Flowy native libs, Google key |
| Primal | `net.primal.android` | **not Flutter** | Negative control — must report `isFlutter=false` |

## What each app taught the tool

**Bztamy (debug/JIT).** The only app that exercises the kernel path. Its
113 MB `kernel_blob.bin` is where `package:` names, API routes and compiled
`--dart-define` keys live. Rules: `FLUT-DEBUG-BUILD`, `FLUT-JIT-SNAPSHOT`,
`SEC-ENV-KEY` (gated on `Envied`/`fromEnvironment`, otherwise every win32
`RPC_S_*` constant matches), route harvesting gated to the kernel layer.

**Kooul.** Ships `.env.dev`, `.env.prod`, `.env.stage` as plain text under
`assets/flutter_assets/`. Thirteen credentials in the prod file, including an
`ORALIZE_X_SECRET`. Rules: `DotEnv` parser + `AST-DOTENV` (CRITICAL for
prod-named files). The first version counted `FORCE_INVALID_STARTUP_AUTH_TOKENS=true`
as a credential — hence the boolean/short-value filter.

**LocalSend.** The first app that OOM-killed the scanner: a corrupt
`StringPool` header produced a 335 MB allocation. Rules: bounds-checked
`StringPool.parse`, declared-size-checked `ApkSource.bytes()`. Also the first
`flutter_rust_bridge` hit (`librust_lib_localsend_app.so`), which is why
non-flutter `.so` files are string-scanned up to 16 MB instead of 1 MB.

**Immich.** 1568 `res/*.xml` files, R8-flattened to `res/8G.xml`. The
`take(600)` cap silently skipped the network-security-config, and the AXML
decoder ignored character data so `<domain>…</domain>` was invisible. Rules:
uncapped `res/` XML pass, `AxmlNode.text` from `NODE_CDATA`, base-config
included in the trust-anchor scan → `NET-CLEARTEXT` + `NET-USERCA`.

**Hiddify.** Its config permits cleartext for `127.0.0.1` only. Before the
text-node fix that read as "domain-config without domain" and scored HIGH.
Rule: loopback-only cleartext downgrades to INFO.

**Obtainium.** Real `NET-CLEARTEXT` + `NET-USERCA` on a widely used app, which
is what confirmed those two rules are worth their severity.

**RustDesk.** Kept as the "good app" baseline: grade C, no criticals, one
native bridge finding. If a rule ever pushes a clean app to D/F, compare here
first.

**Cake Wallet.** Two lessons. (1) Nine node-list YAMLs list servers as
`uri: btc-electrum.cakewallet.com:50002` with no scheme — invisible to a
URL-only harvester, so `endpointListExt` + `endpointLine` now read
yaml/toml/conf/list files. (2) A DER certificate is embedded in `libapp.so`
as a contiguous `MII…` blob with subject `CN=Breez · O=Cake Wallet`; that
became the `X509` parser and `CRYPTO-X509`. Its 123 `Java_*` symbols are the
calibration point for `FLUT-JNI-SURFACE` (threshold 50).

**Spotube.** Five CRITICAL false positives from OpenSSL parser labels:
`libmpv.so` ships the literal strings `-----BEGIN RSA PRIVATE KEY-----` and
friends. Rules: `SEC-KEY-PRIVATE` requires a base64 body, and a PEM header
only counts if the next string is a long mixed-case base64 body — the pending
flag now clears on any non-matching string. Its Google API key
(`AIzaSyB-63…`) and permissive WebView flags are genuine.

**FluffyChat.** Two embedded ISRG roots stored as 64-character PEM lines, one
per string pool entry. The `MII…` regex could never match them, so certificates
are now reassembled from consecutive base64 chunks until the DER parses.
Result: `CRYPTO-X509 — CN=ISRG Root X2 · O=Internet Security Research Group`.
Its Google key lives in `resources.arsc`, not in Dart strings — proof that the
ARSC layer has to be scanned independently.

**AppFlowy.** Twelve Flowy native libraries; the string layer still finds
`appflowy.com`, and the `SEC-KEY-GOOGLE` hit is real. It reproduced the Spotube
PEM false positive from a different Rust lib, which is how the pending-flag bug
was confirmed as systemic rather than app-specific.

**Primal.** Not a Flutter app. Headless scanning still audits it when asked
explicitly, but `framework.isFlutter=false` and the UI launcher excludes it,
because `Discovery.detectFlutter` requires `libapp.so`, `libflutter.so` or an
`AssetManifest` in the zip. It also produced two `SEC-DB-URI` criticals from
Breez SDK doc placeholders (`mysql://user:password@host:3306/dbname`), now
filtered by placeholder-credential matching.

## Re-running the corpus

```sh
# verify locally (does not install or distribute a debug APK)
cd ~/Downloads/projects/real_projects/fg-remote
flock /tmp/opencode/flutterguard-build.lock env ANDROID_HOME="$HOME/Android/Sdk" ANDROID_SDK_ROOT="$HOME/Android/Sdk" "$HOME/tools/gradle-8.10.2/bin/gradle" --offline testDebugUnitTest assembleDebug

# Before device scans, install an approved signed release APK using the
# existing signing identity. Never replace it with a debug or newly signed APK.

# scan (headless intent) and pull the JSON
cd /tmp/opencode && bash survey.sh ~/Downloads/.fgcorpus/apks2/*.apk

# compare against host gold
python3 /tmp/opencode/diffgold.py /tmp/opencode/survey/<pkg>.json /tmp/opencode/man3/<app>/app.txt
```

`diffgold.py` prints gold hosts the report missed, gold cert blobs versus
`CRYPTO-X509` subjects, native-lib coverage and the severity spread — the
signal that turns a scan into a rule change.

The helper scripts and host-gold directories above are local session artifacts,
not checked-in tools. These observations describe the original corpus runs;
they do not prove later architecture or UI changes have passed device checks.

## Second corpus wave — 22 production apps (release builds)

Added 2026-10-30 to widen coverage beyond apps that happen to be on the
author's phone. Every APK is a real release build taken from the project's own
GitHub release, verified before install to contain `lib/arm64-v8a/libapp.so`
(i.e. genuinely Flutter, AOT), and classified by FlutterGuard on device with no
misses: **33 Flutter of 306 installed** after the install.

APKs are kept outside the repo in `~/Downloads/.fgcorpus2/`, with
`installed.tsv` mapping repo → package → size. Fetch and install are repeatable:

```bash
# one asset per repo, preferring arm64/universal; skip x86_64-only releases
bash /tmp/opencode/install_flutter.sh        # downloads + verifies + installs
bash /tmp/opencode/inst_par.sh               # re-entrant: installs whatever is new, 4-way
```

| App | Package | Category | Why it matters |
|---|---|---|---|
| Kazumi | `com.predidit.kazumi` | anime streaming | large asset bundle, many recovered URLs |
| oneAnime | `com.predidit.oneanime` | anime streaming | same author, smaller surface |
| Gopeed | `com.gopeed.gopeed` | downloader | Dart↔Go bridge, engine + native strings |
| PiliPala | `com.guozhigq.pilipala` | video client | per-region hosts, signing + API keys |
| PixEz | `com.perol.pixez` | image client | OAuth client ids, many hosts |
| venera | `com.github.wgh136.venera` | comic reader | plugin-style endpoints |
| Anx Reader | `com.anxcye.anx_reader` | ebook reader | sync endpoints, TTS plugins |
| Openlib | `com.app.openlib` | ebook search | small surface baseline |
| jasmine | `opensource.jmtt2mic` | manga reader | nested candidate routes |
| KitchenOwl | `com.tombursch.kitchenowl` | self-hosted recipes | user-supplied base URL, TLS policy |
| Conduit | `app.cogwheel.conduit` | Matrix client | homeserver override, cleartext paths |
| AuthPass | `design.codeux.authpass.sideload` | password manager | should look clean; crypto libs |
| Cashew | `com.budget.tracker_app` | finance | local-only baseline, few hosts |
| OpenNutriTracker | `com.opennutritracker.ont.opennutritracker` | health | local DB, minimal network |
| BeeCount | `com.tntlikely.beecount` | expenses | backup/export surface |
| Harmony Music | `com.anandnet.harmonymusic` | music | YouTube/Saavik bridges |
| Musify | `com.gokadzev.musify.fdroid` | music | F-Droid build, no Play deps |
| Finamp | `com.unicornsonlsd.finamp` | Jellyfin client | user server URL + auth tokens |
| namida | `com.msob7y.namida` | local music | large kernel, permission surface |
| BloomeeTunes | `ls.bloomee.musicplayer` | music | streaming plugin set |
| Echo-Loop | `app.echoloop` | media | 113 MB universal build |
| Ghosten Player | `com.ghosten.player` | media player | native decoder libs |

### What this wave is for

These are the apps to re-run whenever a rule changes: 33 Flutter apps is enough
that a detector which only fires on one hand-picked sample shows up as
noise-or-silence across the set. Re-run guidance is unchanged — scan headless,
pull the JSON, diff against the previous `.hist`:

```bash
adb shell am start -n com.flutterguard.app/.MainActivity -e scan com.gopeed.gopeed
adb logcat -d | grep FG_REPORT
adb pull /sdcard/Android/data/com.flutterguard.app/files/reports/com_gopeed_gopeed.json
```

Note for future fetches: the latest release assets of FlClash, PiliPlus,
miru-app, JHenTai, pikapika, kelivo and Mangayomi are **x86_64-only** and cannot
be installed on an arm64 phone; pick the arm64 asset when they publish one.
