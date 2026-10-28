# FlutterGuard test corpus

Twelve real Flutter apps, audited twice each: once by hand on the host
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
# build + install
cd ~/Downloads/projects/real_projects/FlutterGuard
~/tools/gradle-8.10.2/bin/gradle --offline assembleDebug 2>&1 | grep -E "^e:|BUILD"
adb install -r app/build/outputs/apk/debug/app-debug.apk

# scan (headless intent) and pull the JSON
cd /tmp/opencode && bash survey.sh ~/Downloads/.fgcorpus/apks2/*.apk

# compare against host gold
python3 /tmp/opencode/diffgold.py /tmp/opencode/survey/<pkg>.json /tmp/opencode/man3/<app>/app.txt
```

`diffgold.py` prints gold hosts the report missed, gold cert blobs versus
`CRYPTO-X509` subjects, native-lib coverage and the severity spread — the
signal that turns a scan into a rule change.
