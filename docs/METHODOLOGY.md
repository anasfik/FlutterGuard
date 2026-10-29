# Methodology: how the rule set was derived

FlutterGuard's detectors were not designed from a checklist. They were derived from
eleven real Flutter apps, with Primal as a non-Flutter negative control. The
Flutter corpus was audited twice: once by hand on a desktop host
(`aapt2` + `unzip` + `strings` of `libapp.so`), and once by the Android app on a
non-rooted phone. `CORPUS.md` holds the corpus table, the manual observations and
the host/device gold paths; this document explains what each app changed in the
scan pipeline.

The rule the project follows: a detector exists because a manual finding proved
the tool was blind to something. A rule without corpus evidence is general
Android review practice and is labeled as such at the end.

## The loop

1. Audit the app by hand on the host and write the gold notes (hosts, certs,
   native libs, secrets, severity spread).
2. Scan the same APK on the device with the current build.
3. Diff the report against the gold. `CORPUS.md` names this as `diffgold.py`:
   missed gold hosts, gold cert blobs versus `CRYPTO-X509` subjects, native-lib
   coverage, severity spread.
4. Fix the smallest layer that explains the gap — a parser bound, a gating
   condition, a severity rule — then rerun the corpus.
5. Re-check the clean baseline (RustDesk) so a new rule does not push a healthy
   app to D/F.

## Detector families

### Debug/JIT artifacts — Bztamy (`com.bzta.my`)

**Manual observation.** The only corpus app that ships no `libapp.so`, only a
113 MB `kernel_blob.bin`. Package URIs, API routes and `--dart-define` names are
readable directly from the kernel.

**Resulting behavior.**

- `FLUT-DEBUG-BUILD` (HIGH) when `kernel_blob.bin` is present
  (`scan/rules/FlutterRules.kt`).
- `FLUT-JIT-SNAPSHOT` (MEDIUM) when isolate/VM snapshot data exists without AOT.
- The kernel files get a full string sweep instead of a native-lib prefix read,
  and `.dart` paths ending a `package:` URI become `dartSources`
  (`scan/Scanner.kt`, kernel section).
- `SEC-ENV-KEY` only accepts a `SHOUTY_NAME` when the surrounding string also
  contains `Envied`, `varName`, `fromEnvironment` or `getEnvironment`. Without
  that gate every win32 `RPC_S_*` constant matched.
- Route harvesting started on the kernel layer. Bztamy is why the kernel is
  scanned at all; AOT builds now feed the same route table from `libapp.so`
  (`scan/rules/SecretScanner.kt`, route prefilter).

### Bundled environment files — Kooul (`com.ora.customer`)

**Manual observation.** AOT build with 19 splits that ships `.env.dev`,
`.env.prod` and `.env.stage` as plain text under `assets/flutter_assets/`.
Thirteen credentials in the prod file, including an `ORALIZE_X_SECRET`.

**Resulting behavior.**

- `scan/parsers/DotEnv.kt` parses `NAME=value`, `export NAME=value` and
  YAML-ish `NAME: value`, strips an inline ` #` comment and surrounding quotes,
  caps at 400 entries.
- `AST-DOTENV` severity is CRITICAL when credential-shaped names are present in
  a file whose name contains `prod` or `live`, HIGH when only credentials,
  MEDIUM otherwise. Every parsed value is also fed back through the secret
  rules, because a dotenv file is the highest-signal text in the artifact.
- The first version counted `FORCE_INVALID_STARTUP_AUTH_TOKENS=true` as a
  credential. Hence the value filter: at least 8 characters and not
  `true`/`false`/`null`/`none`.

### Endpoint inventories without a scheme — Cake Wallet (`com.cakewallet.cake_wallet`)

**Manual observation.** Nine node-list YAML files describe servers as
`uri: btc-electrum.cakewallet.com:50002` — no scheme, so the URL harvester never
saw them.

**Resulting behavior.** `endpointListExt` (`yml`, `yaml`, `toml`, `conf`, `txt`,
`csv`, `list`) plus `endpointLine`, which matches `uri|url|endpoint|host|server|
address|rpc|node|relay|api` followed by a dotted host and optional port, and
feeds it to the scanner as `https://<host>`
(`scan/Scanner.kt`, `scanAssets`). Bounded at 40 lines per file and 200 hits
total, 256 KB per file, 200-character lines.

### Embedded certificates — Cake Wallet and FluffyChat (`chat.fluffy.fluffychat`)

**Cake Wallet.** A DER certificate is embedded in `libapp.so` as one contiguous
`MII…` blob with subject `CN=Breez · O=Cake Wallet`. That produced
`scan/parsers/X509.kt`, which decodes base64 DER and reads only CN (2.5.4.3) and
O (2.5.4.10), taking the last OID hit because the issuer DN precedes the subject.
`CRYPTO-X509` (INFO) reports the identity so the backend and key owner are named
even when no hostname is hardcoded.

**FluffyChat.** Two ISRG roots are stored as 64-character PEM lines, one per
string-pool entry, so the `MII…` regex could never match. Certificates are now
reassembled from consecutive base64-looking strings until the DER parses
(`SecretScanner.feed`, `certChunks`; 12 000-character cap, 6 certificates).
Result on that app: `CRYPTO-X509 — CN=ISRG Root X2 · O=Internet Security
Research Group`.

### Private-key false positives — Spotube (`oss.krtirtho.spotube`), confirmed on AppFlowy

**Manual observation.** Five CRITICAL false positives: `libmpv.so` ships the
literal OpenSSL/librtmp strings `-----BEGIN RSA PRIVATE KEY-----` and friends. A
header is a parser label, not a key.

**Resulting behavior.**

- `SEC-KEY-PRIVATE` requires the header followed by 64+ base64 characters in the
  same string (`pemKeyRegex`).
- The split-string case is handled by `pemPending`: set on a bare header,
  satisfied only by a following 64+ base64 body, and cleared by any
  non-matching string so unrelated later strings cannot complete a key.
- AppFlowy reproduced the same false positive from a different Rust library,
  which confirmed the pending-flag bug as systemic rather than app-specific.

### Placeholder credentials — Primal (`net.primal.android`)

**Manual observation.** Primal is the negative control (not Flutter), but a
headless scan when asked explicitly produced two `SEC-DB-URI` criticals from
Breez SDK documentation placeholders:
`mysql://user:password@host:3306/dbname`.

**Resulting behavior.** `SEC-DB-URI` keeps rejecting supplied credentials
matching documentation placeholders: user in
`user, username, dbname, db, admin, root, test`, password in
`password, pass, passwd, secret, test, admin, changeme, dbname, host`
(`scan/rules/SecretScanner.kt`). The same app is why `framework.isFlutter` is
reported as a fact instead of an assumption: `Discovery.detectFlutter` requires a
`libapp.so`, a `libflutter.so`, or an `AssetManifest`, and the UI skips the
Flutter filter when it finds none.

### Network security config semantics — Immich, Hiddify, Obtainium

**Immich (`app.alextran.immich`).** 1568 `res/*.xml` files, R8-flattened to names
like `res/8G.xml`. A `take(600)` cap silently skipped the network security
config, and the AXML decoder ignored character data, so
`<domain>…</domain>` was invisible.

**Resulting behavior.**

- Every `res/*.xml` entry is decoded (4 MB per file), and the config is
  identified by its root element `network-security-config` rather than by
  filename; a populated config is preferred over a stub
  (`scan/Scanner.kt`).
- `AxmlNode.text` is populated from `NODE_CDATA`
  (`scan/parsers/AxmlDecoder.kt`), so `<domain>` text is readable.
- `base-config` is included in the trust-anchor scan, not just
  `domain-config`, which is what emits `NET-CLEARTEXT` and `NET-USERCA`
  (`scan/rules/NetworkRules.kt`).

**Hiddify (`app.hiddify.com`).** Its config permits cleartext for `127.0.0.1`
only. Before the text-node fix this read as "domain-config without domain" and
scored HIGH. Loopback-only cleartext now downgrades to INFO.

**Obtainium (`dev.imranr.obtainium.fdroid`).** A widely used app with genuine
`NET-CLEARTEXT` and `NET-USERCA`. It did not add a rule; it calibrated the
severity of two rules that had only been seen on anomalies.

### Native-side libraries — LocalSend (`org.localsend.localsend_app`)

**Manual observation.** The first app that OOM-killed the scanner: a corrupt
`StringPool` header produced a 335 MB allocation.

**Resulting behavior.**

- `StringPool.parse` validates chunk size and string count against the buffer
  before allocating (`scan/parsers/Binary.kt`); an out-of-bounds pool returns no
  strings instead of crashing.
- `ApkSource.bytes()` refuses entries whose declared size is unknown or above
  the caller's cap, so a lying zip header cannot force a large allocation.
- LocalSend was also the first `flutter_rust_bridge` hit
  (`librust_lib_localsend_app.so`). Non-Flutter `.so` files are now string-scanned
  up to 16 MB instead of 1 MB, and bridge markers produce
  `FLUT-NATIVE-BRIDGE` (INFO).

**Cake Wallet** added a second native measurement: its 123 `Java_*` symbols are
the calibration point for `FLUT-JNI-SURFACE`, which fires above 50 exported JNI
entry points.

### Clean baseline — RustDesk (`com.carriez.flutter_hbb`)

**Manual observation.** Well-built AOT + Rust remote-desktop app, grade C, no
criticals, one native-bridge finding.

**Resulting behavior.** Not a rule: a regression gate. If a rule change pushes a
clean app to D/F, the corpus is compared against RustDesk before the change is
accepted.

### ARSC as an independent layer — FluffyChat

**Manual observation.** FluffyChat's Google API key lives in `resources.arsc`,
not in Dart strings or DEX.

**Resulting behavior.** `ArscReader.globalStrings` reads the table's global string
pool and feeds every value through the scanner at `Layer.ARSC`
(`scan/parsers/ArscReader.kt`, `scan/Scanner.kt`). Package-level key pools are
skipped because they hold entry names, not values.

### AppFlowy (`io.appflowy.appflowy`)

**Manual observation.** Twelve Flowy native libraries; the string layer still
finds `appflowy.com`, and the `SEC-KEY-GOOGLE` hit is real.

**Resulting behavior.** Confirmed coverage of the multi-library native path and
reproduced the Spotube PEM false positive from a different library, which is how
that bug was classified as systemic. No rule is attributed to AppFlowy alone.

## Detectors that did not come from the corpus

These implement standard Android artifact review and are intentionally not
presented as corpus-derived:

- Manifest checks (`MAN-*`): debuggable, test-only, backup, cleartext flag,
  sharedUserId, exported components, custom dangerous permissions, aggregated
  custom-scheme deep links (`scan/rules/ManifestRules.kt`).
- Signing checks (`SIG-*`): debug certificate, v1-only signature blocks. Scheme
  detection reads the APK Signing Block for presence; it is not cryptographic
  verification (`scan/rules/SigningRules.kt`).
- WebView/bridge markers (`WEB-*`) from DEX strings.
- Third-party service table across files, DEX prefixes, pub packages and hosts
  (`scan/rules/ThirdPartyRules.kt`).
- Credential patterns for Stripe, AWS, Google, GitHub, Slack, OpenAI, SendGrid,
  Telegram, JWT, Mapbox, RevenueCat, Sentry, Supabase, Firebase. FlutterGuard app
  findings in this group were observed on corpus apps (Spotube, FluffyChat,
  AppFlowy) but the patterns themselves are generic.

## Grading and the diff loop

`gradeOf` (`scan/Model.kt`) is deliberately blunt: any critical gives `F`;
otherwise `score = high*25 + medium*8 + low*2`, mapped to `A` (0), `B` (≤10),
`C` (≤45), `D` (≤110), else `F`.

Every scan writes a line-oriented snapshot next to the JSON report
(`scan/History.kt`): version, hosts, routes, `severity|id` findings and pub
dependencies, sorted. The next scan of the same package diffs them and prints
`+` appeared, `-` disappeared, `~` version changed, capped at 40 lines. This is
the one signal a single static scan cannot give: what the update changed.

## Reproducing

The corpus APKs are not in the repository. `CORPUS.md` documents the build,
install, headless scan and gold-diff commands, and the host/device report
locations used during the audit.

Known limit of the on-device path: it can read artifacts and strings but cannot
decompile the Android wrapper or Dart AOT code. Anything that needs `jadx`,
`apksigner` verification, `bundletool`, or Blutter/reFlutter stays a manual step,
which is why `skill/SKILL.md` remains the primary workflow.
