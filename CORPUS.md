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
adb exec-out run-as com.flutterguard.app cat files/reports/com_gopeed_gopeed.json > com_gopeed_gopeed.json
```

Note for future fetches: the latest release assets of FlClash, PiliPlus,
miru-app, JHenTai, pikapika, kelivo and Mangayomi are **x86_64-only** and cannot
be installed on an arm64 phone; pick the arm64 asset when they publish one.

## Gap study: what the 26 release APKs carry that FlutterGuard missed

Method, so the numbers can be re-derived rather than trusted:

```bash
# 1. extract every APK once
for f in ~/Downloads/.fgcorpus2/*.apk ~/Downloads/.fgcorpus/*.apk; do
  d=/tmp/opencode/corpus-x/$(basename "$f" .apk); mkdir -p "$d"; unzip -qo "$f" -d "$d"; done

# 2. provider hosts — FIXED STRINGS, never a regex file.
#    `rg -f` with counted repetitions (`sk-[A-Za-z0-9]{48}`) is ~85x slower:
#    74s for one 2.5MB classes.dex versus 0.87s for the whole 121MB app as -F.
rg -F -a -o --no-filename -N -f hosts.txt <app-dir> | sort -u

# 3. third-party SDKs live as DEX type descriptors, not as readable strings
rg -a -o --no-filename -N 'L(?:com|io|org|net|dev|app|me|co)/[a-z0-9_$]{2,30}(?:/[a-z0-9_$]{2,30}){0,2}' \
  <app-dir>/classes*.dex | sed 's|^L||' | sort | uniq -c | sort -rn
```

### Measured result — AI providers

`hosts.txt` held 109 literal provider hosts. **9 of 26 apps matched at least one**, and
the distribution is the argument for per-provider rules instead of one lumped "LLM" entry:

| App | Provider endpoints found |
|---|---|
| Conduit (`app.cogwheel.conduit`) | **22** — anthropic, cerebras, cohere, deepinfra, deepseek, fireworks, groq, mistral, moonshot, novita, openai, perplexity, poe, together, x.ai, volces (ark), dashscope, gemini, huggingface, openrouter, open.bigmodel, here |
| Anx Reader | 5 — anthropic, deepseek, openai, gemini, openrouter |
| OpenNutriTracker | 3 — anthropic, openai, openrouter |
| AppFlowy | `localhost:11434` **and** `localhost:1234` |
| Echo-Loop | huggingface, posthog, supabase |
| BeeCount | open.bigmodel, supabase |
| namida, primal, authpass | supabase / elastic, here / iterable |

Before this study the only related detector was a single `OpenAI/LLM` service with three
hosts and four pub packages, so Anthropic, Gemini, DeepSeek, OpenRouter, Groq, xAI and the
on-device Ollama/LM Studio endpoints in AppFlowy were all invisible.

`localhost:11434` and `localhost:1234` are the interesting ones: they are not third-party
calls at all, they are a phone talking to an LLM running on the same device or on the LAN.
A finding that says "this app can talk to a local model" is only deliverable if the rule
table contains those ports literally, which is why they are host entries rather than a
generic "AI SDK" guess.

### Measured result — third-party SDKs

The 82 DEX prefixes extracted from the rule table were swept as fixed strings over every
`classes*.dex`. **22 of 26 apps matched at least one.** Prefix → number of apps:

`com/google/android/gms` 11 · `com/pichillilorenzo/flutter_inappwebview` 10 ·
`androidx/media3` 10 · `androidx/work` 8 · `com/google/firebase` 5 ·
`io/flutter/plugins/firebase` 4 · `com/android/billingclient` 4 · `androidx/biometric` 3 ·
`com/google/mlkit` 2 · `io/sentry`, `io/grpc`, `com/revenuecat`, `com/posthog`,
`com/google/android/play/core/integrity`, `com/google/android/exoplayer2` 1 each.

**Every other prefix matched nothing in this corpus** — ad networks, attribution, auth
providers, realtime SDKs, payment SDKs, backend SDKs and vector stores. They are shipped
as coverage for apps that are not in this corpus, not as demonstrated detections. Do not
quote them as findings about these 26 apps.

### Measured result — pubspec and config files

`assets/flutter_assets/pubspec.yaml` exists in **1 of 26** apps (Anx Reader: `anx_reader`
`1.14.0+6321`, 92 dependencies with constraints). It is a bonus signal, not a replacement
for `NOTICES.Z` and `package:` URIs — most release builds strip it.

Cheap filename-only signals that do work across the corpus: root `billing.properties`,
`play-services-{base,basement,tasks,location,places-placereport}.properties`,
`transport-{api,backend-cct,runtime}.properties`, `firebase-encoders{,-json,-proto}.properties`.
Anx Reader additionally bundles a full web payload under
`assets/flutter_assets/assets/foliate-js/` (`index.html`, `epub.js`, prism bundles) plus
`flutter_inappwebview`'s `web_support.js` and a `trix` runner page — a local WebView
surface that no host-based rule can see.

### What this study added to the detectors

- `rules/ProviderSecrets.kt` — 25 rules for credentials the corpus showed in use:
  Anthropic, OpenAI project keys, Groq, HuggingFace, Replicate, OpenRouter, xAI, Fireworks,
  Postmark, Mailgun, Azure Storage `AccountKey`, GCP service-account JSON, DigitalOcean,
  GitHub PAT, GitLab, npm, Docker, Postman, Airtable, Notion, Linear, Slack and Discord
  webhooks, bearer JWTs, AES/ECB usage.
- `rules/ThirdPartyRules.kt` — 35 services became ~135: per-provider LLM entries, ad
  networks, attribution, auth providers, realtime, payments, backends, vector/search,
  on-device HTTP servers (`shelf`, `dart_frog`), local storage and media stacks.
- `rules/AssetInventory.kt` — filename-only inventory: bundled HTML/JS as a WebView
  payload, root `.properties` SDK markers, and config/secret-bearing files (`.env`,
  `.json`, `.yaml`, `.sqlite`, key material) excluding `res/`, `META-INF/` and fonts.
- `parsers/Pubspec.kt` — exact dependency names and constraints when the pubspec ships.

All of it is static, offline and evidence-only: a matched host proves the string is in
the APK, not that the app calls it; a matched key is a key-shaped string, not a verified
credential.

## Device verification of the gap fixes

Recorded 2026-10-30 on the physical device (Redmi Note 9 Pro, LineageOS, API 35), using a
side-by-side `com.flutterguard.app.dev` build so the signed release on the device was untouched.
Target: `app.cogwheel.conduit` — Conduit, the densest provider surface in the corpus.

| | before the fixes | after |
|---|---|---|
| third-party services reported | 15 | 28 |
| AI providers reported | 4 | 17 |
| provider hosts in the report | 4 | 23 |

The four providers found before were OpenAI, OpenRouter, HuggingFace and Ollama/LM Studio. The
17 found after are OpenAI, Anthropic, Google Gemini, OpenRouter, DeepSeek, Groq, Mistral, Cohere,
Together AI, Fireworks AI, Perplexity, xAI, HuggingFace, Alibaba Qwen/DashScope, Moonshot,
Zhipu GLM and Ollama/LM Studio — matching the 22 endpoint strings measured on the host.

### The gap the device run exposed

`SecretScanner` only harvested hosts out of strings that contained `://`. A Dart AOT snapshot
usually stores a provider base URL as a plain string, so `api.anthropic.com` sat in `libapp.so`
invisible while `https://api.anthropic.com/v1/messages` would have been caught. The fix is a
fixed-suffix host matcher with a lookbehind, so `myopenai.com` is not mistaken for `openai.com`;
it is a closed list of provider domains, not a generic FQDN scan, and it is covered by four
regression tests.

### Still unattributed

`api.cerebras.ai`, `api.novita.ai`, `api.poe.com`, `open.bigmodel.cn` and the three
`dashscope.aliyuncs.com` variants are now harvested as hosts, but no service entry names them
individually, so they appear in the host list rather than as a named provider. Naming them is a
data edit in `ThirdPartyRules.services`, not a detector change.

### Cost of a scan on this size of app

Conduit takes about five minutes end to end, roughly 2m45s of it inside the single-threaded
string sweep of the 38 MB `libapp.so`. That stage emits one progress line for all native
libraries, so it looks stalled while it works. Per-library progress and a cheaper sweep for very
large AOT snapshots are the next performance items; they are pre-existing, not caused by the
detector additions.
