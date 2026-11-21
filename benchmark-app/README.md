# FlutterGuard benchmark fixture (UNSAFE, local-only)

This is a deliberately unsafe Flutter Android app used as a **test input** for
FlutterGuard. It exists to plant known facts in a reviewable source tree before
a benchmark harness judges scanner output. It is not a demo, not a template, and
must never be published or installed as a normal app.

- No network operation is performed by fixture code. Project manifests declare
  **no Android permissions** and Dart code has no networking imports.
- Every credential-shaped value is synthetic. There is no account, service, or
  key behind any of them; each is not a real credential. `api.benchmark.invalid`
  is reserved by RFC 2606.
- The permissive network security config is a planted artifact, not evidence
  that this app can make a cleartext request.

## Planted facts (the oracle by construction)

The manifest is intentionally hostile. Every attribute and component below is a
planted artifact fact: the compiled APK really carries it. None of it is
reachable, usable, or exploitable, and no credential is valid.

| # | Fact | Location | Why it is unsafe |
|---|---|---|---|
| 1 | Provider-shaped API key literal, `sk-proj-benchmarkFAKE…` | `lib/main.dart` | Secret-shaped literal compiled into Dart code; AOT does not automatically remove a used string. |
| 2 | `String.fromEnvironment('FG_BENCHMARK_SECRET')` value supplied by `--dart-define` | `lib/main.dart`, build recipe below | Build-time configuration is baked into the AOT snapshot and is readable from the artifact. |
| 3 | `.env` shipped as a Flutter asset with a synthetic key | `assets/test.env`, registered in `pubspec.yaml` | Configuration files in `flutter_assets/` are packaged and readable without executing the app. |
| 4 | Permissive network security config: cleartext allowed, user CAs trusted | `android/app/src/main/res/xml/network_security_config.xml` | If the app had network access, it would accept cleartext and user-installed CAs. |
| 5 | Exported activities, service, receiver and provider with no permission | `AndroidManifest.xml`, `BenchmarkExportedActivity/Service/Receiver/Provider.kt` | Another app can address each component. The components are inert: the activity and service return immediately, the receiver ignores broadcasts, the provider returns nothing. |
| 6 | `android:debuggable="true"` on a release build | `AndroidManifest.xml` | A debuggable application can be attached to and inspected at runtime on a device that permits it. |
| 7 | `android:usesCleartextTraffic="true"` plus a permissive NSC | `AndroidManifest.xml` | The policy allows cleartext HTTP if networking were ever added. |
| 8 | `android:allowBackup="true"` | `AndroidManifest.xml` | Application data is eligible for cloud or adb backup. |
| 9 | `android:sharedUserId` declared | `AndroidManifest.xml` | The manifest claims a shared UID namespace, a legacy cross-app data-sharing mechanism. |
| 10 | Dangerous custom permission declared | `AndroidManifest.xml` | A protection level of `dangerous` is a runtime-granted permission the fixture never uses. |
| 11 | OAuth-shaped deep link (`benchmark-oauth://callback`) | `AndroidManifest.xml`, `OAuthCallbackActivity.kt` | A browsable custom scheme with an auth-shaped host is a redirect target for token interception if the scheme were trusted. The activity is empty. |
| 12 | A packaged secrets file with provider-shaped values | `assets/benchmark-secrets.json`, `assets/benchmark-credentials.txt` | Plaintext assets are readable from the APK without executing the app. Values cover OpenAI, Anthropic, Stripe, GitHub, GitLab, npm, Docker Hub, Supabase, Slack, Discord, SendGrid, Telegram, Google, AWS, Azure, GCP service accounts, JWTs, database URIs, basic-auth URLs and an RSA private key block. All are synthetic and marked `FAKE`/`BENCHMARK`. |

The app displays facts 1–3 as selectable text so release tree-shaking cannot
remove the literals the fixture claims to contain.

There is **no `INTERNET` permission** in any project manifest. The generated
Flutter debug/profile manifests were removed. Confirm the merged permissions
with `aapt2 dump permissions` on each built APK; dependencies can add entries.
Fact 4 is an artifact-presence fact, not a claim of exploitability.

### Presence is not exploitability

A scanner finding any of these items proves the artifact contains the item. It
does not prove the item is reachable, usable, or exploitable. In particular:

- the synthetic keys are not valid credentials;
- the cleartext policy cannot be exercised without `INTERNET`;
- the exported activity finishes immediately and exposes no data;
- `--obfuscate` renames Dart identifiers; it does not promise to remove string
  literals or asset files, and its presence cannot be inferred from an APK
  filename or from "obfuscated-looking" symbols.

This fixture makes **no claim that any scanner detects these facts**. That is
the benchmark's job, with independent gold expectations. It performs no network
operation: no network call, request, or socket is opened.

## Layout

```text
benchmark-app/
  pubspec.yaml
  lib/main.dart
  assets/test.env
  android/…                                  # minimal Flutter Android host
    app/src/main/AndroidManifest.xml
    app/src/main/res/xml/network_security_config.xml
    app/src/main/kotlin/dev/flutterguard/benchmark_app/
      MainActivity.kt
      BenchmarkExportedActivity.kt
  test_fixture.py                            # static oracle for the facts above
  README.md
```

## Static check

```bash
python3 benchmark-app/test_fixture.py
```

It must pass. It reads source only: no build, scan, network, or package install.

## Reproducing the Android host

The host was generated with the cached SDK, not by fetching a new template:

```bash
flutter create --offline --empty --platforms=android \
  --org dev.flutterguard --project-name benchmark_app \
  --description "Synthetic FlutterGuard benchmark fixture (unsafe, local-only)" \
  /tmp/benchmark-app-template
```

Then the extra files above were added and the generated debug/profile manifests
(which contain `INTERNET` only for Flutter tooling) were removed. Do not re-run
`flutter create` into this directory; it overwrites custom files.

## Offline build recipe

Versions used to produce this recipe (no APK was built by the fixture author):

| Tool | Version |
|---|---|
| Flutter | 3.44.2 stable, framework `c9a6c48423` |
| Dart | 3.12.2 |
| Engine | `04efd7c093d4e9281d5526ebcad6ecc60ba8badf` (revision `77e2e94772`) |
| Template revision | `c9a6c484230f8b5e408ec57be1ef71dee1e77020` |
| Android Gradle Plugin | 9.0.1 |
| Gradle | 9.1.0 |
| Kotlin | 2.3.20 |
| Application ID / version | `dev.flutterguard.benchmark_app` / `0.1.0+1` |
| ABI | `android-arm64` only |

Run the whole recipe under the parent's single build lock
(`/tmp/opencode/flutterguard-build.lock`). Pub resolves with `--offline`.
Flutter runs with `--config-only --no-pub` to generate local configuration and
the ignored wrapper, not assemble the APK. Each explicit Gradle invocation
then uses `--offline`; dependencies and the pinned wrapper distribution must
already be cached. `--no-pub` alone does not make Gradle offline.

Each variant starts from `flutter clean` so a release build cannot reuse a
previous variant's output. Copies land in `dist/` with distinct names.

```bash
cd benchmark-app
mkdir -p dist

# 1. Debug (JIT), used to compare against AOT output.
DEFINES=$(printf %s 'FG_BENCHMARK_SECRET=fg_benchmark_define_FAKE_2b7e4c91d6a8f035' | base64 | tr -d '\n')
flutter clean
flutter pub get --offline
flutter build apk --debug --config-only --no-pub --target-platform android-arm64 \
  --dart-define=FG_BENCHMARK_SECRET=fg_benchmark_define_FAKE_2b7e4c91d6a8f035
(cd android && ./gradlew --offline assembleDebug -Ptarget-platform=android-arm64 -Ptarget=lib/main.dart -Pbase-application-name=android.app.Application -Pdart-defines="$DEFINES" -Pdart-obfuscation=false -Ptrack-widget-creation=true -Ptree-shake-icons=true)
cp build/app/outputs/flutter-apk/app-debug.apk dist/benchmark-debug.apk

# 2. Plain release (AOT, no Dart obfuscation).
DEFINES=$(printf %s 'FG_BENCHMARK_SECRET=fg_benchmark_define_FAKE_2b7e4c91d6a8f035' | base64 | tr -d '\n')
flutter clean
flutter pub get --offline
flutter build apk --release --config-only --no-pub --target-platform android-arm64 \
  --dart-define=FG_BENCHMARK_SECRET=fg_benchmark_define_FAKE_2b7e4c91d6a8f035
(cd android && ./gradlew --offline assembleRelease -Ptarget-platform=android-arm64 -Ptarget=lib/main.dart -Pbase-application-name=android.app.Application -Pdart-defines="$DEFINES" -Pdart-obfuscation=false -Ptrack-widget-creation=false -Ptree-shake-icons=true)
cp build/app/outputs/flutter-apk/app-release.apk dist/benchmark-plain-release.apk

# 3. Obfuscated release (AOT, identifiers renamed).
DEFINES=$(printf %s 'FG_BENCHMARK_SECRET=fg_benchmark_define_FAKE_2b7e4c91d6a8f035' | base64 | tr -d '\n')
flutter clean
flutter pub get --offline
flutter build apk --release --config-only --no-pub --target-platform android-arm64 \
  --dart-define=FG_BENCHMARK_SECRET=fg_benchmark_define_FAKE_2b7e4c91d6a8f035 \
  --obfuscate --split-debug-info=dist/obfuscation-symbols
(cd android && ./gradlew --offline assembleRelease -Ptarget-platform=android-arm64 -Ptarget=lib/main.dart -Pbase-application-name=android.app.Application -Pdart-defines="$DEFINES" -Pdart-obfuscation=true -Psplit-debug-info="$PWD/../dist/obfuscation-symbols" -Ptrack-widget-creation=false -Ptree-shake-icons=true)
cp build/app/outputs/flutter-apk/app-release.apk dist/benchmark-obfuscated-release.apk
```

After building, record for each artifact: absolute path, SHA-256, byte size,
build timestamp, and the command used. The obfuscation symbol maps under
`dist/obfuscation-symbols/` are build by-products and are ignored by git; keep
them with any local evaluation run because they map obfuscated Dart names back
to source identifiers.

### Signing

These are **not production-signed**. The Flutter CLI expects a signed APK, so
the generated release build uses the local Android debug keystore. No release
keystore, `key.properties`, password, or signer configuration is checked in.
These APKs are debug-key-signed test inputs for local analysis only, never
user-distributable production builds.

### Offline limitations

- The first template generation was run with `--offline`; it succeeded from the
  local pub cache.
- `flutter pub get --offline` fails loudly if the cache is incomplete.
- With a cached wrapper distribution, Gradle `--offline` rejects missing
  Gradle/AGP/Kotlin dependencies instead of fetching replacements.
- `flutter clean` between variants increases build time but prevents plain and
  obfuscated release outputs from overwriting each other in `build/`.
- Builds are Android-only and arm64-only by design. No iOS, web, or desktop
  targets exist.
- The generated debug/profile manifests were removed with their `INTERNET`
  permission. The debug APK still builds and scans, but `flutter run`, hot
  reload, and the VM service may not attach. That is intentional: this fixture
  is for static analysis, not interactive development.
