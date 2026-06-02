---
name: flutter-apk-security
description: Review Flutter Android APK/AAB release artifacts for manifest, permission, cleartext traffic, exported component, embedded secret, signing, size, WebView, deep link, and third-party service risks.
---

# Flutter APK Security

Use this skill when the user provides an Android APK/AAB, asks whether a Flutter Android release artifact is safe, or asks for review of Android artifact security, permissions, embedded secrets, manifest risks, or release signing signals.

This is an agent workflow, not a standalone scanner. Inspect the artifact and report evidence. Do not silently change a user app's permissions, signing, dependencies, auth, payments, privacy behavior, production environment, publishing config, or API key migration strategy.

## Agent Operating Rules

- Work in a temporary inspection directory outside the target app when possible.
- Preserve the original artifact. Do not modify, rebuild, resign, align, or delete it.
- Prefer read-only commands and local inspection.
- Record exact evidence: file path, manifest node, resource path, package name, certificate subject, permission name, asset path, or extracted string context.
- Redact secrets. Show only a short prefix/suffix or stable identifier when needed.
- Treat decompiled Java/Kotlin/smali as evidence, not as source-of-truth app source. Flutter business logic is usually compiled into native snapshots inside `libapp.so`.
- If the artifact is missing but the user gives a published package name or Play Store listing, use `apkeep` when available to fetch the APK first, then inspect the downloaded artifact.
- If neither an artifact nor a package/listing is available, ask the user for the APK/AAB path or continue with source-level Android review only if the user wants that.

## Obtain A Published APK

If the user wants review of a published app and has not provided an APK/AAB, use [`EFForg/apkeep`](https://github.com/EFForg/apkeep) when available to download the APK, then continue with the normal inspection workflow.

Keep this bounded:

- Only fetch apps the user is authorized to review, or public apps where artifact review is appropriate for the user's stated purpose.
- Do not ask for or store Google account credentials. If Google Play access is needed, ask the user to provide the required email and AAS token for the command, and remind them to use an account where that risk is acceptable.
- Respect app store terms and do not run bulk downloads or high-parallel fetches.
- Record the download source, package name, requested version if any, and resulting APK path in the report.

Safe examples:

```sh
apkeep -a com.example.app .
apkeep -a com.example.app -d apk-pure .
apkeep -a com.example.app -d google-play -e user@example.com -t AAS_TOKEN .
```

If `apkeep` is missing, tell the user and ask them to install it or provide the APK/AAB manually.

## Safe Commands

Use whichever tools exist locally. If a tool is missing, say so and continue with the next best read-only method.

```sh
apkeep -a com.example.app .
file app-release.apk
du -h app-release.apk
unzip -l app-release.apk
jadx -d /tmp/flutterguard-jadx app-release.apk
aapt2 dump badging app-release.apk
aapt2 dump xmltree app-release.apk AndroidManifest.xml
apksigner verify --print-certs app-release.apk
keytool -printcert -jarfile app-release.apk
strings path/to/libapp.so > /tmp/flutterguard-libapp-strings.txt
rg -n "api[_-]?key|secret|token|bearer|private_key|client_secret|AIza|sk_live|pk_live|firebase|sentry|amplitude|mixpanel" /tmp/flutterguard-jadx
```

For AAB files, start with ZIP inspection. If `bundletool` is available and the user approves any generated intermediate output, an agent may build universal APKs for inspection, but this is optional tooling.

```sh
file app-release.aab
du -h app-release.aab
unzip -l app-release.aab
unzip -q app-release.aab -d /tmp/flutterguard-aab
```

## Confirm It Is Flutter

Classify the artifact as Flutter when one or more strong signals exist:

- `assets/flutter_assets/` or `base/assets/flutter_assets/`
- `lib/*/libapp.so`
- `lib/*/libflutter.so`
- Flutter embedding classes such as `io.flutter.embedding.android.FlutterActivity`
- `flutter_assets/AssetManifest.json`, `FontManifest.json`, or `NOTICES.Z`

If Flutter evidence is absent, still perform Android artifact review, but state that Flutter-specific conclusions are not confirmed.

## Inspection Workflow

1. Identify artifact metadata.
   - Package name, version name/code, min/target SDK, app label, file size, ABIs, native libraries.
   - Evidence sources: `aapt2 dump badging`, decompiled `AndroidManifest.xml`, `unzip -l`.

2. Decode or inspect the manifest.
   - Prefer readable manifest from JADX output.
   - If decompilation is incomplete, use `aapt2 dump xmltree`.
   - Capture package, permissions, application flags, activities, services, receivers, providers, intent filters, deep links, metadata, and network security config references.

3. Inspect resources and assets.
   - Review `res/xml/network_security_config.xml`, `res/values/strings.xml`, `assets/`, `flutter_assets/`, JSON/YAML/XML/env/config files, certificates, bundled databases, and web assets.
   - Look for URLs, backend hosts, test/staging endpoints, secrets, excessive media, and unexpected files.

4. Inspect native Flutter strings.
   - Locate every `lib/*/libapp.so`.
   - Use `strings` to look for URLs, keys, tokens, feature flags, environment names, debug markers, private endpoints, and third-party service identifiers.
   - Do not claim full Dart source recovery from `strings`; report only observable strings and risk.

5. Inspect decompiled Android wrapper code.
   - Check `MainActivity`, custom `Application`, plugins, MethodChannel/EventChannel names, WebView usage, file providers, broadcast receivers, and platform code.
   - Extract method-channel names when visible because they identify native attack surface and sensitive bridges.

6. Inspect signing and release signals.
   - Use `apksigner` or `keytool` for APK certificate evidence.
   - Flag debug certificates, expired certificates, weak/old algorithms when reported by tooling, unsigned APKs, failed verification, and missing v2/v3/v4 scheme signals when relevant.
   - Do not infer signing configuration from `AndroidManifest.xml`; signing evidence comes from certificate tooling or source files if the user also provides the app source.

7. Summarize third-party services.
   - Identify obvious Firebase, Google Maps, AWS, Sentry, Stripe, RevenueCat, OneSignal, Supabase, Amplitude, Mixpanel, Facebook, AppsFlyer, or similar service markers.
   - Report only detected evidence and likely review questions. Do not assume misconfiguration without proof.

## Findings To Check

### Critical Blockers

- `android:debuggable="true"` in a release artifact.
- Cleartext traffic globally enabled without a documented release exception.
- Exported activity/service/receiver/provider handling sensitive flows without permission, signature protection, or clear intent-filter justification.
- Hardcoded privileged secrets, private keys, signing material, payment secrets, backend admin tokens, or long-lived bearer tokens.
- Debug or test backend endpoint used as the apparent production endpoint.
- APK signature verification fails, artifact is unsigned, or a debug certificate signs a release artifact.

### High Risk

- Dangerous permissions without a clear product reason: location, camera, microphone, contacts, phone, SMS, calendar, body sensors, storage/media, Bluetooth scan/connect, notification listener, exact alarm.
- Deep links or app links that reach auth, account, checkout, password reset, or payment flows without obvious validation.
- WebView with JavaScript enabled plus broad URL loading, file access, mixed content, or `addJavascriptInterface`.
- `android:allowBackup="true"` or missing backup/data extraction controls for apps handling sensitive data.
- Weak or overly broad `FileProvider` paths.
- Network security config that trusts user/system CAs broadly in release.
- Sensitive data storage signals in shared preferences, SQLite, local files, or cached web assets without visible protection.

### Warnings

- Large unexplained APK/AAB size, unused large assets, duplicate ABIs, or unexpected bundled files.
- Excessive permissions, unused intent filters, or broad queries/package visibility.
- Missing certificate pinning for high-risk financial, medical, enterprise, or credential-heavy apps. Report as context unless the user's threat model requires pinning.
- Staging, localhost, emulator, ngrok, or QA URLs present as strings but not proven active.
- Third-party service keys that are normally public identifiers but still require domain/app restrictions.

### Informational Signals

- Flutter version or embedding hints.
- Detected ABIs and native libraries.
- Detected MethodChannel/EventChannel names.
- Detected service providers and CDN/backend domains.
- Package size and top large assets.

## Evidence Collection Hints

- Permissions: inspect `<uses-permission>` and runtime-sensitive permission groups.
- Exported components: for Android 12+, check explicit `android:exported`; for older targets, intent filters can imply exported behavior.
- Cleartext traffic: inspect `android:usesCleartextTraffic`, referenced network security config, and domain-specific cleartext overrides.
- Deep links: inspect `intent-filter` entries with `VIEW`, `BROWSABLE`, `DEFAULT`, `scheme`, `host`, and `path*`.
- WebView: search for `WebView`, `setJavaScriptEnabled`, `addJavascriptInterface`, `setAllowFileAccess`, `setMixedContentMode`, and channel handlers that pass URLs.
- Storage: search for `SharedPreferences`, `getExternalStorage`, `openFileOutput`, `SQLite`, `Room`, `DataStore`, cache paths, and visible database files.
- Secrets: search assets, resources, decompiled code, and `libapp.so` strings. Distinguish public mobile app identifiers from privileged secrets.
- Services: collect domains and SDK markers before making risk claims.

## Scoring

Start at 100 and subtract:

- 35 for each critical blocker.
- 15 for each high-risk finding.
- 5 for each warning.
- 0 for informational signals.

Clamp score to 0-100.

Status:

- `SAFE`: score 85-100 and no critical blockers.
- `RISKY`: score 60-84 or one unresolved high-risk issue.
- `UNSAFE`: score below 60 or any critical blocker.

Use judgment when a single severe issue should block release even if the numeric score remains high. Explain that decision.

## Human Approval Boundaries

Never auto-edit these areas without explicit approval:

- payment logic
- authentication logic
- signing configuration
- Android permissions
- dependency graph
- publishing configuration
- production environment configuration
- API key migration strategy
- privacy or data collection behavior
- destructive file deletion

Safe automatic work may include generating a Markdown report, adding an audit checklist, suggesting tests, formatting the report, or removing obvious debug output only after the user has approved cleanup.

## Output Format

```text
FlutterGuard APK Security Report

Artifact: path/to/app-release.apk
Flutter Evidence: confirmed | not confirmed | inconclusive
Status: SAFE | RISKY | UNSAFE
Score: 0-100

Critical:
- [severity] Finding title
  Evidence: file/path or command output reference
  Why it matters: concise release risk
  Recommended action: human-approved fix or next check

High Risk:
- ...

Warnings:
- ...

Informational:
- Package: ...
- Version: ...
- Target SDK: ...
- ABIs: ...
- Detected services: ...
- Method channels: ...

Recommended Actions:
- ...

Requires Human Approval:
- ...
```

If no issue is found in a category, write `None found from available evidence.` Do not print full secrets. Redact secret values and report the path, type, and risk.
