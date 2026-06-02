# FlutterGuard APK Security Report

Artifact: `build/app/outputs/flutter-apk/app-release.apk`
Flutter Evidence: confirmed
Status: RISKY
Score: 76/100

Critical:
- None found from available evidence.

High Risk:
- WebView JavaScript bridge is visible in decompiled wrapper code.
  Evidence: `sources/com/example/app/MainActivity.java` references `addJavascriptInterface`.
  Why it matters: JavaScript bridges can expose native functionality if untrusted content reaches the WebView.
  Recommended action: confirm the WebView only loads trusted content and gate any bridge changes behind human approval.

Warnings:
- `ACCESS_FINE_LOCATION` is requested.
  Evidence: `AndroidManifest.xml` uses-permission.
  Recommended action: confirm product justification, runtime prompt copy, privacy policy coverage, and Play Store declaration.
- Staging hostname appears in readable Flutter native strings.
  Evidence: `lib/arm64-v8a/libapp.so` strings, hostname only reported.
  Recommended action: confirm release runtime configuration cannot select this host.

Informational:
- Package: `com.example.reviewapp`
- Version: `1.8.0` / `180`
- Target SDK: 35
- ABIs: `arm64-v8a`, `armeabi-v7a`
- Detected services: Firebase, Sentry, Google Maps
- Method channels: `plugins.flutter.io/google_maps`, `app.example/native_webview`

Recommended Actions:
- Review the WebView bridge and endpoint selection with the app owner.
- Keep the report with release evidence.
- Re-run the review after any permission, WebView, or endpoint changes.

Requires Human Approval:
- WebView bridge changes
- Location permission removal or scope change
- Endpoint migration or rotation strategy
