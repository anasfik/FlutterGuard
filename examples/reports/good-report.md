# FlutterGuard APK Security Report

Artifact: `build/app/outputs/flutter-apk/app-release.apk`
Flutter Evidence: confirmed
Status: SAFE
Score: 93/100

Critical:
- None found from available evidence.

High Risk:
- None found from available evidence.

Warnings:
- `lib/arm64-v8a/libapp.so`: staging hostname appears in readable strings, but no active production route was confirmed from available evidence.

Informational:
- Package: `com.example.safeapp`
- Version: `2.4.1` / `241`
- Target SDK: 35
- ABIs: `arm64-v8a`, `armeabi-v7a`
- Detected services: Firebase, Sentry
- Method channels: `app.example/native_config`

Recommended Actions:
- Confirm the staging hostname cannot be selected in production runtime configuration.
- Keep the APK inspection report with release notes.

Requires Human Approval:
- None.
