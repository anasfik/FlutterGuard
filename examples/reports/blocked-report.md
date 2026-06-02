# FlutterGuard APK Security Report

Artifact: `build/app/outputs/flutter-apk/app-release.apk`
Flutter Evidence: confirmed
Status: UNSAFE
Score: 28/100

Critical:
- Cleartext traffic is globally enabled.
  Evidence: decompiled `AndroidManifest.xml` application node has `android:usesCleartextTraffic="true"`.
  Recommended action: disable cleartext traffic or document a temporary exception after human approval.
- Privileged token-like value is embedded in release assets.
  Evidence: `assets/flutter_assets/assets/config/prod.json`, value redacted.
  Recommended action: rotate the exposed credential and migrate to a backend-mediated strategy after human approval.
- APK signature verification failed.
  Evidence: `apksigner verify --print-certs app-release.apk` returned a verification failure.
  Recommended action: rebuild and sign with the approved release signing process.

High Risk:
- Exported receiver has an intent filter and no visible permission protection.
  Evidence: decompiled `AndroidManifest.xml` receiver node.

Warnings:
- `ACCESS_FINE_LOCATION` is requested and requires privacy/declaration review.
- `lib/arm64-v8a/libapp.so`: localhost and QA hostnames appear in readable strings.

Informational:
- Package: `com.example.blockedapp`
- Target SDK: 35
- ABIs: `arm64-v8a`, `armeabi-v7a`
- Detected services: Firebase, Sentry, Stripe

Recommended Actions:
- Treat this artifact as not releasable.
- Rotate exposed credentials before publishing any fixed build.
- Re-run APK security review after rebuilding and signing.

Requires Human Approval:
- Credential rotation and migration strategy
- Signing configuration
- Permission and exported component changes
