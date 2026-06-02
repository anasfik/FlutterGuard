# FlutterGuard APK Security Report

Artifact: `build/app/outputs/flutter-apk/app-release.apk`
Flutter Evidence: confirmed
Status: RISKY
Score: 72/100

Critical:
- None found from available evidence.

High Risk:
- `android:allowBackup="true"` is present for an app that appears to handle user account data.
  Evidence: decompiled `AndroidManifest.xml` application node.
  Recommended action: review backup/data extraction behavior and disable or constrain it after human approval.

Warnings:
- `ACCESS_FINE_LOCATION` is requested.
  Evidence: `AndroidManifest.xml` uses-permission.
  Recommended action: confirm product justification, runtime prompt copy, privacy policy coverage, and Play Store declaration.
- `lib/arm64-v8a/libapp.so`: `staging-api.example.com` appears in readable strings.
  Recommended action: confirm whether this endpoint can be reached in production.

Informational:
- Package: `com.example.locationapp`
- Target SDK: 35
- ABIs: `arm64-v8a`
- Detected services: Firebase, Google Maps
- Method channels: `plugins.flutter.io/google_maps`, `app.example/location_bridge`

Recommended Actions:
- Get human approval for any backup or permission changes.
- Verify production endpoint selection in the app's release environment.

Requires Human Approval:
- Backup behavior change
- Location permission removal or scope change
- Endpoint migration or rotation strategy
