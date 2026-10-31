# Play Console steps for FlutterGuard 0.3.2 (versionCode 7)

Everything here is the part the Android Publisher API cannot do. The API is
already wired up: service account `reqistry-fastlane@reqistry-play-deployment.iam.gserviceaccount.com`
can open edits on `com.flutterguard.app` (tracks: internal, alpha, beta, production).

## 1. App signing

**Test and release → Setup → App signing** → *Use Play App Signing*, and upload
`~/motoledger-upload.jks` as the **upload key** (alias `motoledger`).

The certificate must stay

```
SHA-256 7350A257DF573946D83C1DFEB1124C3E35E8CA59EB175972300B2600EBBEB1BF
```

because that is the key the already-sideloaded installs trust: same key means
FlutterGuard keeps updating in place, and reports on disk stay readable.
Play App Signing re-signs downloads with Google's key, which is fine — only the
upload key has to match.

## 2. App content (required before any release leaves draft)

| Section | Answer |
|---|---|
| Privacy policy | `https://gwhyyy.com/privacy/flutterguard` (security appendix: `…/flutterguard/security`) |
| App access | All functionality available without credentials |
| Ads | No ads |
| Content rating | Questionnaire: Utility / Security. No violence, no user content, no sharing, no purchases |
| Target audience | 18+ (developer tool), not designed for children |
| Data safety | **No data collected, no data shared.** Everything is read and reported on-device; the app holds no INTERNET permission |
| Government apps | No |
| Financial features | None |
| Health | None |

**Permissions declaration → `QUERY_ALL_PACKAGES`.** Justification, which matches
the in-app first-run disclosure and code:

> FlutterGuard's single purpose is auditing the Flutter apps already installed on
> the user's device: it reads each app's manifest, signing certificate, native
> libraries, embedded strings and network rules, and produces a local security
> report. Without package visibility the app cannot enumerate what to audit, which
> is its core disclosed function (Google Play's "device search" / "security"
> permitted use). Every installed-app scan is gated behind a first-run disclosure
> and a Settings toggle; the user can also audit a single APK through the system
> file picker without this permission. No app inventory leaves the device — the
> app has no INTERNET permission.

**Foreground service declaration → type `dataSync`.** targetSdk 36 rejects the
upload without it.

- Task: "Reads the APK files of installed apps on the device and scans them for
  embedded SDKs, endpoints, secrets and manifest weaknesses. The work is local
  file I/O and string matching; there is no network access."
- Why a foreground service: a scan of one app takes 30–90 s and "Scan all" runs
  33 apps back to back. It must survive the screen turning off or the user leaving
  the app, must show progress, and must stay cancellable. WorkManager cannot give
  either the live progress or the immediate cancel.
- Video (30–60 s, one take is fine):
  1. Open FlutterGuard, tap a Flutter app.
  2. Pull down the notification shade — the progress notification is there with a
     percentage and the current stage.
  3. Press Home, wait a few seconds, reopen the shade — the percentage advanced.
  4. Reopen the app, tap **Cancel scan** — the scan stops and the notification
     disappears.

## 3. Upload

```sh
export PLAY_SA_JSON=~/drive-backup-ffikhi/reqistry-play-deployment-f666e85817ff.json
cd docs/play
./upload.py listing --short "Offline security audit for the Flutter apps on your phone." \
                    --full-file full-description.txt
./upload.py images  --type phoneScreenshots --files screenshots/*.png
./upload.py images  --type icon            --files icon-512.png
./upload.py images  --type featureGraphic  --files feature-1024x500.png
./upload.py bundle --aab ../app/build/outputs/bundle/release/app-release.aab \
                   --track internal --status completed \
                   --notes-file release-notes-0.3.2.txt
```

Start on **internal**, install from the Play link on the test device, then promote
to closed testing. Production only after the internal install has been opened once
and a scan has run.

## 4. Facts to keep straight while filling forms

- No network: the release APK declares `QUERY_ALL_PACKAGES`, `FOREGROUND_SERVICE`,
  `FOREGROUND_SERVICE_DATA_SYNC`, `POST_NOTIFICATIONS` and nothing else.
- Reports are stored in internal app storage (`files/reports/<package>.json`) and
  leave only through Share, on an explicit tap.
- Secrets found in an APK are masked by default; revealing one is per-item and
  blocks screenshots (`FLAG_SECURE`).
- The app does not train models, does not upload samples, has no accounts.
