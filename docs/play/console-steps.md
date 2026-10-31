# Play Console steps for FlutterGuard 0.3.3 (versionCode 8)

0.3.2 (versionCode 7) is submitted and under review. 0.3.3 (versionCode 8) is
the compliance update: R8 minification and resource shrinking, built and
device-verified, ready to upload the moment 0.3.2 is approved. The App content
answers below are unchanged and already filed.

## Already done — do not redo

| Item | State |
| --- | --- |
| Play App Signing | Enrolled, Google-generated app signing key |
| Upload key | `~/motoledger-upload.jks`, alias `motoledger`, cert `7350A257…EBBEB1BF` |
| 0.3.2 (7) AAB | sha256 `51b876c391b3469ebd846ce08f800bd97a50bc7f0d9e2a58698c9eaa3f453e62`, submitted for review |
| 0.3.3 (8) AAB | sha256 `3792f4c638cc0f9c5910843abbde3f49936247fe0f5b00acea7922f993505f8f`, not uploaded yet |
| Internal testing | release 7, **completed** |
| Closed testing (alpha) | release 7, **completed**, 177 countries + rest of world |
| Production | release 7, **completed**, in review |
| Listing | title, 65-char short description, 2955-char full description, icon, feature graphic, 6 screenshots |

Verify any of it with:

```bash
python3 docs/play/upload.py --key <service-account.json> status
```

## 1. App content — Play will not review without these

Publishing overview lists them. Answers that match the shipped build:

| Form | Answer |
| --- | --- |
| Privacy policy | `https://gwhyyy.com/privacy/flutterguard` |
| App access | All functionality available without special access — no login, no account |
| Ads | No ads |
| Content rating questionnaire | Tools; no violence, sex, drugs, gambling, or user-generated content; no user interaction; no location sharing |
| Target audience | 18 and over (a developer tool, not a Families app) |
| Data safety | **No data collected, no data shared** — the app has no `INTERNET` permission, no analytics, no account |
| Government app / financial features / health / news | No to all |
| Category | Tools |
| Tags | Security, Developer tools |

`QUERY_ALL_PACKAGES` declaration — permitted use: device search / security.
Justification to paste:

> FlutterGuard is an on-device security tool. It lists the Flutter apps
> installed on the user's own device so the user can audit them, and it reads
> each app's APK locally to report SDKs, permissions, signing identity and
> embedded secrets. The permission is disclosed on first run and is only used
> after the user agrees; declining keeps the app usable through a
> file-picker path that scans a single APK. The app has no `INTERNET`
> permission, so nothing it reads can leave the device.

Foreground service (`dataSync`) declaration — the scan is local file
processing and reports progress so the user can leave the app mid-scan:

> FlutterGuard runs a short, user-initiated `dataSync` foreground service
> while it audits one APK on the device (30-90 seconds). It shows progress in a
> notification, and cancelling the notification or the button stops the scan.
> No data leaves the device; the app has no network permission.

Demo video — 30-60 s recording, one take is fine:

1. Open FlutterGuard, tap any app in the list.
2. Pull down the notification shade: the progress notification is visible.
3. Press Home, reopen the shade: progress has advanced.
4. Return to the app and press **Cancel scan**: it stops.

## 2. Publish 0.3.3 once 0.3.2 is approved

1. **Publishing overview** — confirm 0.3.2 reads *Approved* / *Published*.
2. Upload the update — either Console (**Production → Create new release →
   Upload → `app/build/outputs/bundle/release/app-release.aab`**) or the API:

   ```bash
   python3 docs/play/upload.py --key <service-account.json> bundle \
       --aab app/build/outputs/bundle/release/app-release.aab \
       --track production --status completed \
       --notes-file docs/play/release-notes-0.3.3.txt
   ```

   The runbook `status` command reports exactly which versionCode each track
   holds, so verify `production: ['8'] completed` afterwards.
3. If Play asks about country selection on the update, keep the countries
   0.3.2 already has; the API rejects new `countryTargeting` on a `completed`
   release (table in section 3).
4. **Upload the R8 mapping file** with the release — Android Studio, or
   *Release → App bundle explorer → mapping file*. Without it Play reports
   obfuscated stack traces and a crash cannot be attributed to a line.

## 3. Why the first production release has to be made in Console

All five ways the API can express "publish to production" were tried against
`com.flutterguard.app`; every one is rejected, and the rejections are
contradictory by design:

| Attempt | Google's response |
| --- | --- |
| `status: completed`, no countries | `Release in track targeting no countries` |
| `status: completed` + `countryTargeting` | `Country targeting is only supported for staged releases` |
| `status: inProgress` (staged), no countries | `The first release on a track cannot be staged` |
| `status: inProgress`, `userFraction: 1.0` | `User fraction must be ... lower than one` |
| `PUT /edits/{id}/countryAvailability/production` | 404, method does not exist |

So: the first release on a track must be `completed`, `completed` must have
countries, and countries only exist on staged releases. Only the Console
wizard sets countries for a non-staged first release.

Everything else is API-driven: internal (0.3.2/7, completed), closed testing
alpha (0.3.2/7, completed, 177 countries + rest of world), the bundle, the
listing and the images.

After that first production release is published, later rollouts and updates
go through `docs/play/upload.py` — bundle upload, track updates, listing text
and images all work once the app is live.

## 4. Facts to keep straight

- **Signing key differs.** Play now signs installs with Google's app signing
  key, not the `7350A257…` upload certificate the GitHub APKs and 33
  sideloaded devices use. Those devices need one uninstall before installing
  from Play; the GitHub APK keeps working as before.
- **The grade is triage, not a verdict.** Static matches are evidence; the
  listing copy and the app both say so. Never describe it as malware
  detection.
- **No network permission** is a shippable fact, not marketing: `aapt2 dump
  permissions` on the release APK lists no `INTERNET`.
