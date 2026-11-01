# Play Console steps for FlutterGuard 0.3.3 (versionCode 8)

On 2026-11-01 the release-lifecycle API confirmed 0.3.2 (versionCode 7) is
`IN_REVIEW` on production; alpha and internal are `PUBLISHED`. Production's
track configuration is `completed`, which does not itself prove approval.
The public listing returned HTTP 404 in the US, UK and France.

0.3.3 (versionCode 8) adds R8 minification and resource shrinking. The same
artifact was smoke-tested on a physical device before it was disconnected;
no new device test is claimed. Fresh unit tests and release lint pass. Leave
the pending first release unchanged while Google reviews it.

## Already done — do not redo

| Item | State |
| --- | --- |
| Play App Signing | Enrolled, Google-generated app signing key |
| Upload key | `~/motoledger-upload.jks`, alias `motoledger`, cert `7350A257…EBBEB1BF` |
| 0.3.2 (7) AAB | sha256 `51b876c391b3469ebd846ce08f800bd97a50bc7f0d9e2a58698c9eaa3f453e62`, submitted for review |
| 0.3.3 (8) AAB | sha256 `3792f4c638cc0f9c5910843abbde3f49936247fe0f5b00acea7922f993505f8f`, not uploaded yet |
| Internal testing | release 7, lifecycle **PUBLISHED** |
| Closed testing (alpha) | release 7, lifecycle **PUBLISHED**, 177 countries + rest of world |
| Production | release 7, lifecycle **IN_REVIEW**, not yet approved |
| Listing | title, 65-char short description, 2955-char full description, icon, feature graphic, 6 screenshots |

The local full description and 0.3.3 release notes have been revised for the
next submission. They remove unmeasured startup/memory claims, qualify scan
duration, and clarify explicit exports. They have not replaced the current
Play listing. Do not infer a memory-vitals fix from a smaller APK.

Verify any of it with:

```bash
python3 docs/play/upload.py --key <service-account.json> status
```

The command prints track configuration and `releaseLifecycleState` separately,
using `applications.tracks.releases.list` for the latter. It abandons its
temporary read edit without committing. Every mutating command commits with
`changesInReviewBehavior=ERROR_IF_IN_REVIEW`: a pending review produces
`CHANGES_ALREADY_IN_REVIEW`, not an automatic cancellation and resubmission.
Do not remove that guard or retry with the API's cancel-and-submit default.
Offline regression check: `python3 docs/play/test_upload.py`.

If a commit returns `CHANGES_ALREADY_IN_REVIEW`, nothing from that edit was
published; its upload remains uncommitted, and the CLI does not persist the
edit ID. Wait for production to be `PUBLISHED`, run `status`, then rerun
`bundle` if version 8 is absent rather than trying to promote a missing bundle.

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

`QUERY_ALL_PACKAGES` declaration — explain why installed-app enumeration is
core to this offline APK auditor. Permission approval is Google's judgement,
not guaranteed by classifying an app as a security tool. High-risk permission
review can take several weeks; check App content and Policy status for any
required action. Justification to paste:

> FlutterGuard is an on-device security tool. It lists the Flutter apps
> installed on the user's own device so the user can audit them, and it reads
> each app's APK locally to report SDKs, permissions, signing identity and
> embedded secrets. The permission is disclosed on first run and is only used
> after the user agrees; declining keeps the app usable through a
> file-picker path that scans a single APK. The app has no `INTERNET`
> permission and does not automatically upload scan data. Exporting or sharing
> a report requires an explicit user action.

Foreground service (`dataSync`) declaration — the scan is local file
processing and reports progress so the user can leave the app mid-scan:

> FlutterGuard runs a user-initiated `dataSync` foreground service
> while it audits one APK on the device. Scan duration depends on APK size and
> the device. It shows progress in a
> notification, and cancelling the notification or the button stops the scan.
> Scanning is local; the app has no network permission or automatic uploads.

Demo video — show the user-initiated work, progress and cancellation. Confirm
the submitted URL is accessible to reviewers without an account:

1. Accept installed-app scanning, then explicitly start a new scan of an app
   rather than opening an existing report.
2. Pull down the notification shade: the progress notification is visible.
3. Press Home, reopen the shade: progress has advanced.
4. Return to the app and press **Cancel scan**: it stops.

## 2. Publish 0.3.3 once 0.3.2 is approved

1. Run `status` and cross-check **Publishing overview**, **Policy status**,
   App content declarations and production countries. If `IN_REVIEW`, wait;
   if `NOT_APPROVED`, address Google's stated reason; if
   `NOT_SENT_FOR_REVIEW`, resolve the required Console action; if
   `APPROVED_NOT_PUBLISHED`, follow the Console publishing action and wait for
   `PUBLISHED`. Do not repeatedly resubmit an unchanged release. Managed
   publishing is unavailable for an app's first publication; later updates
   can use it once the app is live.
2. Once the first production release is approved and published, upload the
   exact checked AAB to **internal testing** first:

   ```bash
   python3 docs/play/upload.py --key <service-account.json> bundle \
       --aab app/build/outputs/bundle/release/app-release.aab \
       --track internal --status completed \
       --notes-file docs/play/release-notes-0.3.3.txt
   ```

   Verify version 8's lifecycle reaches `PUBLISHED` on internal with `status`.
   `completed` alone is not enough. Review Play's
   pre-launch results and, when a test device is available, check a Play-signed
   install: consent/decline, picked APK, installed scan, cancel, background and
   reopen, report, masked secrets, export, and history. Android 15/16 timeout
   behavior and a fresh Play-installed device pass remain untested here.
3. After internal checks pass, promote the existing bundle to a staged
   production update rather than uploading the same versionCode again:

   ```bash
   python3 docs/play/upload.py --key <service-account.json> promote \
       --track production --versions 8 --status inProgress --fraction 0.1 \
       --notes-file docs/play/release-notes-0.3.3.txt
   ```

   Keep existing production countries; do not use `--all-countries` for this
   update. Staging requires an existing production release. Review approval
   and publishing controls still apply after the API commit.
4. After the update is approved and its staged release is published, check
   actual store availability, Android vitals, crashes/ANRs and scan errors.
   If healthy, use `promote --versions 8 --status completed` with the same
   notes to finish rollout; verify the resulting review/publishing lifecycle
   again. Halt the staged release in Console if a regression appears; do not
   try to downgrade to versionCode 7.

## 3. Historical first-release country setup errors

Before production countries were configured, these attempts against
`com.flutterguard.app` failed. These are historical errors, not proof that
the API cannot submit a first release:

| Attempt | Google's response |
| --- | --- |
| `status: completed`, no countries | `Release in track targeting no countries` |
| `status: completed` + `countryTargeting` | `Country targeting is only supported for staged releases` |
| `status: inProgress` (staged), no countries | `The first release on a track cannot be staged` |
| `status: inProgress`, `userFraction: 1.0` | `User fraction must be ... lower than one` |
| `PUT /edits/{id}/countryAvailability/production` | 404, method does not exist |

After the Console country setup, the API successfully committed versionCode
7 to production as `completed`. Country availability and per-release staged
country targeting are different controls. This commit did not establish
review approval or public availability.

Everything else is API-driven: internal (0.3.2/7, completed), closed testing
alpha (0.3.2/7, completed, 177 countries + rest of world), the bundle, the
listing and the images.

After that first production release is published, later rollouts and updates
go through `docs/play/upload.py` — bundle upload, track updates, listing text
and images all work once the app is live.

## 4. Facts to keep straight

- **Signing key differs.** Play signs installs with Google's app signing key,
  not the `7350A257…` upload certificate used by the GitHub APK. Switching
  requires uninstalling the differently signed build. Uninstalling deletes
  local reports, history and settings; export anything needed first. Exports
  do not restore in-app history. The GitHub APK remains available.
- **The grade is triage, not a verdict.** Static matches are evidence; the
  listing copy and the app both say so. Never describe it as malware
  detection.
- **No network permission** is a shippable fact, not marketing: `aapt2 dump
  permissions` on the release APK lists no `INTERNET`.
- **No measured startup or memory improvement.** Reduced APK/DEX size is
  verified; Android vitals and startup timings have not been measured here.
- **R8 thresholds are upcoming.** Google's February 2027 requirement has
  separate optimization, obfuscation and shrinking floors of 25% for apps
  with more than 10 MB DEX. Inspect the uploaded bundle's actual Play metrics;
  enabling R8 alone does not prove those percentages.
- **AAB mappings are automatic.** With AGP 4.1+, Play extracts the R8 mapping
  from the app bundle. Check the exact AAB contains
  `BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map`; retain
  its matching `app/build/outputs/mapping/release/mapping.txt` for offline
  ReTrace. Do not require a separate mapping upload for this AAB workflow.
- **Target API and native code.** Target SDK 36 meets the current submission
  requirement. This build includes AndroidX's `libandroidx.graphics.path.so`
  for four ABIs, so it is not native-library-free. All four ELF binaries are
  16 KB LOAD-aligned, match between APK and AAB, and are uncompressed in the
  APK; `zipalign -c -P 16 4 app-release.apk` passes. Runtime testing on a
  16 KB device remains separate from these artifact checks.

## 5. Official references

- [Release lifecycle](https://developers.google.com/android-publisher/api-ref/rest/v3/applications.tracks.releases/list)
  and [safe commit behavior](https://developers.google.com/android-publisher/api-ref/rest/v3/edits/commit).
- [Review timing and managed publishing](https://support.google.com/googleplay/android-developer/answer/9859654).
- [Package visibility policy](https://support.google.com/googleplay/android-developer/answer/10158779)
  and [permission declaration review](https://support.google.com/googleplay/android-developer/answer/9214102).
- [Foreground-service declarations](https://support.google.com/googleplay/android-developer/answer/13392821)
  and [Android 15+ service timeouts](https://developer.android.com/develop/background-work/services/fgs/timeout).
- [Target API requirements](https://support.google.com/googleplay/android-developer/answer/11926878),
  [16 KB compatibility](https://developer.android.com/guide/practices/page-sizes),
  [AAB mapping extraction](https://support.google.com/googleplay/android-developer/answer/9848633),
  and [upcoming DEX requirements](https://support.google.com/googleplay/android-developer/answer/17492799).
