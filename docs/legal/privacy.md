# FlutterGuard privacy policy

Effective date: 2026-10-30
Policy version: 1

FlutterGuard is an offline static-analysis tool for Android applications, with a
focus on Flutter artifacts. This policy describes exactly what the app reads,
what it stores, and what it never does.

## Summary

- FlutterGuard has no network permission. It cannot send anything anywhere.
- No accounts, no telemetry, no analytics, no advertising, no crash reporting.
- Reports stay in FlutterGuard's own app-specific storage until you delete them.
- Files leave the app only when you explicitly export and choose a destination.

## What the app reads

With your consent, FlutterGuard lists installed applications through Android's
package manager. The `QUERY_ALL_PACKAGES` permission exists solely so the app can
offer installed Android apps for an audit. For an app you choose to scan, it
reads the APK files Android exposes for that app (the base APK and its split
APKs) and parses them on the device: the manifest, resources, DEX string tables,
native libraries, bundled assets, and signing information. No application code
is executed.

If you decline broad package visibility, or if the permission is unavailable,
you can still audit an APK you pick with the system file picker, or share an APK
to FlutterGuard from another app such as Files. In that mode FlutterGuard reads
only the file you supplied and copies it to its private cache for the duration of
the scan.

## What is collected and transmitted

Nothing is transmitted. FlutterGuard declares no `INTERNET` permission, so the
operating system denies it network access entirely.

The app creates the following data on your device:

- A scan report (JSON) per audited package in its app-specific storage.
- An optional version history log per audited package (`.hist`) used to compare
  scans of different app versions. You can turn this off in Settings.
- Temporary export files in the app cache when you export a report.
- A temporary copy of an imported APK in the app cache, deleted when the scan
  ends.

No usage statistics, device identifiers, installed-app list, or report content
is collected by the maintainer. There is no server component.

## What is shared

Nothing is shared automatically. A report leaves the device only when you press
Export and then choose a destination app in Android's share sheet. The export is
delivered through a non-exported `FileProvider` that grants read access to the
single file for that one share. Other apps cannot browse FlutterGuard's storage.

Exports are redacted by default. Values that look like credentials are replaced
with a length-only mask such as `[32 chars hidden]`. Writing raw values into an
export requires an explicit raw-value opt-in and confirmation for that one file,
and the option can be disabled entirely in Settings.

## Secret handling

Detected secrets are masked in the UI by default. Revealing a value is an
explicit per-item action; while a value is revealed the screen is marked secure
so it is excluded from screenshots and the recents preview. Raw values exist only
in the memory of the scanning process: they are not written to reports, history,
exports, or logs, and they disappear when the process ends.

## Scan execution

Scans run in a foreground service with a progress notification, so leaving the
app does not silently cancel or duplicate work. Notification permission is
optional: without it the scan still runs, but Android hides its progress and
result notifications.

## Retention and deletion

Reports and history remain on the device until you delete them.

- Settings → Delete all reports removes every stored report, history log, and
  interrupted-scan marker.
- Uninstalling FlutterGuard removes its app-specific storage, including reports.
- Exported files are owned by the app you shared them with and must be deleted
  there.

## Permissions

- `QUERY_ALL_PACKAGES`: list installed apps so you can choose one to audit.
- `FOREGROUND_SERVICE` and `FOREGROUND_SERVICE_DATA_SYNC`: run a scan reliably
  while you use another app.
- `POST_NOTIFICATIONS` (Android 13+): show scan progress and result
  notifications. Optional.

FlutterGuard requests no storage, location, contacts, camera, microphone, or
network permission.

## Children

FlutterGuard is a developer and researcher tool. It is not directed at children
and collects no personal information from anyone.

## Changes

Material changes to this policy bump the policy version shown at the top. When
the stored consent is older than the current version, FlutterGuard shows the
disclosure again before reading the installed-app list.

## Contact

FlutterGuard is maintained in the open at
https://github.com/anasfik/FlutterGuard. Questions or corrections can be raised
as an issue there, or sent by email to work@gwhyyy.com.

The developer address for privacy requests and store listings is
work@gwhyyy.com.
