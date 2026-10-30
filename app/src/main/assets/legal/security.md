# FlutterGuard security model

Effective date: 2026-10-30

FlutterGuard performs static analysis of Android APK artifacts on the device. It
is a reading tool: it does not run, install, modify, or attack the applications
it inspects. This document describes the boundaries it enforces and the limits
you should assume.

## Network boundary

The app declares no `INTERNET` permission. Without it the Android kernel denies
socket creation to the app process, so no scanner result, report content, or
secret can leave the device through FlutterGuard itself.

External documentation links open in another app only after an explicit tap. The
destination app has its own permissions and privacy policy; FlutterGuard only
hands it a URL.

## What is read

- Android's package manager metadata for installed applications (with your
  consent), including labels, versions, SDK levels, and signing certificates.
- The APK files the OS exposes for an app you choose: base APK and split APKs.
- The APK you pick or share in file mode, and nothing else.

Static parsers read the manifest, resources, DEX string tables, native library
strings, archive entries, and signing blocks. Parsing is bounded: previews are
capped, oversized entries are skipped, entry names are validated, and no archive
path is ever extracted to the filesystem or executed.

## What is never done

- No network request of any kind: no telemetry, analytics, ads, or crash upload.
- No dynamic analysis, instrumentation, or code execution of the scanned app.
- No modification of the scanned APK or of the app it belongs to.
- No background collection: a scan runs only when you start it or grant a
  scripted request you invoked yourself.
- No raw secrets in reports, exports, history, notifications, or logs.

## Secret handling

Findings that look like credentials are masked by default. A mask reveals only
the length, never characters. Revealing a value is an explicit action, is
restricted to the current visit, and marks the window secure for screenshots
(`FLAG_SECURE`) while the value is visible.

Raw values are retained only in the memory of the scanning process. They are not
serialized: a report reopened from disk can show its masked evidence but not the
original value. To reveal values again, rescan the app.

Exports are redacted by default. Raw values are written only when you confirm the
sensitive option for that specific file; turning the setting off removes the
option entirely.

## Storage and sharing

- Reports and history live in the app's own storage directory. Android gives
  other apps no general access to it, and removing FlutterGuard removes it.
- Exports are written to the app cache and handed to the share sheet through a
  `FileProvider` declared `exported="false"` with per-URI read grants.
- Imported APKs are copied into the app cache for the duration of the scan and
  deleted afterwards.

Anyone who can read the device's storage with root, debug access, or a backup
mechanism can read stored reports. FlutterGuard disables Android backup for its
data, but it cannot defend against a compromised device or a rooted OS.

## Permission set

- `QUERY_ALL_PACKAGES`: broad package visibility, requested so installed apps
  can be listed for auditing. It is an optimisation for convenience, not a
  requirement: file-pick and share-import scans work without it.
- `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`: a foreground service
  owns the single running scan and shows honest progress.
- `POST_NOTIFICATIONS`: optional progress and result notifications.

There is no storage, location, contacts, camera, microphone, or network
permission in the manifest.

## Known limitations

- Static matches are evidence and hypotheses, not proof of exploitability.
- Obfuscation, packing, and encrypted payloads can hide behavior from static
  analysis.
- A ROM or device policy that blocks reading another app's APK makes installed-app
  scans fail visibly; the file-pick path remains available.
- Dynamic configuration, server-supplied endpoints, and runtime-generated keys
  are not observable from the artifact alone.

## Reporting a vulnerability in FlutterGuard

Report security issues privately through the project repository at
https://github.com/anasfik/FlutterGuard. Include the affected version, steps to
reproduce, and the impact you observed. Please do not include real credentials
or third-party user data in a report.
