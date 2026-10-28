# Security Policy

FlutterGuard helps agents review Flutter Android APK/AAB artifacts for release security risks. It ships two things: the agent workflow in `skill/SKILL.md` and the companion Android app in `app/`.

## Reporting Vulnerabilities

Please report security issues privately to the maintainers before opening a public issue. Include:

- affected version or commit
- reproduction steps
- expected impact
- affected files or artifact evidence when safe to share

Do not include real production secrets, signing keys, customer data, or private APK/AAB files in public issues.

## The Android App

- The app declares exactly one permission, `android.permission.QUERY_ALL_PACKAGES`, so it can enumerate installed applications.
- It has no `INTERNET` permission and makes no network requests. All parsing, decoding and rule evaluation happen in the app process.
- It reads only what the OS already exposes to any app: the `base.apk` and split APKs of installed packages, plus package metadata.
- `android:allowBackup="false"` is set, so app-private data is not included in cloud or adb backups.
- Reports live in app-specific external storage (`Android/data/com.flutterguard.app/files/reports/`), private to the app on Android 11+ but deliberately `adb pull`-able for headless/CI use (the release build is not debuggable) and are only exposed through a non-exported `FileProvider` scoped to `cache/exports/`, when the user picks "Share JSON" or "Share Markdown". Nothing leaves the device unless the user shares it.
- The headless mode (`-e scan <package>`) writes the same report and logs only its path (`FG_REPORT <path>`), not report contents.

## Report Contents

Treat exports as sensitive. The app is not a secrets manager:

- Dotenv credential values and the `google-services.json` API key are partially
  redacted through `Evidence.redact` (first/last characters kept).
- Findings produced by the string scanner embed the matched value inside a short context snippet, because that snippet is the evidence. Those exports can therefore contain live-looking key material.

Redact before pasting a report into a public issue, and rotate anything the report proves was shipped.

## Safety Philosophy

FlutterGuard should not blindly auto-fix sensitive production behavior. Authentication, payments, signing, dependency changes, permissions, publishing configuration, production environment config, API key migration, and privacy/data behavior require human approval.
