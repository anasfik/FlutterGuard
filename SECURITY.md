# Security Policy

FlutterGuard helps agents review Flutter Android APK/AAB artifacts for release security risks.

## Reporting Vulnerabilities

Please report security issues privately to the maintainers before opening a public issue. Include:

- affected version or commit
- reproduction steps
- expected impact
- affected files or artifact evidence when safe to share

Do not include real production secrets, signing keys, customer data, or private APK/AAB files in public issues.

## Safety Philosophy

FlutterGuard should not blindly auto-fix sensitive production behavior. Authentication, payments, signing, dependency changes, permissions, publishing configuration, production environment config, API key migration, and privacy/data behavior require human approval.
