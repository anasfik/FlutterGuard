# Threat Model

FlutterGuard focuses on release risks observable from Flutter Android APK/AAB artifacts.

## Artifact Inspection Limits

Mobile artifacts are inspectable, but APK/AAB review is not the same as source-code review. Decompiled Java/Kotlin/smali and extracted strings are evidence, not complete application source.

Flutter app logic is usually compiled into native snapshots inside `libapp.so`. Agents may inspect readable strings and native library metadata, but must not claim full Dart source recovery from artifact inspection alone.

## Android Manifest Risks

- cleartext traffic
- dangerous permissions without justification
- exported components without protection
- deep links that expose auth, account, payment, or password-reset flows
- debug flags in release context
- broad backup or data extraction behavior
- weak providers, receivers, services, or activity intent filters

## Hardcoded Secrets

Privileged backend tokens, payment secrets, signing material, private keys, and private credentials must not be shipped in resources, assets, Flutter assets, wrapper code, or readable native strings.

Reports must redact secret values and include only enough evidence for a human to locate and assess the issue.

## Network And WebView Risk

Agents should inspect cleartext settings, network security config, backend hostnames, staging endpoints, certificate trust signals, WebView flags, JavaScript bridges, file access, and mixed-content behavior.

Certificate pinning is context-dependent. Missing pinning is usually informational unless the app handles high-risk financial, medical, enterprise, or credential-heavy workflows and the user's threat model requires it.

## Signing And Release Risk

Unsigned artifacts, failed APK signature verification, debug certificates, expired certificates, or weak algorithms reported by tooling can block release.

Signing changes require human approval. FlutterGuard reports evidence and recommended action; it does not silently resign, rebuild, or alter publishing configuration.

## Unsafe Auto-Fixes

FlutterGuard should not silently change auth, payments, permissions, signing, dependency graph, publishing config, production environment config, API key migration, or privacy/data behavior.

## Human Approval Boundaries

When a finding affects production behavior, external obligations, user privacy, credentials, signing, publishing, auth, or payments, report evidence and ask for approval before editing.
