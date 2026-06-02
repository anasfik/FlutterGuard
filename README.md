# FlutterGuard

FlutterGuard is an agent-native APK/AAB security review skill for Flutter Android releases.

It is a pure agent skill for Claude Code, Codex, Cursor, OpenClaw, Gemini CLI, and other coding agents. Install or reference the single skill, then ask your agent to inspect a Flutter Android release artifact before shipping.

FlutterGuard is not a CLI. It is not an APK scanner app. It is not a static analyzer. It is one operational agent skill plus safety boundaries for APK/AAB security review.

## Install

Use this repository directly with any agent platform that supports local skills, instruction packs, or project-level agent guidance. The skill entrypoint is the root `SKILL.md`.

Recommended install:

- `SKILL.md`

Then ask:

```text
Use FlutterGuard to review this Flutter APK before release.
```

## Agent Platforms

Codex:

- Start with `AGENTS.md`.
- Reference the repository root or `SKILL.md`.

Claude Code:

- Copy this repository, or its root `SKILL.md`, into your Claude Code skills location.

OpenClaw:

- Add this repository as an instruction pack.

Other agents:

- Point the agent at the repository root or `SKILL.md`.
- Include `AGENTS.md` as repository-level behavior guidance if your platform supports it.

## What It Checks

- APK/AAB metadata: package name, version, SDK levels, size, ABIs, native libraries, and Flutter evidence.
- Android manifest risk: permissions, exported components, cleartext traffic, debug flags, backup behavior, providers, services, receivers, and deep links.
- Embedded secret risk: resources, assets, Flutter assets, decompiled wrapper code, and readable strings from `libapp.so`.
- Network security: cleartext settings, network security config, certificate trust signals, backend hosts, staging endpoints, and pinning context.
- WebView and platform bridge risk: WebView flags, JavaScript bridges, MethodChannel/EventChannel names, and native wrapper attack surface.
- Signing and release signals: APK signature verification, certificate identity, debug certificate indicators, and release evidence available from the artifact.
- Third-party service signals: Firebase, Google Maps, AWS, Sentry, Stripe, RevenueCat, OneSignal, Supabase, analytics SDKs, and similar markers.

## Skill

`SKILL.md`

Use when an APK/AAB artifact exists or the user asks for Flutter Android artifact safety review.

## Example Output

```text
FlutterGuard APK Security Report

Artifact: build/app/outputs/flutter-apk/app-release.apk
Flutter Evidence: confirmed
Status: RISKY
Score: 72/100

Critical:
- None found from available evidence.

High Risk:
- android:allowBackup is enabled for an app that appears to handle account data.
  Evidence: AndroidManifest.xml application node.
  Recommended action: Review backup policy and disable or constrain backup after human approval.

Warnings:
- Staging API hostname appears in libapp.so strings.
  Evidence: lib/arm64-v8a/libapp.so strings, value redacted to host only.

Informational:
- Package: com.example.app
- Target SDK: 35
- ABIs: arm64-v8a, armeabi-v7a
- Detected services: Firebase, Sentry

Requires Human Approval:
- Backup behavior change
- Endpoint migration or rotation strategy
```

## Repository Map

- `SKILL.md`: the installable FlutterGuard skill.
- `AGENTS.md`: project-level guidance for Codex-style agents working with this repo.
- `SECURITY.md`: reporting and safety policy.

## Safety Philosophy

FlutterGuard should not silently auto-fix sensitive production behavior.

Human approval is required for:

- authentication changes
- payment changes
- permission removal or addition
- dependency changes
- signing configuration
- publishing configuration
- production environment configuration
- API key migration
- privacy or data collection behavior
- deleting files from an app

Safe agent work includes artifact inspection, evidence collection, Markdown reports, checklist notes, test suggestions, and non-invasive recommendations.

## Status

FlutterGuard is currently a single agentic skill. The repository intentionally contains no CLI engine, generated binaries, APK fixtures, build output, scan outputs, installers, or CI wrappers.
