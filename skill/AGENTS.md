# FlutterGuard Agent Guide

FlutterGuard is an agent-native APK/AAB security review skill for Flutter Android releases. The same repository also ships the on-device Android app that automates part of that review.

## Product Shape

- `skill/SKILL.md` is the installable skill: the workflow an agent follows when it inspects an artifact by hand.
- `skill/AGENTS.md` and `skill/SECURITY.md` carry repository behavior and safety policy.
- The repository root is also an Android project: `app/` (Kotlin + Jetpack Compose, package `com.flutterguard.app`), `build.gradle.kts`, `settings.gradle.kts`, `gradle.properties`.
- `CORPUS.md` records the real-app corpus that produced the detectors; `docs/METHODOLOGY.md` explains how each detector family was derived.

Neither layer is a CLI, GitHub Action, or SaaS product, and the app does not replace the skill: it only sees what is installed on the phone it runs on.

## Working Rules

Preserve the agent-first identity. Describe FlutterGuard as a skill plus a companion app, never as a CLI, static-analysis service, or cloud scanner.

The skill must tell agents exactly what APK/AAB evidence to inspect, what commands are safe to run, what evidence to collect, how to score findings, and what changes require human approval.

The app is on-device only by design. Do not add `INTERNET` or other network permissions, telemetry, crash reporting, remote config, update checks, or any code path that uploads an artifact, a report, or a finding. Do not add a second permission beyond `QUERY_ALL_PACKAGES` without an explicit project decision.

Detection changes belong in `app/src/main/java/com/flutterguard/app/scan/` (`rules/` for findings, `parsers/` for artifact formats). When a rule is added or retuned, say which real app motivated it and record the observation in `CORPUS.md` or `docs/METHODOLOGY.md`; a rule with no corpus evidence should be labeled as general Android review practice.

Do not invent completed executable features. If a workflow requires external tooling such as `jadx`, `aapt2`, `apksigner`, `keytool`, `strings`, or `bundletool`, explain it as optional tooling an agent may use locally or in the target app workspace.

## Safety Boundaries

Never silently modify these areas in a user app:

- payment logic
- authentication logic
- signing configuration
- Android permissions
- dependency graph
- publishing configuration
- production environment configuration
- API key migration strategy
- privacy or data collection behavior
- destructive file deletion

For those areas, produce findings and recommended actions, then ask for human approval before editing.

Safe automatic work may include generating reports, suggesting tests, formatting Markdown, and adding non-invasive recommendations.

## Repo Checks

For documentation and the skill, check that:

- `skill/SKILL.md` has YAML frontmatter with `name` and `description`
- safety boundaries are explicit
- README claims and `skill/AGENTS.md` agree on the skill-plus-app shape
- docs do not refer to missing skills, rules, CLIs, CI wrappers, or generated APK fixtures
- app claims match the source: report path and schema, headless intent extra, absence of `INTERNET`, and the rules actually implemented under `scan/`
- corpus and methodology claims match `CORPUS.md` and the detector source
