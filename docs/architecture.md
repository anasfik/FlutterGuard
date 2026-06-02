# Architecture

FlutterGuard is a pure agent skill repository. Its architecture is intentionally small: one installable skill, examples, and documentation.

## 1. Skill

`skills/flutter-apk-security/` is the product. It is an agent-readable workflow for reviewing Flutter Android APK/AAB artifacts.

The skill defines:

- when to use it
- safe artifact-inspection commands
- evidence to collect
- Android and Flutter artifact risks to inspect
- critical blockers and severity guidance
- scoring and output format
- human approval boundaries

The skill must remain useful with ordinary agent capabilities such as reading files, searching text, running safe local commands, and writing reports.

## 2. Examples

`examples/` contains install notes, prompts, and report examples for agent platforms.

Examples should be realistic and should not claim that FlutterGuard can run as a standalone app, CLI, CI wrapper, or automated scanner.

## 3. Docs

`docs/` explains how to maintain the one skill, reason about APK/AAB release risks, and preserve safety boundaries.

## Non-Goals

This repository does not contain:

- CLI code
- API server code
- GitHub Action implementation
- generated APK fixtures
- build output
- scan results
- platform-specific installers
- additional Flutter release, dependency, AI-slop, or CI skills
