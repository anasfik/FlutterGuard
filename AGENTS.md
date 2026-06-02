# FlutterGuard Agent Guide

FlutterGuard is an agent-native APK/AAB security review skill for Flutter Android releases. Treat this repository as a single installable agent skill.

## Product Shape

- `SKILL.md` at the repository root is the product.
- `README.md`, `AGENTS.md`, and `SECURITY.md` support discovery, repo-level behavior, and safety policy.

There is no CLI layer in this repository. Do not add Go, Node, Python, APK fixtures, build output, scan results, install scripts, CI wrappers, or standalone scanner behavior unless the project direction changes explicitly.

## Working Rules

Preserve the agent-first identity. Do not describe FlutterGuard as a CLI, static analyzer, APK scanner app, GitHub Action, or SaaS product.

The skill must tell agents exactly what APK/AAB evidence to inspect, what commands are safe to run, what evidence to collect, how to score findings, and what changes require human approval.

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

- root `SKILL.md` has YAML frontmatter with `name` and `description`
- safety boundaries are explicit
- README claims match this one-skill, agent-only repository
- docs do not refer to missing skills, rules, scanner apps, CLIs, CI wrappers, generated APK fixtures, or scan outputs
