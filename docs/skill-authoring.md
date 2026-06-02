# Skill Authoring

FlutterGuard currently contains one skill:

- `SKILL.md`

The skill must contain YAML frontmatter:

```yaml
---
name: flutter-apk-security
description: Clear one-sentence description of when the skill should be used.
---
```

Write the skill for agents doing real APK/AAB review work:

- say when to use the skill
- list safe read-only commands
- define how to confirm Flutter evidence
- list exact artifact areas to inspect
- define critical blockers
- define severity and scoring
- define output format
- require evidence with paths or command-output references
- require redaction of secrets
- include human approval boundaries

Avoid marketing copy, vague advice, and claims that depend on standalone executable features.

A good skill should still help when the only tools available are shell commands, file search, and careful review.
