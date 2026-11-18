# FlutterGuard CLI

Headless scanner for a single APK. Same analysis engine as the Android app,
plain JVM runtime, no Android SDK or device required.

```bash
flutterguard scan INPUT.apk --json OUTPUT.json [--sarif OUTPUT.sarif] [--fail-on confirmed]
```

Build the launcher distribution:

```bash
./gradlew :cli:installDist
cli/build/install/flutterguard/bin/flutterguard --help  # prints the usage line, exit 2
```

Requires JDK 17 or newer. The distribution bundles the engine, `org.json` and
`kotlinx-coroutines-core`; nothing is downloaded at runtime.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan completed; gate not requested or not hit. |
| `1`  | Scan completed and the requested gate was hit (`--fail-on confirmed` with at least one `CONFIRMED` finding). |
| `2`  | Invalid arguments, unreadable/unsupported input, scan failure (including cancellation), or output failure. |

A gate hit is evaluated only after both outputs are published, so `1` can never
hide a scan or write error. A `CONFIRMED` finding means the artifact itself
proves the configuration (see the in-app confidence model); it is not an
exploitability verdict.

## Output safety

- `--json` and `--sarif` may not be the input APK, a symlink to it, a hardlink
  or a symlinked-parent alias of it (`Files.isSameFile` plus resolved-path
  comparison). The input is opened read-only and is never truncated.
- An existing output file is refused with exit 2. New output is staged as
  sibling temporary files, `fsync`ed, then published with atomic moves; a
  destination that appears while the scan is running is refused rather than
  replaced, and a failed publication rolls back anything already published.
  Temporary files are removed on failure.
- Progress and errors go to stderr. Commands such as
  `flutterguard scan app.apk --json report.json > /dev/null` therefore lose no
  diagnostics. stdout stays empty; the report lives in the `--json` file.
- Progress lines carry a stage name and percentage only. No recovered value,
  snippet, host or file content is ever printed. Interrupting the CLI thread
  cancels the scan and exits 2.

## JSON

`--json` is the engine's redacted report, schema `flutterguard/report/2`
(`ReportExport.toJson`, `sensitive = false`). Detected secret values are masked;
they are never written to disk by the CLI.

## SARIF 2.1.0

`--sarif` emits one run to the GitHub code-scanning shape:

- `tool.driver.name = "FlutterGuard"`,
  `informationUri = "https://flutterguard.dev/"`,
  `rules[]` = one entry per distinct reported finding id, with
  `shortDescription.text` (title), `help.text` (remediation) and
  `defaultConfiguration.level` (strongest level seen for that id).
- `results[]` = `ruleId`, `ruleIndex`, `level`, `message.text` (scrubbed detail,
  falling back to the title), `partialFingerprints` and one location.
- `partialFingerprints["flutterguardEvidence/v1"] = "<findingId>|<evidence.source>"`.
  Identity only: never a secret value, a snippet or a hash of one.
- Locations point at the scanned APK as a `file:` URI and carry **no**
  `region`/line data. The artifact is a binary; inventing source positions
  would be false precision.
- Levels: `CONFIRMED` + `CRITICAL|HIGH` → `error`; `CONFIRMED` + `MEDIUM|LOW` →
  `warning`; `CONFIRMED` + `INFO` and every `SUSPECTED` → `note`;
  `INFORMATIONAL` inventory is omitted by default.
- The document is parsed and structurally checked (`version`, `runs`,
  `tool.driver`, every `ruleId` resolving to a rule, `ruleIndex` in range)
  before it is written. A validation or write failure is exit 2.

## Continuous integration

`.github/workflows/apk-scan.yml` checks out the repository, sets up JDK 17, runs
`:cli:test`, builds the CLI distribution, builds FlutterGuard's own debug APK as
the owned fixture, scans it into JSON + SARIF, retains both as workflow
artifacts for 14 days, and (in a separate job) uploads the SARIF to code
scanning. Only that upload job requests `security-events: write` (plus
`actions: read`, which `upload-sarif` needs on private repositories); fork pull
requests skip it, which does not fail the job. The benchmark step is guarded on
`benchmarks/harness.py` being tracked, so it stays inert until that harness
lands in the repository.

The workflow does not use `--fail-on`: FlutterGuard's debug build legitimately
contains `CONFIRMED` findings (debuggable manifest, debug certificate), so the
gate would reject the repository's own fixture. Gate usage belongs to the
project being scanned.

## Limits

- Local structural validation is not GitHub acceptance. Code-scanning ingestion,
  alert display and deduplication by fingerprint are unverified until the
  workflow actually runs on GitHub with those permissions.
- One APK per invocation; split APK sets are not assembled here.
- The report is static artifact evidence. It never proves runtime behaviour or
  exploitability, and the SARIF locations never imply recovered source code.
