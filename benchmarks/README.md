# Assertion benchmark harness

Standard-library runner that judges a FlutterGuard JSON report against explicit,
digest-pinned expectations. It never derives expectations from scanner output,
never scans by itself, and never copies evidence values into its summaries.

```bash
python3 benchmarks/harness.py --help
python3 -m unittest discover -s benchmarks -p 'test_*.py'
```

## Contract

The runner invokes exactly one executable, with an argv list and no shell:

```text
<cli> scan INPUT.apk --json OUTPUT.json
```

The CLI must exit `0` for a completed scan. Its report must be a JSON object
with `schema` in `flutterguard/report/1` (current) or `flutterguard/report/2`
(planned finding kinds), a non-empty `meta.packageName`, and a `findings` list
whose entries each carry a non-empty string `id`. Anything else fails the
sample; the harness does not guess a report shape.

Every input is SHA-256 verified immediately before the scan. Required inputs
that are missing, mismatched, unreadable, slow, or failed are sample failures.
Optional inputs that are absent are `not_run`, never a pass.

## Manifests

`benchmarks/manifests/flutter-fixtures.json` — three owned fixture APKs, all
`required`. Assertions come from planted fixture facts, each corroborated on
the pinned build with `zipfile` entry inspection and `aapt2 36.1.0` (compiled
manifest/NSC), not from any scanner report.

`benchmarks/manifests/production-flutter-controls.json` — optional local corpus
controls (`required: false`). Only Flutter presence/absence is judged; every
other rule those APKs trigger is unjudged. Sample paths are relative to
`--corpus-root`, so the manifest stays portable.

```bash
# Owned fixtures (repository-root corpus).
python3 benchmarks/harness.py \
  --manifest benchmarks/manifests/flutter-fixtures.json \
  --cli /path/to/flutterguard \
  --json-out /tmp/fixtures.json --md-out /tmp/fixtures.md

# Optional production presence controls.
python3 benchmarks/harness.py \
  --manifest benchmarks/manifests/production-flutter-controls.json \
  --corpus-root "$CORPUS_ROOT" \
  --cli /path/to/flutterguard --json-out /tmp/controls.json

# Presence + digest check only; no scanner, no claim about detections.
python3 benchmarks/harness.py --manifest benchmarks/manifests/flutter-fixtures.json --validate-only
```

## Manifest schema (version 1)

| Field | Meaning |
|---|---|
| `manifestVersion` | must be `1` |
| `name` | report label |
| `samples[].id` | unique, stable sample identifier |
| `samples[].path` | relative to the corpus root; no absolute paths or `..` |
| `samples[].sha256` | 64 lowercase hex characters, the only accepted artifact identity |
| `samples[].required` | `true` = absence/error fails the run; `false` = absence is `not_run` |
| `samples[].package` | optional; a report for another package fails the sample |
| `samples[].assertions[]` | non-empty, unique `id` per sample |
| `assertions[].kind` | `finding` or `field` |
| `assertions[].rule` / `.field` | finding id, or dotted field such as `framework.isFlutter` |
| `assertions[].expect` | `present` / `absent`, or a boolean for fields |
| `assertions[].source` | independent evidence reference (source line, compiled check) |

A manifest with a bad digest, empty assertion list, duplicate id, unknown
expectation, or absolute path is rejected before any scan (exit 2).

## Judging and metrics

- `present` + finding seen → TP; `present` + missing → FN.
- `absent` + finding seen → FP; `absent` + missing → TN.
- Findings whose rule has no assertion are **unjudged**, reported per rule and
  excluded from precision/recall. They are not false positives.
- Precision is `null` when `TP + FP == 0`; recall is `null` when
  `TP + FN == 0`. Markdown prints `unavailable`. A zero denominator is never
  rendered as 100%.
- `field` assertions are identity checks (correct artifact/framework), not
  TP/FP counts.
- Assertions state artifact presence or absence — not exploitability and not
  credential validity. The fixture's provider-shaped literal is a lead.

## Output and exit codes

The summary is deterministic and sorted, with no raw evidence, snippets,
stderr, or scan-log content: sample id, relative path, expected digest,
status, reason, duration, per-assertion outcome and counts, per-rule unjudged
counts, metrics, and engine revision (when supplied). JSON is printed to
stdout; `--json-out` / `--md-out` additionally write files via a temporary
sibling and `os.replace`.

| Exit | Meaning |
|---|---|
| 0 | at least one sample executed and no sample failed; optional samples may be `not_run` |
| 1 | any sample failed, or nothing was executed (not-run-only is not a pass) |
| 2 | manifest or invocation error; nothing was scanned |

A failing scanner exit, timeout, malformed report, wrong schema, or package
mismatch can never be reported as a pass. `not_run` is absence of evidence,
not a clean result; an all-`not_run` run exits 1.

## Fixture provenance

Fixture digests (verified locally with `sha256sum`; compiled facts verified with
`aapt2 dump badging|permissions|xmltree`):

| Sample | SHA-256 | Independently observed |
|---|---|---|
| debug | `e7a69203…66f43` | debuggable; `kernel_blob.bin`; no `libapp.so`; NSC cleartext + user CA; exported activity; packaged `test.env`; synthetic `sk-proj-` literal |
| plain release | `3597a330…19de` | not debuggable; `libapp.so`; no kernel; NSC cleartext + user CA (compiled `res/8G.xml`); exported activity; packaged `test.env`; literal |
| obfuscated release | `6c9f1b36…f1d` | same release facts; Dart identifiers obfuscated, string literals/assets retained |

No fixture carries `INTERNET`. The permissive NSC is a policy fact, not a
working cleartext path. None of the planted keys is valid.

## Limits

- The digest is checked immediately before the scan; inputs are not re-hashed
  after the CLI returns.
- Obfuscation is not asserted: the fixture map and DWARF presence do not prove
  or disprove Dart-name removal, so no `FLUT-NO-OBFUSCATION` expectation exists.
- This is a judged assertion set, not a corpus-wide precision claim. The
  production manifest asserts Flutter presence only.
- Real CLI execution is pending W5; this harness was verified with the unit
  suite and digest-only validation of the real fixture APKs.
