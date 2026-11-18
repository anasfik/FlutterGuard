#!/usr/bin/env python3
"""Assertion-level benchmark runner for FlutterGuard.

Judged expectations are pinned in a JSON manifest next to an input digest. A
small, explicit report contract is all this harness trusts; it never derives
expectations from scanner output and never copies evidence values into its own
report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

SCHEMA = "flutterguard/benchmark/1"
VALIDATE_SCHEMA = "flutterguard/benchmark/validate/1"
MANIFEST_VERSION = 1
# /1 is the current engine export; /2 is the planned finding-kind revision.
REPORT_SCHEMAS = ("flutterguard/report/1", "flutterguard/report/2")
MAX_REPORT_BYTES = 64 * 1024 * 1024
DEFAULT_TIMEOUT = 300.0
REPO_ROOT = Path(__file__).resolve().parent.parent

METRIC_NOTE = (
    "Counts cover only explicitly judged finding assertions. Unjudged findings "
    "are not false positives, and a ratio is null when its denominator is zero."
)


class ManifestError(ValueError):
    """The manifest is malformed; nothing may be scanned."""


def _nonempty_str(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


# --------------------------------------------------------------------- inputs


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def input_path(sample: dict, corpus_root: str | os.PathLike) -> Path:
    return Path(corpus_root) / sample["path"]


def load_manifest(path: str | os.PathLike) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc.__class__.__name__}") from exc
    return load_manifest_dict(data)


def load_manifest_dict(data: object) -> dict:
    """Validate the portable manifest shape; return it unchanged."""
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")
    if data.get("manifestVersion") != MANIFEST_VERSION or isinstance(data.get("manifestVersion"), bool):
        raise ManifestError(f"unsupported manifestVersion (expected {MANIFEST_VERSION})")
    if not _nonempty_str(data.get("name")):
        raise ManifestError("manifest.name must be a non-empty string")
    samples = data.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ManifestError("manifest.samples must be a non-empty list")

    sample_ids: set[str] = set()
    for sample in samples:
        if not isinstance(sample, dict):
            raise ManifestError("each sample must be an object")
        sample_id = sample.get("id")
        if not _nonempty_str(sample_id):
            raise ManifestError("sample.id must be a non-empty string")
        if sample_id in sample_ids:
            raise ManifestError(f"duplicate sample id: {sample_id}")
        sample_ids.add(sample_id)

        path = sample.get("path")
        if not _nonempty_str(path) or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ManifestError(f"{sample_id}: path must be relative to the corpus root")
        digest = sample.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ManifestError(f"{sample_id}: sha256 must be 64 lowercase hex characters")
        if not isinstance(sample.get("required"), bool):
            raise ManifestError(f"{sample_id}: required must be a boolean")
        if "package" in sample and not _nonempty_str(sample["package"]):
            raise ManifestError(f"{sample_id}: package must be a non-empty string when present")

        assertions = sample.get("assertions")
        if not isinstance(assertions, list) or not assertions:
            raise ManifestError(f"{sample_id}: assertions must be a non-empty list")
        assertion_ids: set[str] = set()
        for assertion in assertions:
            if not isinstance(assertion, dict):
                raise ManifestError(f"{sample_id}: each assertion must be an object")
            assertion_id = assertion.get("id")
            if not _nonempty_str(assertion_id):
                raise ManifestError(f"{sample_id}: assertion.id must be a non-empty string")
            if assertion_id in assertion_ids:
                raise ManifestError(f"{sample_id}: duplicate assertion id {assertion_id}")
            assertion_ids.add(assertion_id)
            kind = assertion.get("kind")
            if kind == "finding":
                if not _nonempty_str(assertion.get("rule")):
                    raise ManifestError(f"{sample_id}/{assertion_id}: rule must be a non-empty string")
                if assertion.get("expect") not in ("present", "absent"):
                    raise ManifestError(f"{sample_id}/{assertion_id}: finding expect must be present or absent")
            elif kind == "field":
                if not _nonempty_str(assertion.get("field")):
                    raise ManifestError(f"{sample_id}/{assertion_id}: field must be a dotted path")
                if not isinstance(assertion.get("expect"), bool):
                    raise ManifestError(f"{sample_id}/{assertion_id}: field expect must be a boolean")
            else:
                raise ManifestError(f"{sample_id}/{assertion_id}: unknown assertion kind")
            if "source" in assertion and not isinstance(assertion["source"], str):
                raise ManifestError(f"{sample_id}/{assertion_id}: source must be a string")
    return data


def validate_inputs(manifest: dict, corpus_root: str | os.PathLike) -> dict:
    """Check presence and digests only; never invokes the scanner."""
    inputs = []
    for sample in sorted(manifest["samples"], key=lambda s: s["id"]):
        path = input_path(sample, corpus_root)
        entry = {
            "id": sample["id"],
            "path": sample["path"],
            "required": sample["required"],
            "expectedSha256": sample["sha256"],
            "exists": path.is_file(),
        }
        if not entry["exists"]:
            entry["ok"] = False
            entry["status"] = "failed" if sample["required"] else "not_run"
            entry["reason"] = "required input missing" if sample["required"] else "optional input missing"
        else:
            actual = sha256_file(path)
            entry["actualSha256"] = actual
            entry["ok"] = actual == sample["sha256"]
            entry["status"] = "ok" if entry["ok"] else "failed"
            entry["reason"] = None if entry["ok"] else "sha256 mismatch"
        inputs.append(entry)
    return {
        "schema": VALIDATE_SCHEMA,
        "ok": all(entry["status"] != "failed" for entry in inputs),
        "inputs": inputs,
    }


# ------------------------------------------------------------------ evaluation


def finding_counts(report: dict) -> Counter:
    return Counter(finding["id"] for finding in report["findings"])


def field_value(report: dict, dotted: str) -> tuple[bool, object]:
    node: object = report
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def evaluate_assertions(sample: dict, report: dict) -> dict:
    """Judge one sample's explicit assertions; count TP/FP/FN/TN for findings."""
    counts = finding_counts(report)
    judged: set[str] = set()
    results: list[dict] = []
    tp = fp = fn = tn = 0

    for assertion in sample["assertions"]:
        if assertion["kind"] == "finding":
            rule = assertion["rule"]
            judged.add(rule)
            observed = counts.get(rule, 0)
            if assertion["expect"] == "present":
                ok = observed > 0
                tp, fn = (tp + 1, fn) if ok else (tp, fn + 1)
            else:
                ok = observed == 0
                tn, fp = (tn + 1, fp) if ok else (tn, fp + 1)
            results.append({
                "id": assertion["id"],
                "kind": "finding",
                "rule": rule,
                "expect": assertion["expect"],
                "observed": observed,
                "outcome": "pass" if ok else "fail",
            })
        else:
            found, value = field_value(report, assertion["field"])
            ok = found and isinstance(value, bool) and value == assertion["expect"]
            results.append({
                "id": assertion["id"],
                "kind": "field",
                "field": assertion["field"],
                "expect": assertion["expect"],
                "observed": value if isinstance(value, (bool, type(None))) else None,
                "outcome": "pass" if ok else "fail",
            })

    results.sort(key=lambda item: item["id"])
    unjudged = {rule: count for rule, count in sorted(counts.items()) if rule not in judged}
    return {
        "results": results,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "unjudged": unjudged,
    }


def summarize_metrics(per_sample: list[dict]) -> dict:
    tp = sum(sample["tp"] for sample in per_sample)
    fp = sum(sample["fp"] for sample in per_sample)
    fn = sum(sample["fn"] for sample in per_sample)
    tn = sum(sample["tn"] for sample in per_sample)
    unjudged: Counter = Counter()
    for sample in per_sample:
        unjudged.update(sample["unjudged"])
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "judged": tp + fp + fn + tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "unjudged": dict(sorted(unjudged.items())),
        "note": METRIC_NOTE,
    }


# ----------------------------------------------------------------- subprocesses


def _validate_report(report: object, expected_package: str | None) -> tuple[dict | None, str | None]:
    if not isinstance(report, dict):
        return None, "report must be a JSON object"
    schema = report.get("schema")
    if schema not in REPORT_SCHEMAS:
        return None, f"report schema {_short(schema)} is not accepted"
    meta = report.get("meta")
    package = meta.get("packageName") if isinstance(meta, dict) else None
    if not _nonempty_str(package):
        return None, "report meta.packageName is missing"
    if expected_package is not None and package != expected_package:
        return None, f"package mismatch: expected {expected_package}, got {_short(package)}"
    findings = report.get("findings")
    if not isinstance(findings, list):
        return None, "report findings must be a list"
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not _nonempty_str(finding.get("id")):
            return None, f"report findings[{index}].id is missing"
    return report, None


def _short(value: object, limit: int = 80) -> str:
    text = "" if value is None else str(value)
    text = "".join(c for c in text if c.isprintable())
    return text[:limit]


def _scan(apk: Path, cli: str, timeout: float, workdir: Path) -> tuple[dict | None, str | None, bool]:
    """Run the CLI contract once. Returns (report, error, scan_ran)."""
    out = workdir / "report.json"
    argv = [cli, "scan", str(apk), "--json", str(out)]
    stdout = (workdir / "stdout.log").open("wb")
    stderr = (workdir / "stderr.log").open("wb")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            return None, f"scan timed out after {timeout:g}s", True
    finally:
        stdout.close()
        stderr.close()
    if code != 0:
        # Exit code and byte counts only: stderr may echo recovered values.
        return None, f"scan exited {code}", True
    if not out.is_file():
        return None, "scan produced no report", True
    if out.stat().st_size > MAX_REPORT_BYTES:
        return None, "report exceeds the size cap", True
    try:
        report = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "report is not valid JSON", True
    return report, None, True


def run_sample(sample: dict, corpus_root: str | os.PathLike, cli: str, timeout: float) -> dict:
    started = time.monotonic()
    path = input_path(sample, corpus_root)
    failed = {
        "id": sample["id"],
        "path": sample["path"],
        "expectedSha256": sample["sha256"],
        "status": "failed",
        "reason": None,
        "scanRan": False,
        "durationMs": 0,
        "assertions": [],
        "metrics": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "unjudged": {},
    }

    if not path.is_file():
        if sample["required"]:
            failed["reason"] = "required input missing"
            return failed
        return {**failed, "status": "not_run", "reason": "optional input missing"}

    actual = sha256_file(path)
    if actual != sample["sha256"]:
        failed["reason"] = f"sha256 mismatch: expected {sample['sha256']}, got {actual}"
        return failed

    with tempfile.TemporaryDirectory(prefix="fgbench-") as tmp:
        report, error, scan_ran = _scan(path, cli, timeout, Path(tmp))
    if error is not None:
        return {**failed, "reason": error, "scanRan": scan_ran}

    report, error = _validate_report(report, sample.get("package"))
    if error is not None:
        return {**failed, "reason": error, "scanRan": True}

    judged = evaluate_assertions(sample, report)
    failures = [result for result in judged["results"] if result["outcome"] == "fail"]
    status = "failed" if failures else "ok"
    return {
        "id": sample["id"],
        "path": sample["path"],
        "expectedSha256": sample["sha256"],
        "status": status,
        "reason": f"{len(failures)} assertion(s) failed" if failures else None,
        "scanRan": True,
        "durationMs": int(round((time.monotonic() - started) * 1000)),
        "assertions": judged["results"],
        "metrics": {key: judged[key] for key in ("tp", "fp", "fn", "tn")},
        "unjudged": judged["unjudged"],
    }


# ---------------------------------------------------------------- orchestration


def run_manifest(
    manifest: dict,
    *,
    manifest_path: str,
    corpus_root: str | os.PathLike,
    cli: str | None,
    timeout: float,
    engine_revision: str | None = None,
    validate_only: bool = False,
) -> dict:
    if validate_only:
        return validate_inputs(manifest, corpus_root)
    if not cli or not Path(cli).is_file() or not os.access(cli, os.X_OK):
        raise ValueError("--cli must point to an executable file")
    if not (isinstance(timeout, (int, float)) and 0 < timeout < 86400):
        raise ValueError("--timeout must be a finite number of seconds between 0 and 86400")

    samples = [run_sample(sample, corpus_root, cli, float(timeout)) for sample in sorted(manifest["samples"], key=lambda s: s["id"])]
    metrics = summarize_metrics([sample["metrics"] | {"unjudged": sample["unjudged"]} for sample in samples])
    return {
        "schema": SCHEMA,
        "engineRevision": engine_revision,
        "manifest": {
            "path": manifest_path,
            "name": manifest["name"],
            "manifestVersion": manifest["manifestVersion"],
        },
        "totals": {
            "samples": len(samples),
            "samplesRan": sum(1 for sample in samples if sample["scanRan"]),
            "samplesNotRun": sum(1 for sample in samples if sample["status"] == "not_run"),
            "samplesFailed": sum(1 for sample in samples if sample["status"] == "failed"),
            "assertions": sum(len(sample["assertions"]) for sample in samples),
            "failedAssertions": sum(
                1 for sample in samples for result in sample["assertions"] if result["outcome"] == "fail"
            ),
        },
        "metrics": metrics,
        "samples": samples,
        "ok": any(sample["scanRan"] for sample in samples)
        and not any(sample["status"] == "failed" for sample in samples),
    }


def render_markdown(summary: dict) -> str:
    totals, metrics = summary["totals"], summary["metrics"]
    lines = [
        "# FlutterGuard benchmark",
        "",
        f"- Manifest: `{summary['manifest']['name']}` v{summary['manifest']['manifestVersion']}",
        f"- Engine revision: `{summary['engineRevision'] or 'unknown'}`",
        f"- Result: **{'PASS' if summary['ok'] else 'FAIL'}**",
        "",
        "## Totals",
        "",
        "| samples | ran | not run | failed | assertions | failed assertions |",
        "|---|---|---|---|---|---|",
        f"| {totals['samples']} | {totals['samplesRan']} | {totals['samplesNotRun']} | "
        f"{totals['samplesFailed']} | {totals['assertions']} | {totals['failedAssertions']} |",
        "",
        "## Judged finding assertions",
        "",
        "| judged | tp | fp | fn | tn | precision | recall |",
        "|---|---|---|---|---|---|---|",
        f"| {metrics['judged']} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | {metrics['tn']} | "
        f"{_ratio(metrics['precision'])} | {_ratio(metrics['recall'])} |",
        "",
        metrics["note"],
        "",
        "## Samples",
        "",
        "| sample | status | assertions | failed | duration ms |",
        "|---|---|---|---|---|",
    ]
    for sample in summary["samples"]:
        failed = sum(1 for result in sample["assertions"] if result["outcome"] == "fail")
        lines.append(
            f"| {sample['id']} | {sample['status']} | {len(sample['assertions'])} | {failed} | {sample['durationMs']} |"
        )

    problems = [
        (sample, result)
        for sample in summary["samples"]
        for result in sample["assertions"]
        if result["outcome"] == "fail"
    ]
    lines += ["", "## Failed assertions", ""]
    if not problems:
        lines.append("None.")
    for sample, result in problems:
        subject = result["rule"] if result["kind"] == "finding" else result["field"]
        lines.append(f"- `{sample['id']}` / `{result['id']}` — {subject} expected {result['expect']}, observed {result['observed']}")

    lines += ["", "## Samples not run or failed", ""]
    blocked = [sample for sample in summary["samples"] if sample["status"] != "ok"]
    if not blocked:
        lines.append("None.")
    for sample in blocked:
        lines.append(f"- `{sample['id']}` — {sample['status']}: {sample['reason']}")

    lines += ["", "## Unjudged reported rules", ""]
    if not metrics["unjudged"]:
        lines.append("None.")
    else:
        lines.append("| rule | findings |")
        lines.append("|---|---|")
        for rule, count in metrics["unjudged"].items():
            lines.append(f"| {rule} | {count} |")

    lines += [
        "",
        "## Limits",
        "",
        "- Assertions judge artifact presence or absence, not exploitability or credential validity.",
        "- Reported rules with no explicit assertion are unjudged, never false positives.",
        "- NOT RUN means the evidence was unavailable; it is not a pass and not a clean baseline.",
        "",
    ]
    return "\n".join(lines)


def _ratio(value: float | None) -> str:
    return "unavailable" if value is None else f"{value:.4f}"


def write_text_atomic(path: str | os.PathLike, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


# ------------------------------------------------------------------------ main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run digest-pinned FlutterGuard assertion benchmarks.")
    parser.add_argument("--manifest", required=True, help="benchmark manifest JSON")
    parser.add_argument("--cli", help="flutterguard executable (contract: flutterguard scan INPUT.apk --json OUTPUT)")
    parser.add_argument("--corpus-root", default=str(REPO_ROOT), help="root that manifest sample paths are relative to")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="seconds per scan (finite, no default infinity)")
    parser.add_argument("--json-out", help="write the safe JSON summary here")
    parser.add_argument("--md-out", help="write the Markdown summary here")
    parser.add_argument("--engine-revision", help="engine revision recorded in the summary")
    parser.add_argument("--validate-only", action="store_true", help="check input presence and digests without scanning")
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
        if not args.validate_only and not args.cli:
            parser.error("--cli is required unless --validate-only is used")
        if args.validate_only and args.md_out:
            parser.error("--md-out requires a scan run")
        summary = run_manifest(
            manifest,
            manifest_path=args.manifest,
            corpus_root=args.corpus_root,
            cli=args.cli,
            timeout=args.timeout,
            engine_revision=args.engine_revision,
            validate_only=args.validate_only,
        )
    except (ManifestError, ValueError, OSError) as exc:
        print(f"benchmark error: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        write_text_atomic(args.json_out, text)
    if args.md_out and not args.validate_only:
        write_text_atomic(args.md_out, render_markdown(summary))
    sys.stdout.write(text)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
