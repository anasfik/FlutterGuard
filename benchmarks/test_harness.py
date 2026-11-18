"""Self-tests for the benchmark harness.

The fake scanner is a real subprocess speaking the documented CLI contract; it
only exists because the JVM CLI is not built yet. Matching, metrics and error
handling run as production code.
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402


PACKAGE = "dev.flutterguard.benchmark_app"


def report(*finding_ids, package=PACKAGE, schema="flutterguard/report/2", flutter=True, evidence=None):
    findings = []
    for fid in finding_ids:
        f = {"id": fid, "severity": "HIGH"}
        if evidence:
            f["evidence"] = [{"source": "libapp.so", "snippet": evidence}]
        findings.append(f)
    return {
        "schema": schema,
        "meta": {"packageName": package},
        "framework": {"isFlutter": flutter},
        "findings": findings,
    }


def write_fake_cli(tmp: Path, payload=None, exit_code=0, sleep=0.0, marker=None, raw=None, name="fake cli"):
    path = tmp / "cli dir" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"#!{sys.executable}",
        "import sys, time",
        "args = sys.argv[1:]",
        "assert args[0] == 'scan', args",
        "out = args[args.index('--json') + 1]",
    ]
    if sleep:
        lines.append(f"time.sleep({sleep!r})")
    if marker is not None:
        lines.append(f"open({str(marker)!r}, 'w').write('invoked')")
    if raw is not None:
        lines.append(f"open(out, 'w').write({raw!r})")
    elif payload is not None:
        lines.append(f"open(out, 'w').write({json.dumps(payload)!r})")
    if exit_code:
        lines.append(f"sys.exit({exit_code})")
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o755)
    return path


def write_apk(root: Path, name="sample.apk", payload=b"fake-apk"):
    path = root / name
    path.write_bytes(payload)
    return path, hashlib.sha256(payload).hexdigest()


def finding_assert(assertion_id, rule, expect, source="unit-test"):
    return {"id": assertion_id, "kind": "finding", "rule": rule, "expect": expect, "source": source}


def field_assert(assertion_id, field, expect, source="unit-test"):
    return {"id": assertion_id, "kind": "field", "field": field, "expect": expect, "source": source}


def write_manifest(tmp: Path, samples, name="test-manifest.json"):
    path = tmp / name
    path.write_text(json.dumps({"manifestVersion": 1, "name": "unit", "samples": samples}))
    return path


def load_manifest_dict(path):
    return json.loads(Path(path).read_text())


def run(tmp, samples, cli, timeout=5.0, corpus_root=None, validate_only=False):
    path = write_manifest(tmp, samples)
    return harness.run_manifest(
        load_manifest_dict(path),
        manifest_path=str(path),
        corpus_root=corpus_root or tmp,
        cli=str(cli),
        timeout=timeout,
        validate_only=validate_only,
    )


class MatchingAndMetricsTests(unittest.TestCase):
    def test_presence_absence_tp_fp_fn_tn_and_unjudged(self):
        sample = {
            "id": "s1",
            "path": "s.apk",
            "sha256": "0" * 64,
            "required": True,
            "assertions": [
                finding_assert("a1", "RULE-HIT", "present"),
                finding_assert("a2", "RULE-MISSED", "present"),
                finding_assert("a3", "RULE-FALSE-POSITIVE", "absent"),
                finding_assert("a4", "RULE-ABSENT-OK", "absent"),
            ],
        }
        result = harness.evaluate_assertions(sample, report("RULE-HIT", "RULE-FALSE-POSITIVE", "RULE-UNJUDGED"))

        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (1, 1, 1, 1))
        self.assertEqual(result["unjudged"], {"RULE-UNJUDGED": 1})
        self.assertEqual(
            sorted(r["id"] for r in result["results"] if r["outcome"] == "fail"),
            ["a2", "a3"],
        )

    def test_duplicate_findings_still_count_as_present(self):
        sample = {
            "id": "s1",
            "path": "s.apk",
            "sha256": "0" * 64,
            "required": True,
            "assertions": [finding_assert("a1", "RULE-HIT", "present")],
        }
        result = harness.evaluate_assertions(sample, report("RULE-HIT", "RULE-HIT"))
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["results"][0]["observed"], 2)
        self.assertEqual(result["results"][0]["outcome"], "pass")

    def test_zero_denominators_are_unavailable_not_perfect(self):
        totals = harness.summarize_metrics([
            {"tp": 0, "fp": 0, "fn": 0, "tn": 2, "unjudged": {}},
        ])
        self.assertIsNone(totals["precision"])
        self.assertIsNone(totals["recall"])
        self.assertEqual(totals["judged"], 2)

    def test_metrics_aggregate_across_samples(self):
        totals = harness.summarize_metrics([
            {"tp": 2, "fp": 0, "fn": 1, "tn": 1, "unjudged": {"R": 2}},
            {"tp": 1, "fp": 1, "fn": 2, "tn": 0, "unjudged": {"R": 1}},
        ])
        self.assertEqual((totals["tp"], totals["fp"], totals["fn"], totals["tn"]), (3, 1, 3, 1))
        self.assertAlmostEqual(totals["precision"], 3 / 4)
        self.assertAlmostEqual(totals["recall"], 3 / 6)
        self.assertEqual(totals["unjudged"], {"R": 3})

    def test_field_assertion_is_identity_check_not_tp_fp(self):
        sample = {
            "id": "s1",
            "path": "s.apk",
            "sha256": "0" * 64,
            "required": True,
            "assertions": [field_assert("f1", "framework.isFlutter", False)],
        }
        result = harness.evaluate_assertions(sample, report("ANY", flutter=True))
        self.assertEqual(result["results"][0]["outcome"], "fail")
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (0, 0, 0, 0))
        self.assertEqual(result["unjudged"], {"ANY": 1})


class ManifestValidationTests(unittest.TestCase):
    def base_sample(self):
        return {
            "id": "s1",
            "path": "s.apk",
            "sha256": "a" * 64,
            "required": True,
            "assertions": [finding_assert("a1", "R", "present")],
        }

    def assert_rejected(self, mutate):
        sample = self.base_sample()
        mutate(sample)
        with self.assertRaises(harness.ManifestError):
            harness.load_manifest_dict({"manifestVersion": 1, "name": "t", "samples": [sample]})

    def test_valid_manifest_accepted(self):
        harness.load_manifest_dict({"manifestVersion": 1, "name": "t", "samples": [self.base_sample()]})

    def test_rejects_bad_digest(self):
        self.assert_rejected(lambda s: s.update(sha256="xyz"))

    def test_rejects_absolute_path(self):
        self.assert_rejected(lambda s: s.update(path="/etc/passwd"))

    def test_rejects_duplicate_sample_and_assertion_ids(self):
        with self.assertRaises(harness.ManifestError):
            harness.load_manifest_dict({
                "manifestVersion": 1,
                "name": "t",
                "samples": [self.base_sample(), self.base_sample()],
            })
        self.assert_rejected(lambda s: s["assertions"].append(finding_assert("a1", "R2", "absent")))

    def test_rejects_unknown_expect_and_missing_assertions(self):
        self.assert_rejected(lambda s: s["assertions"][0].update(expect="maybe"))
        self.assert_rejected(lambda s: s.update(assertions=[]))

    def test_rejects_unknown_manifest_version(self):
        with self.assertRaises(harness.ManifestError):
            harness.load_manifest_dict({"manifestVersion": 2, "name": "t", "samples": [self.base_sample()]})


class RunnerTests(unittest.TestCase):
    def test_successful_scan_reports_ok(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            cli = write_fake_cli(tmp, payload=report("RULE-HIT"))
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": digest,
                "required": True,
                "package": PACKAGE,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            summary = run(tmp, [sample], cli)
            self.assertTrue(summary["ok"])
            self.assertEqual(summary["samples"][0]["status"], "ok")
            self.assertEqual(summary["metrics"]["tp"], 1)
            self.assertEqual(summary["totals"]["failedAssertions"], 0)

    def test_digest_mismatch_fails_before_scanning(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            write_apk(tmp)
            marker = tmp / "invoked"
            cli = write_fake_cli(tmp, payload=report(), marker=marker)
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": "b" * 64,
                "required": True,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            summary = run(tmp, [sample], cli)
            self.assertFalse(summary["ok"])
            self.assertEqual(summary["samples"][0]["status"], "failed")
            self.assertIn("sha256", summary["samples"][0]["reason"].lower())
            self.assertFalse(marker.exists(), "scanner must not run on unverified input")

    def test_required_missing_fails_and_optional_missing_is_not_run(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cli = write_fake_cli(tmp, payload=report("RULE-HIT"))
            required = {
                "id": "required",
                "path": "absent-required.apk",
                "sha256": "a" * 64,
                "required": True,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            optional = {
                "id": "optional",
                "path": "absent-optional.apk",
                "sha256": "a" * 64,
                "required": False,
                "assertions": [finding_assert("a2", "RULE-HIT", "present")],
            }
            summary = run(tmp, [required, optional], cli)
            statuses = {s["id"]: s["status"] for s in summary["samples"]}
            self.assertEqual(statuses, {"required": "failed", "optional": "not_run"})
            self.assertFalse(summary["ok"])
            self.assertEqual(summary["totals"]["samplesRan"], 0)

    def test_optional_only_absence_is_not_a_perfect_score(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cli = write_fake_cli(tmp, payload=report())
            optional = {
                "id": "optional",
                "path": "absent.apk",
                "sha256": "a" * 64,
                "required": False,
                "assertions": [finding_assert("a2", "RULE-HIT", "present")],
            }
            summary = run(tmp, [optional], cli)
            self.assertFalse(summary["ok"], "a run with no executed sample is not a pass")
            self.assertIsNone(summary["metrics"]["precision"])
            self.assertIsNone(summary["metrics"]["recall"])
            self.assertEqual(summary["totals"]["samplesNotRun"], 1)

    def test_scanner_failure_timeout_and_bad_report_fail(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": digest,
                "required": True,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            cases = {
                "nonzero exit": write_fake_cli(tmp, payload=report("RULE-HIT"), exit_code=3, name="exit3"),
                "timeout": write_fake_cli(tmp, payload=report("RULE-HIT"), sleep=3, name="slow"),
                "bad json": write_fake_cli(tmp, raw="{not json", name="badjson"),
                "wrong schema": write_fake_cli(tmp, payload=report(schema="other/report/9"), name="schema"),
                "missing findings": write_fake_cli(tmp, payload={"schema": "flutterguard/report/2", "meta": {"packageName": PACKAGE}}, name="nofindings"),
                "bad finding": write_fake_cli(tmp, payload={"schema": "flutterguard/report/2", "meta": {"packageName": PACKAGE}, "findings": [{"title": "x"}]}, name="badfinding"),
                "no report": write_fake_cli(tmp, name="noreport"),
            }
            for label, cli in cases.items():
                with self.subTest(label):
                    summary = run(tmp, [sample], cli, timeout=0.4)
                    self.assertFalse(summary["ok"], label)
                    self.assertEqual(summary["samples"][0]["status"], "failed", label)

    def test_v1_schema_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            cli = write_fake_cli(tmp, payload=report("RULE-HIT", schema="flutterguard/report/1"))
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": digest,
                "required": True,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            self.assertTrue(run(tmp, [sample], cli)["ok"])

    def test_package_identity_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            cli = write_fake_cli(tmp, payload=report("RULE-HIT", package="com.example.other"))
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": digest,
                "required": True,
                "package": PACKAGE,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            summary = run(tmp, [sample], cli)
            self.assertFalse(summary["ok"])
            self.assertIn("package", summary["samples"][0]["reason"].lower())

    def test_failed_assertion_fails_run(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            cli = write_fake_cli(tmp, payload=report("RULE-UNEXPECTED"))
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": digest,
                "required": True,
                "assertions": [
                    finding_assert("a1", "RULE-HIT", "present"),
                    finding_assert("a2", "RULE-UNEXPECTED", "absent"),
                ],
            }
            summary = run(tmp, [sample], cli)
            self.assertFalse(summary["ok"])
            self.assertEqual(summary["totals"]["failedAssertions"], 2)
            self.assertEqual(summary["metrics"]["fn"], 1)
            self.assertEqual(summary["metrics"]["fp"], 1)

    def test_paths_with_spaces_use_no_shell(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp, name="apk with space.apk")
            cli = write_fake_cli(tmp, payload=report("RULE-HIT"))
            sample = {
                "id": "s1",
                "path": "apk with space.apk",
                "sha256": digest,
                "required": True,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            self.assertTrue(run(tmp, [sample], cli)["ok"])

    def test_output_is_deterministic_sorted_and_never_copies_secret_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            secret = "sk-proj-LEAKCANARY0123456789abcdef"
            cli = write_fake_cli(tmp, payload=report("RULE-HIT", "RULE-UNJUDGED", evidence=secret))
            samples = [
                {
                    "id": "zeta",
                    "path": "sample.apk",
                    "sha256": digest,
                    "required": True,
                    "assertions": [finding_assert("a1", "RULE-HIT", "present")],
                },
                {
                    "id": "alpha",
                    "path": "sample.apk",
                    "sha256": digest,
                    "required": True,
                    "assertions": [finding_assert("a1", "RULE-HIT", "present")],
                },
            ]
            summary = run(tmp, samples, cli)
            text = json.dumps(summary, sort_keys=True)
            self.assertNotIn("LEAKCANARY", text)
            self.assertEqual([s["id"] for s in summary["samples"]], ["alpha", "zeta"])
            self.assertEqual(summary, json.loads(text))
            self.assertEqual(text, json.dumps(summary, sort_keys=True))

    def test_validate_inputs_reports_digest_without_scanning(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            manifest = {
                "manifestVersion": 1,
                "name": "v",
                "samples": [
                    {
                        "id": "ok",
                        "path": "sample.apk",
                        "sha256": digest,
                        "required": True,
                        "assertions": [finding_assert("a1", "R", "present")],
                    },
                    {
                        "id": "mismatch",
                        "path": "sample.apk",
                        "sha256": "c" * 64,
                        "required": True,
                        "assertions": [finding_assert("a2", "R", "present")],
                    },
                ],
            }
            result = harness.validate_inputs(manifest, str(tmp))
            self.assertFalse(result["ok"])
            self.assertEqual([i["id"] for i in result["inputs"]], ["mismatch", "ok"])
            self.assertTrue(result["inputs"][1]["ok"])

    def test_main_writes_outputs_and_returns_exit_codes(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _, digest = write_apk(tmp)
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": digest,
                "required": True,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            manifest_path = write_manifest(tmp, [sample])
            json_out = tmp / "out" / "summary.json"
            md_out = tmp / "out" / "summary.md"

            passing_cli = write_fake_cli(tmp, payload=report("RULE-HIT"), name="pass")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = harness.main([
                    "--manifest", str(manifest_path),
                    "--cli", str(passing_cli),
                    "--corpus-root", str(tmp),
                    "--json-out", str(json_out),
                    "--md-out", str(md_out),
                ])
            self.assertEqual(code, 0)
            summary = json.loads(json_out.read_text())
            self.assertTrue(summary["ok"])
            self.assertIn("PASS", md_out.read_text())
            self.assertEqual(stdout.getvalue(), json_out.read_text())

            failing_cli = write_fake_cli(tmp, payload=report(), name="fail")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    harness.main([
                        "--manifest", str(manifest_path),
                        "--cli", str(failing_cli),
                        "--corpus-root", str(tmp),
                    ]),
                    1,
                )

            bad_manifest = write_manifest(tmp, [dict(sample, sha256="short")], name="bad.json")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    harness.main(["--manifest", str(bad_manifest), "--cli", str(passing_cli)]),
                    2,
                )

    def test_validate_only_main_returns_one_on_digest_mismatch(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            write_apk(tmp)
            sample = {
                "id": "s1",
                "path": "sample.apk",
                "sha256": "d" * 64,
                "required": True,
                "assertions": [finding_assert("a1", "RULE-HIT", "present")],
            }
            manifest_path = write_manifest(tmp, [sample])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    harness.main([
                        "--manifest", str(manifest_path),
                        "--corpus-root", str(tmp),
                        "--validate-only",
                    ]),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
