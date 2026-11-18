package com.flutterguard.cli

import com.flutterguard.app.scan.Evidence
import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.FindingKind
import com.flutterguard.app.scan.Severity
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * SARIF 2.1.0 contract: stable rules, severity-aware levels, honest binary
 * artifact locations, no evidence values and no fabricated source regions.
 */
class SarifTest {

    private fun finding(
        id: String,
        severity: Severity,
        kind: FindingKind,
        detail: String = "detail for $id",
        evidence: List<Evidence> = emptyList(),
    ) = Finding(
        id = id,
        title = "Title $id",
        severity = severity,
        detail = detail,
        evidence = evidence,
        remediation = "Remediation $id",
        kind = kind,
    )

    private fun report(findings: List<Finding>) = com.flutterguard.app.scan.Report(
        meta = com.flutterguard.app.scan.AppMeta(
            packageName = "com.example.sarif",
            label = "Sarif",
            versionName = "1.0",
            versionCode = 1,
            minSdk = 26,
            targetSdk = 34,
            installer = null,
            firstInstallMs = 0,
            lastUpdateMs = 0,
            isSystem = false,
            sizeBytes = 1024,
            splitCount = 0,
            abis = emptyList(),
            nativeLibs = emptyList(),
            baseSha256 = "00",
            fileScan = true,
        ),
        framework = com.flutterguard.app.scan.FrameworkInfo(isFlutter = true),
        signing = com.flutterguard.app.scan.SigningInfo(null, null, null, false, false, false, null, null, null),
        findings = findings,
        hosts = emptyList(),
        channels = emptyList(),
        thirdParty = emptyList(),
        permissions = emptyList(),
        deepLinks = emptyList(),
        stats = com.flutterguard.app.scan.ReportStats(0, 0, 0, 0, 0, 0, 0),
        grade = 'A',
    )

    private val fixtures = listOf(
        finding("TEST-CRITICAL", Severity.CRITICAL, FindingKind.CONFIRMED, evidence = listOf(Evidence("lib/arm64-v8a/libapp.so", 10, "snippet-ok"))),
        finding("TEST-HIGH", Severity.HIGH, FindingKind.CONFIRMED),
        finding("TEST-MEDIUM", Severity.MEDIUM, FindingKind.CONFIRMED),
        finding("TEST-LOW", Severity.LOW, FindingKind.CONFIRMED),
        finding("TEST-SUSPECT", Severity.HIGH, FindingKind.SUSPECTED),
        finding("TEST-INFO", Severity.INFO, FindingKind.INFORMATIONAL),
        finding(
            "TEST-SECRET",
            Severity.HIGH,
            FindingKind.SUSPECTED,
            detail = "matched VALUE_LEAK_CANARY in classes.dex",
            evidence = listOf(Evidence("classes.dex", 42, "SNIPPET_LEAK_CANARY", "VALUE_LEAK_CANARY")),
        ),
    )

    private fun document() = Sarif.document(report(fixtures), "file:///tmp/scan-target.apk")

    @Test
    fun hasRequiredTopLevelShape() {
        val root = JSONObject(document())
        assertEquals("2.1.0", root.getString("version"))
        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", root.getString("\$schema"))
        val runs = root.getJSONArray("runs")
        assertEquals(1, runs.length())
        val driver = runs.getJSONObject(0).getJSONObject("tool").getJSONObject("driver")
        assertEquals("FlutterGuard", driver.getString("name"))
        assertEquals("https://flutterguard.dev/", driver.getString("informationUri"))
        assertNotNull(driver.getJSONArray("rules"))
    }

    @Test
    fun emitsOneRulePerDistinctReportedIdAndReferencesIt() {
        val root = JSONObject(document())
        val run = root.getJSONArray("runs").getJSONObject(0)
        val rules = run.getJSONObject("tool").getJSONObject("driver").getJSONArray("rules")
        val expected = fixtures.filter { it.kind != FindingKind.INFORMATIONAL }.map { it.id }.distinct().sorted()
        val actual = (0 until rules.length()).map { rules.getJSONObject(it).getString("id") }.sorted()
        assertEquals(expected, actual)
        for (i in 0 until rules.length()) {
            val rule = rules.getJSONObject(i)
            assertTrue(rule.getJSONObject("shortDescription").getString("text").isNotBlank())
            assertTrue(rule.getJSONObject("help").getString("text").isNotBlank())
            assertTrue(rule.getJSONObject("defaultConfiguration").getString("level") in setOf("error", "warning", "note"))
        }
        val results = run.getJSONArray("results")
        val ids = actual.toSet()
        for (i in 0 until results.length()) {
            val r = results.getJSONObject(i)
            assertTrue("ruleId ${r.getString("ruleId")} missing from rules", r.getString("ruleId") in ids)
            assertTrue(r.getInt("ruleIndex") in 0 until rules.length())
        }
    }

    @Test
    fun levelsFollowTheMapping() {
        val root = JSONObject(document())
        val results = root.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
        val byId = (0 until results.length()).associate { i ->
            val r = results.getJSONObject(i)
            r.getString("ruleId") to r.getString("level")
        }
        assertEquals("error", byId["TEST-CRITICAL"])
        assertEquals("error", byId["TEST-HIGH"])
        assertEquals("warning", byId["TEST-MEDIUM"])
        assertEquals("warning", byId["TEST-LOW"])
        assertEquals("note", byId["TEST-SUSPECT"])
        assertFalse("informational inventory must be omitted", byId.containsKey("TEST-INFO"))
    }

    @Test
    fun neverLeaksEvidenceAndNeverFabricatesRegions() {
        val json = document()
        assertFalse("evidence snippet leaked", json.contains("SNIPPET_LEAK_CANARY"))
        assertFalse("evidence value leaked", json.contains("VALUE_LEAK_CANARY"))
        assertFalse("no source region may be invented", json.contains("\"region\""))
        val root = JSONObject(json)
        val results = root.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
        val first = results.getJSONObject(0)
        val uri = first.getJSONArray("locations").getJSONObject(0)
            .getJSONObject("physicalLocation").getJSONObject("artifactLocation").getString("uri")
        assertEquals("file:///tmp/scan-target.apk", uri)
    }

    @Test
    fun fingerprintsUseSafeIdentityAndAreStable() {
        val a = JSONObject(document())
        val b = JSONObject(document())
        val ra = a.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
        val rb = b.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
        assertEquals(ra.length(), rb.length())
        for (i in 0 until ra.length()) {
            val fa = ra.getJSONObject(i).getJSONObject("partialFingerprints")
            val fb = rb.getJSONObject(i).getJSONObject("partialFingerprints")
            assertEquals(fa.getString("flutterguardEvidence/v1"), fb.getString("flutterguardEvidence/v1"))
            assertEquals(1, fa.length())
        }
        val withEvidence = (0 until ra.length())
            .map { ra.getJSONObject(it) }
            .first { it.getString("ruleId") == "TEST-CRITICAL" }
        assertEquals(
            "TEST-CRITICAL|lib/arm64-v8a/libapp.so",
            withEvidence.getJSONObject("partialFingerprints").getString("flutterguardEvidence/v1"),
        )
    }

    private fun mutated(block: (JSONObject) -> Unit): String {
        val root = JSONObject(document())
        block(root)
        return root.toString()
    }

    private fun assertInvalid(name: String, json: String) {
        val failure = runCatching { Sarif.validate(json) }.exceptionOrNull()
        assertTrue("$name must be rejected by validate()", failure is IllegalArgumentException)
    }

    @Test
    fun validateRejectsAnIncompleteDocument() {
        Sarif.validate(document()) // the generated document must pass

        assertInvalid("missing \$schema", mutated { it.remove("\$schema") })
        assertInvalid(
            "missing message text",
            mutated { root ->
                root.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
                    .getJSONObject(0).getJSONObject("message").put("text", "")
            },
        )
        assertInvalid(
            "missing artifact uri",
            mutated { root ->
                root.getJSONArray("runs").getJSONObject(0).getJSONArray("results").getJSONObject(0)
                    .getJSONArray("locations").getJSONObject(0)
                    .getJSONObject("physicalLocation").getJSONObject("artifactLocation").remove("uri")
            },
        )
        assertInvalid(
            "unknown level",
            mutated { root ->
                root.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
                    .getJSONObject(0).put("level", "fatal")
            },
        )
        assertInvalid(
            "unknown rule reference",
            mutated { root ->
                root.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
                    .getJSONObject(0).put("ruleId", "NOT-A-RULE")
            },
        )
    }
}
