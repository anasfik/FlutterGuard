package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Persisted-report contract: exactly schema 1 and 2 are readable, kinds are
 * re-derived from the central catalog (a serialized kind may never upgrade an
 * ID), and the grade is always recomputed from decoded findings. Reading never
 * writes: [ReportJson.decode] returns a new report and the stored text is not
 * touched.
 */
class ReportJsonTest {

    @Test
    fun onlyTheKnownSchemasAreAccepted() {
        assertTrue(ReportJson.acceptsSchema(ReportJson.SCHEMA))
        assertTrue("schema 1 reports must stay readable", ReportJson.acceptsSchema("flutterguard/report/1"))
        assertEquals("flutterguard/report/2", ReportJson.SCHEMA)
        assertFalse("a missing schema must not default to a report", ReportJson.acceptsSchema(null))
        assertFalse(ReportJson.acceptsSchema(""))
        assertFalse("a future schema must not be decoded with today's defaults", ReportJson.acceptsSchema("flutterguard/report/3"))
        assertFalse(ReportJson.acceptsSchema("{\"a\":1}"))
    }

    @Test
    fun malformedOrSchemaLessTextIsRejected() {
        assertNull(ReportJson.decode("{"))
        assertNull(ReportJson.decode("{}"))
        assertNull(ReportJson.decode(""))
        assertNull(ReportJson.decode("{\"schema\":\"flutterguard/report/3\"}"))
        // A schema-1 file without identity is still not a report.
        assertNull(ReportJson.decode("{\"schema\":\"flutterguard/report/1\"}"))
    }

    @Test
    fun aLegacyCriticalPatternOnlyFindingDoesNotGradeTheApp() {
        // Schema 1 stored no kind and kept a total-severity grade. The only
        // finding is a PEM-shaped lead at CRITICAL: it must be preserved, but a
        // pattern is not a confirmed fact, so the recomputed grade is clean.
        val legacy = """
            {
              "schema": "flutterguard/report/1",
              "meta": {
                "packageName": "com.example.legacy", "label": "Legacy", "versionName": "1.0",
                "versionCode": 7, "sizeBytes": 4096, "splitCount": 0, "isSystem": false,
                "fileScan": false
              },
              "stats": {
                "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0,
                "stringsScanned": 11, "durationMs": 22
              },
              "grade": "F",
              "findings": [
                {
                  "id": "SEC-KEY-PRIVATE", "title": "Hardcoded private key material",
                  "severity": "CRITICAL", "detail": "Value found in libapp.so. Pattern: SEC-KEY-PRIVATE.",
                  "evidence": [{"source": "lib/arm64-v8a/libapp.so", "offset": 128, "snippet": "[64 chars hidden]"}],
                  "remediation": "rotate", "masvs": ["MASVS-CRYPTO-1"]
                }
              ]
            }
        """.trimIndent()

        val decoded = ReportJson.decode(legacy)
        assertNotNull("a schema-1 report must load", decoded)
        decoded!!
        assertEquals("com.example.legacy", decoded.meta.packageName)
        val finding = decoded.findings.single()
        assertEquals("the finding itself is preserved", "SEC-KEY-PRIVATE", finding.id)
        assertEquals(Severity.CRITICAL, finding.severity)
        assertEquals(FindingKind.SUSPECTED, finding.kind)
        assertEquals("the evidence row is preserved", "lib/arm64-v8a/libapp.so", finding.evidence.single().source)
        assertEquals(128L, finding.evidence.single().offset)
        assertEquals("[64 chars hidden]", finding.evidence.single().snippet)
        // Grade is recomputed from confirmed findings only; the stored F is ignored.
        assertEquals('A', decoded.grade)
        assertEquals("severity totals stay totals", 1, decoded.stats.critical)
        assertEquals(0, decoded.stats.confirmed)
        assertEquals(1, decoded.stats.suspected)
        assertEquals(0, decoded.stats.informational)
    }

    @Test
    fun schemaTwoRoundtripsKnownKindsAndRecomputesTheGrade() {
        val report = sampleReport()
        val json = ReportExport.toJson(report)
        assertTrue(json, json.contains("flutterguard/report/2"))

        val decoded = ReportJson.decode(json)
        assertNotNull(json, decoded)
        decoded!!
        assertEquals(report.findings.map { it.id }.toSet(), decoded.findings.map { it.id }.toSet())
        assertEquals(
            report.findings.associate { it.id to it.kind },
            decoded.findings.associate { it.id to it.kind },
        )
        assertEquals(gradeOf(report.findings), decoded.grade)
        assertEquals(report.findings.count { it.kind == FindingKind.CONFIRMED }, decoded.stats.confirmed)
        assertEquals(report.findings.count { it.kind == FindingKind.SUSPECTED }, decoded.stats.suspected)
        assertEquals(report.findings.count { it.kind == FindingKind.INFORMATIONAL }, decoded.stats.informational)
    }

    @Test
    fun aStoredKindCanOnlyLowerConfidence() {
        fun stored(kind: String, id: String, severity: String, grade: String) = """
            {
              "schema": "flutterguard/report/2",
              "meta": {"packageName": "com.example.clamp", "versionCode": 1},
              "grade": "$grade",
              "stats": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
              "findings": [
                {"id": "$id", "title": "t", "severity": "$severity", "detail": "d",
                 "evidence": [], "remediation": "r", "kind": "$kind"}
              ]
            }
        """.trimIndent()

        // Unknown/lead ID claiming CONFIRMED is clamped to SUSPECTED.
        val upgraded = ReportJson.decode(stored("CONFIRMED", "SEC-KEY-AWS", "HIGH", "F"))!!
        assertEquals(FindingKind.SUSPECTED, upgraded.findings.single().kind)
        assertEquals("stored grade F is not trusted", 'A', upgraded.grade)

        // A confirmed ID serialized as INFORMATIONAL stays the less certain kind.
        val downgraded = ReportJson.decode(stored("INFORMATIONAL", "MAN-DEBUG", "HIGH", "A"))!!
        assertEquals(FindingKind.INFORMATIONAL, downgraded.findings.single().kind)
        assertEquals('A', downgraded.grade)

        // A serialized unknown kind is ignored in favour of the catalog.
        val unknown = ReportJson.decode(stored("SUPER-SURE", "MAN-DEBUG", "HIGH", "A"))!!
        assertEquals(FindingKind.CONFIRMED, unknown.findings.single().kind)
        assertEquals('C', unknown.grade)
    }

    private fun sampleReport(): Report {
        val meta = AppMeta(
            "com.example.roundtrip", "Roundtrip", "1.0", 3, 26, 35, null, 0, 0, false, 100, 0,
            emptyList(), emptyList(), "",
        )
        val findings = listOf(
            Finding(
                "MAN-DEBUG", "App is debuggable", Severity.HIGH,
                "android:debuggable=true", emptyList(), "ship release builds",
            ),
            Finding(
                "SEC-KEY-AWS", "AWS access key id embedded", Severity.HIGH,
                "Value found in classes.dex. Pattern: SEC-KEY-AWS.",
                listOf(Evidence("classes.dex", 42, "[20 chars hidden]")), "rotate",
            ),
            Finding(
                "NET-CLEARTEXT", "NSC permits cleartext traffic", Severity.INFO,
                "loopback only", emptyList(), "keep it loopback",
            ),
            Finding(
                "FLUT-NOTICES", "Dependency inventory", Severity.INFO,
                "https://NOTICES.Z", emptyList(), "patch dependencies",
            ),
        )
        return Report(
            meta = meta,
            framework = FrameworkInfo(isFlutter = true),
            signing = SigningInfo(null, null, null, false, false, false, null, null, null, emptyList(), emptyList()),
            findings = findings,
            hosts = emptyList(),
            channels = emptyList(),
            thirdParty = emptyList(),
            permissions = emptyList(),
            deepLinks = emptyList(),
            stats = ReportStats(0, 3, 0, 0, 2, 10, 5),
            grade = gradeOf(findings),
        )
    }
}
