package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Snapshot metadata is additive and optional: a report without it decodes as
 * unknown, never as a fabricated AOT/obfuscation value.
 */
class FrameworkSnapshotJsonTest {

    private fun report(framework: FrameworkInfo) = Report(
        meta = AppMeta(
            packageName = "com.example.app", label = "Example", versionName = null, versionCode = 1,
            minSdk = null, targetSdk = null, installer = null, firstInstallMs = 0, lastUpdateMs = 0,
            isSystem = false, sizeBytes = 10, splitCount = 0, abis = emptyList(), nativeLibs = emptyList(),
            baseSha256 = "",
        ),
        framework = framework,
        signing = SigningInfo(null, null, null, false, false, false, null, null, null),
        findings = emptyList(), hosts = emptyList(), channels = emptyList(), thirdParty = emptyList(),
        permissions = emptyList(), deepLinks = emptyList(),
        stats = ReportStats(0, 0, 0, 0, 0, 0, 0),
        grade = 'A',
    )

    @Test
    fun snapshotFieldsRoundTripThroughTheReportSchema() {
        val framework = FrameworkInfo(
            isFlutter = true,
            snapshotKind = "full-AOT",
            snapshotHash = "ace654289f5abc240509fc941453ebc5",
            snapshotFeatures = listOf("product/arm64/android/compressed-pointers"),
        )
        val decoded = ReportJson.decode(ReportExport.toJson(report(framework)))
        assertNotNull(decoded)
        assertEquals("full-AOT", decoded!!.framework.snapshotKind)
        assertEquals("ace654289f5abc240509fc941453ebc5", decoded.framework.snapshotHash)
        assertEquals(listOf("product/arm64/android/compressed-pointers"), decoded.framework.snapshotFeatures)
    }

    @Test
    fun anUnknownOrNumericSnapshotKindDecodesAsUnknown() {
        fun json(kind: String) = """
            {
              "schema": "flutterguard/report/2",
              "meta": {"packageName": "com.example.app", "versionCode": 1},
              "framework": {"isFlutter": true, "snapshotKind": $kind},
              "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
              "findings": []
            }
        """.trimIndent()

        // A hand-edited number, a numeric string and an unknown label are not
        // kinds: the card must say unknown instead of rendering the raw value.
        for (raw in listOf("3", "\"3\"", "\"full-aot\"", "\"unknown\"")) {
            val decoded = ReportJson.decode(json(raw))
            assertNotNull("$raw must still decode as a report", decoded)
            assertNull("$raw is not a SnapshotKind label", decoded!!.framework.snapshotKind)
        }
        assertEquals("full-AOT", ReportJson.decode(json("\"full-AOT\""))!!.framework.snapshotKind)
    }

    @Test
    fun absentSnapshotFieldsAreOmittedAndDecodeAsUnknown() {
        val json = ReportExport.toJson(report(FrameworkInfo(isFlutter = true)))
        assertFalse("no kind key for an unread snapshot", json.contains("snapshotKind"))
        assertFalse("no hash key for an unread snapshot", json.contains("snapshotHash"))
        assertFalse("no features key for an unread snapshot", json.contains("snapshotFeatures"))

        val decoded = ReportJson.decode(json)
        assertNotNull(decoded)
        assertNull(decoded!!.framework.snapshotKind)
        assertNull(decoded.framework.snapshotHash)
        assertTrue(decoded.framework.snapshotFeatures.isEmpty())
    }
}
