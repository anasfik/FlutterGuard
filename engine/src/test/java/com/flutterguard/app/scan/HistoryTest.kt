package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HistoryTest {

    private val before = listOf(
        "version:5.0.0 (42)",
        "hosts:api.invidious.io|song.link|www.youtube.com",
        "routes:/api/v1|/v1/player",
        "findings:HIGH|MAN-CLEARTEXT|MEDIUM|MAN-BACKUP",
        "deps:dio|irondash_engine_context|jiosaavn",
    ).joinToString("\n")

    private val after = listOf(
        "version:5.1.2 (45)",
        "hosts:www.youtube.com|www.jiosaavn.com",
        "routes:/api/v1|/api/skipSegments",
        "findings:HIGH|MAN-CLEARTEXT|HIGH|SEC-KEY-GOOGLE",
        "deps:dio|smtc_windows",
    ).joinToString("\n")

    @Test
    fun reportsVersionAndMembershipChanges() {
        val lines = History.diff(before, after)
        assertEquals("~ version 5.0.0 (42) → 5.1.2 (45)", lines.first())
        assertTrue(lines.contains("- host api.invidious.io"))
        assertTrue(lines.contains("- host song.link"))
        assertTrue(lines.contains("+ host www.jiosaavn.com"))
        assertTrue(lines.contains("- route /v1/player"))
        assertTrue(lines.contains("+ route /api/skipSegments"))
        assertTrue(lines.contains("- finding MEDIUM|MAN-BACKUP"))
        assertTrue(lines.contains("+ finding HIGH|SEC-KEY-GOOGLE"))
        assertTrue(lines.contains("- dep irondash_engine_context"))
        assertTrue(lines.contains("+ dep smtc_windows"))
        // unchanged entries must not appear
        assertTrue(lines.none { it.contains("www.youtube.com") })
        assertTrue(lines.none { it.contains("/api/v1") })
    }

    @Test
    fun saysSoWhenNothingChanged() {
        val lines = History.diff(before, before)
        assertEquals(1, lines.size)
        assertTrue(lines.first().startsWith("no change"))
    }

    private fun snapshot(
        versionName: String,
        versionCode: Long,
        hosts: List<String>,
        permissions: List<String>,
    ) = History.snapshot(
        Report(
            meta = AppMeta(
                packageName = "com.example.app", label = "Example", versionName = versionName,
                versionCode = versionCode, minSdk = 26, targetSdk = 35, installer = null,
                firstInstallMs = 0, lastUpdateMs = 0, isSystem = false, sizeBytes = 1024,
                splitCount = 0, abis = emptyList(), nativeLibs = emptyList(), baseSha256 = "",
            ),
            framework = FrameworkInfo(isFlutter = true),
            signing = SigningInfo(
                signerSubject = null, signerIssuer = null, sha256Fingerprint = "AA:BB:CC",
                debugCert = false, multipleSigners = false, rotationHistory = false,
                validFrom = null, validTo = null, sigAlgorithm = null,
            ),
            findings = emptyList(),
            hosts = hosts.map { HostInfo(it, "app") },
            channels = emptyList(),
            thirdParty = emptyList(),
            permissions = permissions.map { PermissionHit(it, "dangerous", "") },
            deepLinks = emptyList(),
            stats = ReportStats(0, 0, 0, 0, 0, 0, 0),
            grade = 'A',
        ),
    )

    /**
     * The inline card must describe the newest scan pair. Reading the whole log
     * accumulates extended categories across every block, so a removal from two
     * releases ago is blamed on today's scan and a re-added value disappears.
     */
    @Test
    fun diffAgainstLatestInComparesOnlyTheNewestRecordedScan() {
        val v1 = snapshot("1.0.0", 1, listOf("a.example"), listOf("android.permission.CAMERA"))
        val v2 = snapshot("1.1.0", 2, listOf("b.example"), emptyList())
        val v3 = snapshot("1.2.0", 3, listOf("b.example"), emptyList())
        val v4 = snapshot("1.3.0", 4, listOf("b.example"), listOf("android.permission.CAMERA"))

        // The v2 card is genuinely the v1→v2 pair.
        val v2Lines = History.diffAgainstLatestIn(ScanLog.append(null, v1), v2)
        assertTrue(v2Lines.toString(), v2Lines.contains("- permission android.permission.CAMERA"))
        assertTrue(v2Lines.toString(), v2Lines.contains("+ host b.example"))

        // v3 differs from v2 only by version: v1's permission and host are not
        // v3's change, and v2's removal must not be re-reported.
        val logV1V2 = ScanLog.append(ScanLog.append(null, v1), v2)
        val v3Lines = History.diffAgainstLatestIn(logV1V2, v3)
        assertFalse(v3Lines.toString(), v3Lines.any { it.startsWith("- permission") })
        assertFalse(v3Lines.toString(), v3Lines.contains("+ host a.example"))

        // CAMERA present in v1, dropped in v2, re-added in v4: against v3 it is
        // an addition, not silence from the accumulated log.
        val logV1V2V3 = ScanLog.append(logV1V2, v3)
        val v4Lines = History.diffAgainstLatestIn(logV1V2V3, v4)
        assertTrue(v4Lines.toString(), v4Lines.contains("+ permission android.permission.CAMERA"))
        assertFalse(v4Lines.toString(), v4Lines.any { it.startsWith("- permission") })
        assertFalse(v4Lines.toString(), v4Lines.contains("+ host a.example"))
    }

    @Test
    fun diffAgainstLatestInReturnsNothingForAnEmptyOrUnparseableLog() {
        val current = snapshot("1.0.0", 1, listOf("a.example"), emptyList())
        assertEquals(emptyList<String>(), History.diffAgainstLatestIn("", current))
        assertEquals(emptyList<String>(), History.diffAgainstLatestIn("not a snapshot", current))
    }

    @Test
    fun capsTheNumberOfLines() {
        val hosts = (1..20).joinToString("|") { "h$it.example" }
        val routes = (1..20).joinToString("|") { "/r$it" }
        val findings = (1..20).joinToString("|") { "LOW|F$it" }
        val deps = (1..20).joinToString("|") { "d$it" }
        val old = "version:1 (1)\nhosts:\nroutes:\nfindings:\ndeps:"
        val new = "version:1 (1)\nhosts:$hosts\nroutes:$routes\nfindings:$findings\ndeps:$deps"
        val lines = History.diff(old, new)
        assertTrue("diff grew to ${lines.size} lines", lines.size <= 40)
        assertTrue(lines.last(), lines.last().contains("more"))
    }
}
