package com.flutterguard.app.scan

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * End-to-end wiring: the scanner reaches the snapshot header through the APK
 * entry and the report keeps the observed facts across JSON.
 */
class DartSnapshotScanIntegrationTest {

    private fun apk(): File? =
        listOf(
            "../benchmark-app/dist/benchmark-plain-release.apk",
            "benchmark-app/dist/benchmark-plain-release.apk",
        ).map { File(it) }.firstOrNull { it.isFile }

    @Test
    fun releaseApkReportCarriesTheObservedSnapshotHeader() = runBlocking {
        val apk = apk()
        assumeTrue("owned fixture absent", apk != null)
        val report = Scanner.scanFile(apk!!, onProgress = { _, _ -> })

        assertEquals("full-AOT", report.framework.snapshotKind)
        assertEquals("ace654289f5abc240509fc941453ebc5", report.framework.snapshotHash)
        assertTrue(
            "features: ${report.framework.snapshotFeatures}",
            report.framework.snapshotFeatures.containsAll(listOf("product", "arm64", "compressed-pointers")),
        )

        val decoded = ReportJson.decode(ReportExport.toJson(report))
        assertNotNull(decoded)
        assertEquals("full-AOT", decoded!!.framework.snapshotKind)
        assertEquals("ace654289f5abc240509fc941453ebc5", decoded.framework.snapshotHash)
    }
}
