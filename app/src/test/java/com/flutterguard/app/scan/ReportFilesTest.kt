package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/** Atomic report storage: a failed save must never replace a good report or history. */
class ReportFilesTest {

    @Test
    fun saveWritesBothFilesAndLeavesNoTemporaryResidue() {
        val dir = createTempDir("fg-save")
        try {
            val saved = ReportFiles.save(dir, "com.example.app", "{\"a\":1}", "version:1")
            assertEquals("{\"a\":1}", saved.json.readText())
            assertEquals("version:1", File(dir, "com_example_app.hist").readText())
            assertNull(saved.historyNote)
            assertEquals(emptyList<String>(), dir.listFiles()!!.map { it.name }.filter { it.endsWith(".tmp") })

            ReportFiles.save(dir, "com.example.app", "{\"a\":2}", "version:2")
            assertEquals("{\"a\":2}", File(dir, "com_example_app.json").readText())
            // The history file is now a bounded per-app log: the newest snapshot
            // is last, previous scans are retained for the version diff.
            val hist = File(dir, "com_example_app.hist").readText()
            assertTrue(hist, hist.trimEnd().endsWith("version:2"))
            assertTrue(hist, hist.contains("version:1"))
            assertEquals(listOf(-1L, -1L), ScanLog.decode(hist).map { it.versionCode })
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun failedSaveKeepsThePreviousGoodReport() {
        val dir = createTempDir("fg-save-fail")
        try {
            val good = ReportFiles.save(dir, "com.example.app", "{\"good\":true}", "version:1")
            val jsonBytes = good.json.readText()

            // Occupy the target path with a directory so the atomic rename cannot succeed.
            val target = File(dir, "com.example.app".replace('.', '_') + ".json")
            target.delete()
            assertTrue(target.mkdirs())

            try {
                ReportFiles.save(dir, "com.example.app", "{\"partial\":true}", "version:2")
                fail("save must report the failure")
            } catch (_: Throwable) {
                // expected
            }
            assertEquals("version:1", File(dir, "com_example_app.hist").readText())
            assertTrue(target.isDirectory)
            assertFalse(File(dir, "com_example_app.json.tmp").exists())
            assertFalse(jsonBytes.isEmpty())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun historyFailureIsReportedWithoutLosingTheReport() {
        val dir = createTempDir("fg-save-hist")
        try {
            // A directory where the history file must go makes only that rename fail.
            assertTrue(File(dir, "com_example_app.hist").mkdirs())
            val saved = ReportFiles.save(dir, "com.example.app", "{\"a\":1}", "version:1")
            assertEquals("{\"a\":1}", saved.json.readText())
            assertTrue(saved.historyNote != null && saved.historyNote!!.isNotBlank())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun clearingInterruptedMarkersKeepsTheLiveScanMarker() {
        val dir = createTempDir("fg-inflight-live")
        try {
            ReportFiles.markInflight(dir, "com.live.app")
            ReportFiles.markInflight(dir, "com.stale.app")
            val reported = ReportFiles.interrupted(dir, keep = listOf("com.live.app"))
            assertEquals(listOf("com.stale.app"), reported)

            ReportFiles.clearInterrupted(dir, keep = listOf("com.live.app"))
            assertEquals(listOf("com.live.app"), ReportFiles.interrupted(dir))
            assertTrue(File(dir, "com_live_app.inflight").exists())
            assertFalse(File(dir, "com_stale_app.inflight").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aMissingReportIsReportedAsMissingNotUnreadable() {
        val dir = createTempDir("fg-load-missing")
        try {
            assertEquals(StoredReport.Missing, ReportFiles.load(dir, "com.example.app"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aReportThatBelongsToAnotherPackageIsRejected() {
        // `com.a_b` and `com.a.b` share one file name (baseName maps `.` to `_`),
        // and a researcher can `adb push` any JSON: identity must be checked.
        val mine = report("com.a.b")
        assertTrue(ReportFiles.ownedBy("com.a.b", mine))
        assertFalse(ReportFiles.ownedBy("com.a_b", mine))
        assertFalse(ReportFiles.ownedBy("com.other", mine))
    }

    @Test
    fun anOversizeReportIsRejectedBeforeItIsRead() {
        val dir = createTempDir("fg-load-oversize")
        try {
            val file = ReportFiles.jsonFile(dir, "com.example.app")
            // Sparse file: the size gate must fire before readText() allocates it.
            java.io.RandomAccessFile(file, "rw").use { it.setLength(ReportFiles.MAX_REPORT_BYTES + 1) }
            val loaded = ReportFiles.load(dir, "com.example.app")
            assertTrue(loaded is StoredReport.Unreadable)
            assertTrue((loaded as StoredReport.Unreadable).message, loaded.message.contains("too large"))
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun report(pkg: String) = Report(
        meta = AppMeta(pkg, "Example", "1", 1, 26, 35, null, 0, 0, false, 0, 0, emptyList(), emptyList(), ""),
        framework = FrameworkInfo(isFlutter = true),
        signing = SigningInfo(null, null, null, false, false, false, null, null, null, emptyList(), emptyList()),
        findings = emptyList(),
        hosts = emptyList(),
        channels = emptyList(),
        thirdParty = emptyList(),
        permissions = emptyList(),
        deepLinks = emptyList(),
        stats = ReportStats(0, 0, 0, 0, 0, 0, 0),
        grade = 'A',
    )

    @Test
    fun inflightMarkerIdentifiesAnInterruptedScan() {        val dir = createTempDir("fg-inflight")
        try {
            ReportFiles.markInflight(dir, "com.example.app")
            ReportFiles.markInflight(dir, "com.other.app")
            assertEquals(listOf("com.example.app", "com.other.app"), ReportFiles.interrupted(dir))
            ReportFiles.clearInflight(dir, "com.example.app")
            assertEquals(listOf("com.other.app"), ReportFiles.interrupted(dir))
            ReportFiles.clearInterrupted(dir)
            assertEquals(emptyList<String>(), ReportFiles.interrupted(dir))
        } finally {
            dir.deleteRecursively()
        }
    }
}
