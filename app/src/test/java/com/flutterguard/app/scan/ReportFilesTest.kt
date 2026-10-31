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
    fun aFileScanNeverOverwritesTheInstalledAppsReportOrHistory() {
        // A shared/picked APK can declare any package name. Writing it to the
        // installed app's slot would silently replace the verdict the researcher
        // already has for the app on the device — data loss, not a cosmetic bug.
        val dir = createTempDir("fg-file-namespace")
        try {
            ReportFiles.save(dir, "com.whatsapp", "{\"installed\":true}", "version:1")
            val installedJson = ReportFiles.jsonFile(dir, "com.whatsapp")
            val installedHist = ReportFiles.historyFile(dir, "com.whatsapp")

            val forged = ReportFiles.save(
                dir, "com.whatsapp", "{\"forged\":true}", "version:9", fileScan = true,
            )

            assertFalse("a file scan must not target the installed report", forged.json == installedJson)
            assertEquals("{\"installed\":true}", installedJson.readText())
            assertEquals(1, ScanLog.decode(installedHist.readText()).size)
            assertEquals("{\"forged\":true}", forged.json.readText())
            // The forged APK must not inherit the installed app's version log.
            assertEquals("version:9", ReportFiles.previousHistory(dir, "com.whatsapp", fileScan = true))
            assertEquals(installedHist.readText(), ReportFiles.previousHistory(dir, "com.whatsapp"))
            assertFalse(installedHist.readText().contains("version:9"))
            // Delete-all still removes both namespaces.
            assertEquals(4, ReportFiles.deleteAll(dir))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun legacyExternalReportsMoveIntoPrivateStorage() {
        val legacy = createTempDir("fg-legacy")
        val current = File(createTempDir("fg-current"), "reports")
        try {
            val report = File(legacy, "com_example_app.json").apply { writeText("{\"old\":true}") }
            val hist = File(legacy, "com_example_app.hist").apply { writeText("version:1") }
            File(legacy, "com_example_app.json.tmp").apply { writeText("partial") }

            assertEquals(2, ReportFiles.moveReports(legacy, current))

            assertEquals("{\"old\":true}", File(current, report.name).readText())
            assertEquals("version:1", File(current, hist.name).readText())
            assertFalse(report.exists())
            assertFalse(hist.exists())

            // A report the new build already wrote wins; the stale copy is dropped.
            File(current, "com_other.json").writeText("{\"new\":true}")
            File(legacy, "com_other.json").writeText("{\"old\":true}")
            assertEquals(1, ReportFiles.moveReports(legacy, current))
            assertEquals("{\"new\":true}", File(current, "com_other.json").readText())
            assertFalse(File(legacy, "com_other.json").exists())
        } finally {
            legacy.deleteRecursively()
            current.parentFile?.deleteRecursively()
        }
    }

    @Test
    fun aFileScanNeverResolvesToTheInstalledAppsStoredReport() {
        // org.json is stubbed in JVM tests, so this asserts the file the read path
        // picks, which is the part that can silently show the wrong app's verdict.
        val dir = createTempDir("fg-readnamespace")
        try {
            ReportFiles.save(dir, "com.whatsapp", "{\"installed\":true}", "version:1")
            // A stored report is present (decode needs org.json, absent on the JVM,
            // so it reads back as Unreadable — the point is that it is not Missing).
            assertTrue(ReportFiles.load(dir, "com.whatsapp") !is StoredReport.Missing)
            // No picked-APK report yet: it must be Missing, never the installed one.
            assertTrue(
                ReportFiles.load(dir, "com.whatsapp", fileScan = true) is StoredReport.Missing,
            )
            assertFalse(
                ReportFiles.jsonFile(dir, "com.whatsapp", true) ==
                    ReportFiles.jsonFile(dir, "com.whatsapp"),
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aTruncatedMigrationTargetIsReplacedByTheLegacyCopy() {
        val legacy = createTempDir("fg-legacy-trunc")
        val current = File(createTempDir("fg-current-trunc"), "reports").apply { mkdirs() }
        try {
            // A crash mid-copy can leave a zero-length target: never mistake it for
            // a finished report and delete the only good copy.
            File(current, "com_example_app.json").writeText("")
            File(legacy, "com_example_app.json").writeText("{\"old\":true}")

            assertEquals(1, ReportFiles.moveReports(legacy, current))

            assertEquals("{\"old\":true}", File(current, "com_example_app.json").readText())
            assertFalse(File(legacy, "com_example_app.json").exists())
            assertEquals(
                emptyList<String>(),
                current.listFiles()!!.map { it.name }.filter { it.endsWith(".tmp") },
            )
        } finally {
            legacy.deleteRecursively()
            current.parentFile?.deleteRecursively()
        }
    }

    @Test
    fun anOversizedLegacyFileIsDroppedInsteadOfLeftInSharedStorage() {
        val legacy = createTempDir("fg-legacy-big")
        val current = File(createTempDir("fg-current-big"), "reports").apply { mkdirs() }
        try {
            // 9 MB: bigger than any report we write, so it is not ours to keep.
            File(legacy, "com_huge.json").writeBytes(ByteArray(9 * 1024 * 1024))
            // One legacy file cleared: dropped, not copied.
            assertEquals(1, ReportFiles.moveReports(legacy, current))
            assertFalse("an oversized legacy report must not survive", File(legacy, "com_huge.json").exists())
            assertFalse(File(current, "com_huge.json").exists())

            // An unrelated file is left alone: it is not ours.
            File(legacy, "notes.txt").writeText("keep me")
            ReportFiles.moveReports(legacy, current)
            assertTrue(File(legacy, "notes.txt").exists())
        } finally {
            legacy.deleteRecursively()
            current.parentFile?.deleteRecursively()
        }
    }

    @Test
    fun inflightMarkersAreNamespacedToo() {
        val dir = createTempDir("fg-inflight-ns")
        try {
            ReportFiles.markInflight(dir, "com.example.app")
            ReportFiles.markInflight(dir, "com.example.app", fileScan = true)
            // Two markers on disk, one entry for the banner: the content is the
            // bare package name in both namespaces and `interrupted` de-duplicates.
            assertEquals(listOf("com.example.app"), ReportFiles.interrupted(dir))
            assertTrue(ReportFiles.inflightFile(dir, "com.example.app").exists())
            assertTrue(ReportFiles.inflightFile(dir, "com.example.app", fileScan = true).exists())
            // Clearing one namespace leaves the other's scan still marked.
            ReportFiles.clearInflight(dir, "com.example.app", fileScan = true)
            assertFalse(ReportFiles.inflightFile(dir, "com.example.app", fileScan = true).exists())
            assertTrue(ReportFiles.inflightFile(dir, "com.example.app").exists())
            assertEquals(listOf("com.example.app"), ReportFiles.interrupted(dir))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun inflightMarkerIdentifiesAnInterruptedScan() {
        val dir = createTempDir("fg-inflight")
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
