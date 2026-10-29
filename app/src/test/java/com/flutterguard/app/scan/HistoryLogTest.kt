package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Versioned per-app scan log: stamps, ordering, per-version diff, bounded retention. */
class HistoryLogTest {

    private fun report(
        versionName: String?,
        versionCode: Long,
        grade: Char,
        generatedAt: Long,
        hosts: List<String> = emptyList(),
    ) = Report(
        meta = AppMeta(
            packageName = "com.example.app",
            label = "Example",
            versionName = versionName,
            versionCode = versionCode,
            minSdk = 26,
            targetSdk = 35,
            installer = null,
            firstInstallMs = 0,
            lastUpdateMs = 0,
            isSystem = false,
            sizeBytes = 1024,
            splitCount = 0,
            abis = emptyList(),
            nativeLibs = emptyList(),
            baseSha256 = "",
        ),
        framework = FrameworkInfo(isFlutter = true),
        signing = SigningInfo(
            signerSubject = null,
            signerIssuer = null,
            sha256Fingerprint = null,
            debugCert = false,
            multipleSigners = false,
            rotationHistory = false,
            validFrom = null,
            validTo = null,
            sigAlgorithm = null,
        ),
        findings = emptyList(),
        hosts = hosts.map { HostInfo(host = it, classification = "app") },
        channels = emptyList(),
        thirdParty = emptyList(),
        permissions = emptyList(),
        deepLinks = emptyList(),
        stats = ReportStats(0, 0, 0, 0, 0, stringsScanned = 0, durationMs = 0),
        grade = grade,
        generatedAt = generatedAt,
    )

    private val first = report("1.0.0", 1, 'B', generatedAt = 1_700_000_000_000, hosts = listOf("a.example"))
    private val second = report("1.1.0", 2, 'C', generatedAt = 1_700_000_100_000, hosts = listOf("a.example", "b.example"))

    @Test
    fun snapshotIsStampedWithVersionAndTimestamp() {
        val snapshot = History.snapshot(first)
        assertTrue(snapshot, snapshot.startsWith("stamp:1700000000000|1.0.0|1|B"))
        // The existing diff keys must survive the extra header line.
        assertTrue(snapshot.contains("version:1.0.0 (1)"))
        assertEquals(snapshot, History.snapshot(first))
    }

    @Test
    fun diffIgnoresTheStampLine() {
        val diff = History.diff(History.snapshot(first), History.snapshot(second))
        assertTrue(diff.contains("~ version 1.0.0 (1) → 1.1.0 (2)"))
        assertTrue(diff.contains("+ host b.example"))
    }

    @Test
    fun entriesStayOrderedOldestFirstAndRetainStamps() {
        val log = ScanLog.append(ScanLog.append(null, History.snapshot(first)), History.snapshot(second))
        val entries = ScanLog.decode(log)
        assertEquals(2, entries.size)
        assertEquals(listOf(1L, 2L), entries.map { it.versionCode })
        assertEquals(listOf(1_700_000_000_000, 1_700_000_100_000), entries.map { it.stampedAtMs })
        assertEquals(listOf("1.0.0", "1.1.0"), entries.map { it.versionName })
        assertEquals(listOf('B', 'C'), entries.map { it.grade })
    }

    @Test
    fun reappendingTheSameSnapshotDoesNotDuplicateTheEntry() {
        val once = ScanLog.append(null, History.snapshot(first))
        val twice = ScanLog.append(once, History.snapshot(first))
        assertEquals(1, ScanLog.decode(twice).size)
    }

    @Test
    fun logIsBoundedAndKeepsTheNewestEntries() {
        var log: String? = null
        for (i in 1..(ScanLog.MAX_ENTRIES + 12)) {
            log = ScanLog.append(log, History.snapshot(report("2.0.$i", i.toLong(), 'A', generatedAt = i.toLong())))
        }
        val entries = ScanLog.decode(log)
        assertEquals(ScanLog.MAX_ENTRIES, entries.size)
        assertEquals(ScanLog.MAX_ENTRIES.toLong() + 12, entries.last().versionCode)
        assertEquals(13L, entries.first().versionCode)
    }

    @Test
    fun diffIsComputedAgainstThePreviousEntryOfTheSameVersion() {
        val sameVersion = report("1.0.0", 1, 'B', generatedAt = 1_700_000_200_000, hosts = listOf("a.example", "c.example"))
        val log = ScanLog.append(
            ScanLog.append(ScanLog.append(null, History.snapshot(first)), History.snapshot(second)),
            History.snapshot(sameVersion),
        )
        val entries = ScanLog.decode(log)

        assertTrue(ScanLog.diffForPreviousVersion(entries, 1).isEmpty())
        assertEquals(listOf("+ host c.example"), ScanLog.diffForPreviousVersion(entries, 2))
        assertTrue(ScanLog.diffForPreviousVersion(entries, 0).isEmpty())
    }

    @Test
    fun legacySnapshotWithoutStampStillDecodes() {
        val legacy = "version:0.9.0 (9)\nhosts:a.example\nroutes:\nfindings:\ndeps:"
        val entries = ScanLog.decode(legacy)
        assertEquals(1, entries.size)
        assertEquals(0L, entries.first().stampedAtMs)
        assertEquals(9L, entries.first().versionCode)
        assertEquals("0.9.0", entries.first().versionName)
        assertEquals(null, entries.first().grade)
        assertFalse(entries.first().snapshot.isEmpty())
    }

    @Test
    fun decodeToleratesEmptyAndGarbage() {
        assertTrue(ScanLog.decode(null).isEmpty())
        assertTrue(ScanLog.decode("").isEmpty())
        assertTrue(ScanLog.decode("   ").isEmpty())
    }

    @Test
    fun aValueContainingTheBlockSeparatorRoundTripsAsOneEntry() {
        // Artifact text is attacker-controlled; a route/host containing the
        // separator must not split the snapshot into two bogus entries.
        val nasty = report(
            "1.0.0",
            1,
            'B',
            generatedAt = 1_700_000_000_000,
            hosts = listOf("a.example\n#---\nhosts:evil.example"),
        )
        val snapshot = History.snapshot(nasty)
        assertTrue(snapshot, snapshot.contains("\n#---\n"))

        val log = ScanLog.append(null, snapshot)
        val entries = ScanLog.decode(log)
        assertEquals(1, entries.size)
        assertEquals(snapshot.trim(), entries.first().snapshot)

        val two = ScanLog.append(log, History.snapshot(report("1.0.1", 2, 'A', generatedAt = 1_700_000_100_000)))
        assertEquals(2, ScanLog.decode(two).size)
    }

    @Test
    fun anEmbeddedStampLineCannotForgeTheLogHeader() {
        // N8: a recovered value containing a newline + "stamp:" must stay a value;
        // the version/timestamp/grade shown in history come from the real header only.
        val nasty = report(
            "1.0.0",
            1,
            'B',
            generatedAt = 1_700_000_000_000,
            hosts = listOf("a.example\nstamp:1|9.9|99|F"),
        )
        val log = ScanLog.append(null, History.snapshot(nasty))
        val entries = ScanLog.decode(log)
        assertEquals(1, entries.size)
        assertEquals(1_700_000_000_000, entries.first().stampedAtMs)
        assertEquals("1.0.0", entries.first().versionName)
        assertEquals(1L, entries.first().versionCode)
        assertEquals('B', entries.first().grade)
        // The snapshot itself still round-trips byte for byte.
        assertEquals(History.snapshot(nasty).trim(), entries.first().snapshot)
    }

    @Test
    fun anUnreadableHistoryLogIsNotOverwritten() {
        val dir = createTempDir("fg-hist-read")
        try {
            // A directory at the history path makes readText() throw while exists() is true.
            assertTrue(java.io.File(dir, "com_example_app.hist").mkdirs())
            val saved = ReportFiles.save(dir, "com.example.app", "{\"a\":1}", "version:1")
            assertEquals("{\"a\":1}", saved.json.readText())
            assertEquals(null, saved.history)
            assertTrue(saved.historyNote.orEmpty(), saved.historyNote.orEmpty().contains("left untouched"))
            assertTrue(java.io.File(dir, "com_example_app.hist").isDirectory)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun reportSaveKeepsTheVersionLogOnDisk() {
        val dir = createTempDir("fg-log")
        try {
            ReportFiles.save(dir, "com.example.app", "{\"v\":1}", History.snapshot(first))
            val saved = ReportFiles.save(dir, "com.example.app", "{\"v\":2}", History.snapshot(second))
            val hist = ReportFiles.historyFile(dir, "com.example.app").readText()

            val entries = ScanLog.decode(hist)
            assertEquals(listOf(1L, 2L), entries.map { it.versionCode })
            assertEquals("{\"v\":2}", saved.json.readText())
            assertEquals(2L, entries.last().versionCode)
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun createTempDir(prefix: String) =
        java.nio.file.Files.createTempDirectory(prefix).toFile()
}
