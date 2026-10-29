package com.flutterguard.app.ui

import com.flutterguard.app.scan.AppMeta
import com.flutterguard.app.scan.FrameworkInfo
import com.flutterguard.app.scan.HostInfo
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportStats
import com.flutterguard.app.scan.ScanJob
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.ScanStartPolicy
import com.flutterguard.app.scan.SigningInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A1/A2: the shown report comes from the live job, the last success, or the persisted file; another scan never blanks it. */
class DetailPhaseTest {

    private fun report(label: String = "A") = Report(
        meta = AppMeta(
            packageName = "com.a", label = label, versionName = "1", versionCode = 1,
            minSdk = 26, targetSdk = 35, installer = null, firstInstallMs = 0, lastUpdateMs = 0,
            isSystem = false, sizeBytes = 1, splitCount = 0, abis = emptyList(),
            nativeLibs = emptyList(), baseSha256 = "",
        ),
        framework = FrameworkInfo(isFlutter = true),
        signing = SigningInfo(
            signerSubject = null, signerIssuer = null, sha256Fingerprint = null, debugCert = false,
            multipleSigners = false, rotationHistory = false, validFrom = null, validTo = null, sigAlgorithm = null,
        ),
        findings = emptyList(), hosts = emptyList(), channels = emptyList(), thirdParty = emptyList(),
        permissions = emptyList(), deepLinks = emptyList(),
        stats = ReportStats(0, 0, 0, 0, 0, 0, 0), grade = 'A',
    )

    private val ownDone = ScanPhase.Done(ScanJob(3, "com.a", 0), report("live"), "/tmp/a.json")
    private val otherRunning = ScanPhase.Running(ScanJob(4, "com.b", 0))

    @Test
    fun storedReportIsShownWhenNothingIsInMemory() {
        val stored = report("stored")
        assertEquals("stored", DetailPhase.report(ScanPhase.Idle, null, "com.a", stored)?.meta?.label)
        assertEquals(DetailPane.REPORT, DetailPhase.pane(ScanPhase.Idle, "com.a", hasReport = true))
    }

    @Test
    fun lastSuccessWinsOverTheStoredFileAndTheLiveJobWinsOverBoth() {
        val stored = report("stored")
        assertEquals("stored", DetailPhase.report(ScanPhase.Idle, null, "com.a", stored)?.meta?.label)
        assertEquals(
            "stored",
            DetailPhase.report(otherRunning, null, "com.a", stored)?.meta?.label,
        )
        assertEquals("live", DetailPhase.report(ownDone, null, "com.a", report("stored"))?.meta?.label)
    }

    @Test
    fun anotherPackagesScanDoesNotBlankTheReport() {
        assertEquals(DetailPane.REPORT, DetailPhase.pane(otherRunning, "com.a", hasReport = true))
        assertEquals(DetailPane.OTHER_SCAN, DetailPhase.pane(otherRunning, "com.a", hasReport = false))
        assertEquals("com.b", DetailPhase.runningElsewhere(otherRunning, "com.a", hasReport = true))
        assertNull(DetailPhase.runningElsewhere(otherRunning, "com.a", hasReport = false))
    }

    @Test
    fun ownScanShowsProgressAndFailureShowsFailure() {
        val selfRunning = ScanPhase.Running(ScanJob(8, "com.a", 0))
        assertEquals(DetailPane.PROGRESS, DetailPhase.pane(selfRunning, "com.a", hasReport = false))
        assertEquals(DetailPane.PROGRESS, DetailPhase.pane(selfRunning, "com.a", hasReport = true))
        assertEquals(
            DetailPane.FAILURE,
            DetailPhase.pane(ScanPhase.Failed(ScanJob(9, "com.a", 0), "boom"), "com.a", hasReport = false),
        )
        assertEquals(DetailPane.NOT_STARTED, DetailPhase.pane(ScanPhase.Idle, "com.a", hasReport = false))
    }

    @Test
    fun anotherPackagesFailureIsNeverThisAppsFailure() {
        // A2: com.b failing on Home must not show "Could not audit this app" for the
        // never-scanned com.a, whose message would be built from a null failure.
        val otherFailed = ScanPhase.Failed(ScanJob(9, "com.b", 0), "boom")
        val otherCancelled = ScanPhase.Cancelled(ScanJob(10, "com.b", 0))
        assertEquals(DetailPane.NOT_STARTED, DetailPhase.pane(otherFailed, "com.a", hasReport = false))
        assertEquals(DetailPane.NOT_STARTED, DetailPhase.pane(otherCancelled, "com.a", hasReport = false))
        // With a report on screen the report still wins over any failure.
        assertEquals(DetailPane.REPORT, DetailPhase.pane(otherFailed, "com.a", hasReport = true))
        // The owner's own failure is still a failure.
        assertEquals(
            DetailPane.FAILURE,
            DetailPhase.pane(ScanPhase.Cancelled(ScanJob(11, "com.a", 0)), "com.a", hasReport = false),
        )
    }

    @Test
    fun openingAStoredReportNeverAutoStartsAScan() {
        assertFalse(ScanStartPolicy.shouldAutoStart(ScanPhase.Idle, "com.a", queueActive = false, hasReport = true))
        assertTrue(ScanStartPolicy.shouldAutoStart(ScanPhase.Idle, "com.a", queueActive = false, hasReport = false))
        assertFalse(ScanStartPolicy.shouldAutoStart(ScanPhase.Idle, "com.a", queueActive = true, hasReport = false))
    }

    @Test
    fun unverifiedHostsNeverProduceAnOpenUrl() {
        assertNull(EndpointRow(HostInfo("appflowy.comworkspace", "app"), "appflowy.comworkspace", null, false).url)
    }
}
