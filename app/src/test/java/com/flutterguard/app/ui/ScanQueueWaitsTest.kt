package com.flutterguard.app.ui

import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ScanJob
import com.flutterguard.app.scan.ScanPhase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The two queue waits must belong to the job the queue started. A stale
 * Done/Failed/Cancelled of the same package is not this job's outcome.
 */
class ScanQueueWaitsTest {

    private fun report(): Report = com.flutterguard.app.scan.Report(
        meta = com.flutterguard.app.scan.AppMeta(
            packageName = "com.x", label = "X", versionName = "1", versionCode = 1,
            minSdk = 26, targetSdk = 35, installer = null, firstInstallMs = 0, lastUpdateMs = 0,
            isSystem = false, sizeBytes = 1, splitCount = 0, abis = emptyList(),
            nativeLibs = emptyList(), baseSha256 = "",
        ),
        framework = com.flutterguard.app.scan.FrameworkInfo(isFlutter = true),
        signing = com.flutterguard.app.scan.SigningInfo(
            signerSubject = null, signerIssuer = null, sha256Fingerprint = null, debugCert = false,
            multipleSigners = false, rotationHistory = false, validFrom = null, validTo = null, sigAlgorithm = null,
        ),
        findings = emptyList(), hosts = emptyList(), channels = emptyList(), thirdParty = emptyList(),
        permissions = emptyList(), deepLinks = emptyList(),
        stats = com.flutterguard.app.scan.ReportStats(0, 0, 0, 0, 0, 0, 0), grade = 'A',
    )

    private val stale = ScanPhase.Done(ScanJob(7, "com.x", 0), report(), null)

    @Test
    fun aStaleTerminalOfTheSamePackageIsNotEntry() {
        // The named regression from the review: Done(job 7) must not count as the new job starting.
        assertNull(ScanQueueWaits.startedJobId(stale, "com.x", baselineJobId = 7))
    }

    @Test
    fun aStaleTerminalOfTheSamePackageIsNotThisJobsTerminal() {
        assertFalse(ScanQueueWaits.isTerminal(stale, "com.x", startedJobId = 8))
        assertNull(ScanQueueWaits.result(stale, "com.x", startedJobId = 8))
        assertFalse(ScanQueueWaits.isTerminal(ScanPhase.Failed(ScanJob(7, "com.x", 0), "old"), "com.x", 8))
        assertFalse(ScanQueueWaits.isTerminal(ScanPhase.Cancelled(ScanJob(7, "com.x", 0)), "com.x", 8))
    }

    @Test
    fun entryRequiresTheNewRunningJob() {
        val running = ScanPhase.Running(ScanJob(8, "com.x", 0))
        assertEquals(8L, ScanQueueWaits.startedJobId(running, "com.x", baselineJobId = 7))
        // Same job as the baseline is not new work.
        assertNull(ScanQueueWaits.startedJobId(ScanPhase.Running(ScanJob(7, "com.x", 0)), "com.x", 7))
        // Another package is never this queue item.
        assertNull(ScanQueueWaits.startedJobId(ScanPhase.Running(ScanJob(9, "com.y", 0)), "com.x", 7))
    }

    @Test
    fun theIdleGateIsCancellableSoAPermanentBusyStoreCannotWedgeTheQueue() {
        // Ready: nothing running, no scanner body exiting.
        assertTrue(ScanQueueWaits.idleOrCancelled(running = false, executing = false, cancelRequested = false))
        // Busy: either slot. Not ready, so the queue waits — but only until its bound.
        assertFalse(ScanQueueWaits.idleOrCancelled(running = true, executing = false, cancelRequested = false))
        assertFalse(ScanQueueWaits.idleOrCancelled(running = false, executing = true, cancelRequested = false))
        assertFalse(ScanQueueWaits.idleOrCancelled(running = true, executing = true, cancelRequested = false))
        // Cancel-all must abandon the wait instead of suspending forever.
        assertTrue(ScanQueueWaits.idleOrCancelled(running = true, executing = true, cancelRequested = true))
        assertTrue(ScanQueueWaits.idleOrCancelled(running = false, executing = true, cancelRequested = true))
        // The wait is bounded by the same per-app timeout the runner uses.
        assertTrue(ScanQueueWaits.APP_TIMEOUT_MS in 1..(60 * 60_000L))
    }

    @Test
    fun terminalAndResultRequireTheStartedJob() {
        val done = ScanPhase.Done(ScanJob(8, "com.x", 0), report(), null)
        val failed = ScanPhase.Failed(ScanJob(8, "com.x", 0), "boom")
        val cancelled = ScanPhase.Cancelled(ScanJob(8, "com.x", 0))

        assertTrue(ScanQueueWaits.isTerminal(done, "com.x", 8))
        assertEquals(QueueItemState.DONE, ScanQueueWaits.result(done, "com.x", 8))
        assertEquals(QueueItemState.FAILED, ScanQueueWaits.result(failed, "com.x", 8))
        assertEquals(QueueItemState.CANCELLED, ScanQueueWaits.result(cancelled, "com.x", 8))
        assertNull(ScanQueueWaits.result(ScanPhase.Running(ScanJob(8, "com.x", 0)), "com.x", 8))
    }

    @Test
    fun queueStartIsRefusedWhileAScanRunsOrTheStoreStillExecutes() {
        val apps = listOf(QueueApp("com.x", "X"))
        assertTrue(ScanQueueGate.canBegin(running = false, executing = false, queueRunning = false, apps = apps))
        assertFalse(ScanQueueGate.canBegin(running = true, executing = false, queueRunning = false, apps = apps))
        assertFalse(ScanQueueGate.canBegin(running = false, executing = true, queueRunning = false, apps = apps))
        assertFalse(ScanQueueGate.canBegin(running = false, executing = false, queueRunning = true, apps = apps))
        assertFalse(ScanQueueGate.canBegin(running = false, executing = false, queueRunning = false, apps = emptyList()))
        assertFalse(ScanQueueGate.canBegin(running = false, executing = false, queueRunning = false, apps = listOf(QueueApp(" ", "blank"))))
    }
}
