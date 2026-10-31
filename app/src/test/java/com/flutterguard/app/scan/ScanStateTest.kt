package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/**
 * Platform-free lifecycle rules for the single active scan job. These are the
 * rules that decide whether a start/progress/completion may move the state:
 * no duplicate job, no stale progress, no stale completion.
 */
class ScanStateTest {

    private fun report(pkg: String = "com.example.app") = Report(
        meta = AppMeta(pkg, "Example", "1.0", 1, 26, 35, null, 0, 0, false, 0, 0, emptyList(), emptyList(), ""),
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

    private fun job(id: Long = 1, pkg: String = "com.example.app") = ScanJob(id, pkg, 1_000)

    @Test
    fun idleStartsAJob() {
        val (state, accepted) = ScanState().start(job())
        assertTrue(accepted)
        assertEquals("com.example.app", state.running?.job?.packageName)
        assertEquals(ScanPhase.Idle, ScanState().phase)
    }

    @Test
    fun secondStartIsRejectedWhileAJobRuns() {
        val (running, _) = ScanState().start(job(1))
        val (state, accepted) = running.start(job(2, "com.other.app"))
        assertFalse(accepted)
        assertEquals(1L, state.running?.job?.id)
        assertEquals("com.example.app", state.running?.job?.packageName)
    }

    @Test
    fun progressFromAStaleJobIsIgnored() {
        val (running, _) = ScanState().start(job(7))
        val updated = running.progress(8, "Scanning assets", 70)
        assertEquals(running, updated)
    }

    @Test
    fun progressIsClampedAndNeverGoesBackwards() {
        val (running, _) = ScanState().start(job(1))
        val a = running.progress(1, "Reading package info", 20).progress(1, "Assets", 60)
        assertEquals(60, a.running?.pct)
        val b = a.progress(1, "later stage", 30)
        assertEquals(60, b.running?.pct)
        assertEquals("later stage", b.running?.stage)
        assertEquals(100, b.progress(1, "Done", 140).running?.pct)
    }

    @Test
    fun staleCompletionIsIgnored() {
        val (running, _) = ScanState().start(job(3))
        val stale = running.succeeded(2, report(), "/tmp/x.json", null, emptyList())
        assertEquals(running, stale)
        assertEquals(null, stale.lastSuccess)
    }

    @Test
    fun completionRecordsLastSuccessForFailedRetries() {
        val (running, _) = ScanState().start(job(4))
        val done = running.succeeded(4, report(), "/tmp/x.json", null, listOf("+ host api.example"))
        assertTrue(done.phase is ScanPhase.Done)
        assertEquals(listOf("+ host api.example"), (done.phase as ScanPhase.Done).diff)
        assertEquals(done.phase, done.lastSuccess)

        val retried = done.progress(4, "running again?", 10) // terminal: progress is inert
        assertEquals(done, retried)

        val (running2, _) = done.start(job(5))
        val failed = running2.failed(5, "APK unreadable")
        assertTrue(failed.phase is ScanPhase.Failed)
        assertEquals(done.phase, failed.lastSuccess)
    }

    @Test
    fun cancelIsRequestedThenTerminalAndLateSuccessWins() {
        val (running, _) = ScanState().start(job(9))
        val cancelling = running.requestCancel(9)
        assertTrue(cancelling.running!!.cancelRequested)
        // A scan that finished before observing the request is a real success.
        val done = cancelling.succeeded(9, report(), "/tmp/x.json", null, emptyList())
        assertTrue(done.phase is ScanPhase.Done)

        val (running2, _) = ScanState().start(job(10))
        val cancelled = running2.requestCancel(10).cancelled(10)
        assertTrue(cancelled.phase is ScanPhase.Cancelled)
        assertEquals(null, cancelled.lastSuccess)
        // Nothing may move a cancelled job afterwards.
        assertEquals(cancelled, cancelled.progress(10, "late stage", 50))
        assertNull(cancelled.running)
    }

    @Test
    fun interruptedFailureIsMarkedAsSuch() {
        val (running, _) = ScanState().start(job(11))
        val failed = running.failed(11, "Scan interrupted (process or service stopped)", interrupted = true)
        assertEquals(true, (failed.phase as ScanPhase.Failed).interrupted)
    }

    @Test
    fun storeAcceptsOneJobAtATimeAndTracksCancellation() {
        ScanStore.reset()
        val first = ScanStore.start("com.example.one", now = 10)
        val second = ScanStore.start("com.example.two", now = 11)
        assertEquals("com.example.one", first?.packageName)
        assertNull(second)
        assertFalse(ScanStore.isCancelled(first!!.id))
        ScanStore.requestCancel(first.id)
        assertTrue(ScanStore.isCancelled(first.id))
        ScanStore.cancelled(first.id)
        // Terminal state alone is not enough: the scanner body still owns the slot.
        ScanStore.executionFinished(first.id)
        // A terminal state frees the slot for the next retry.
        assertEquals("com.example.two", ScanStore.start("com.example.two", now = 12)?.packageName)
        ScanStore.reset()
    }

    @Test
    fun abandonedExecutionBlocksANewStartUntilItsBodyExits() {
        ScanStore.reset()
        val a = ScanStore.start("com.example.a", now = 20)!!
        // Timeout: the job is terminal, but its synchronous scanner body may still be running.
        ScanStore.failed(a.id, "Foreground time limit reached", interrupted = true)
        assertNull("a second scanner body must never overlap the abandoned one", ScanStore.start("com.example.b", now = 21))
        ScanStore.executionFinished(a.id)
        assertEquals("com.example.b", ScanStore.start("com.example.b", now = 22)?.packageName)
        ScanStore.reset()
    }

    @Test
    fun executingStateIsObservableWhileTheScannerBodyWindsDown() {
        ScanStore.reset()
        val a = ScanStore.start("com.example.a", now = 40)!!
        assertTrue(ScanStore.isExecuting())
        assertEquals(a.id, ScanStore.executingJob)
        // Terminal phase, body still unwinding: the queue must still see it.
        ScanStore.failed(a.id, "cancelled", interrupted = true)
        assertTrue(ScanStore.isExecuting())
        ScanStore.executionFinished(a.id)
        assertFalse(ScanStore.isExecuting())
        assertNull(ScanStore.executingJob)
        ScanStore.reset()
    }

    @Test
    fun abandoningAJobIsPermanentAndNotRevivedByANewJob() {        val abandoned = ScanToken(1)
        abandoned.abandon()
        val next = ScanToken(2)
        // Starting the next job must not clear the previous job's abandon flag.
        assertTrue(abandoned.isAbandoned)
        assertFalse(next.isAbandoned)
        abandoned.abandon()
        assertTrue(abandoned.isAbandoned)
    }

    @Test
    fun aFinishedExecutionReleasesOnlyItsOwnSlot() {
        ScanStore.reset()
        val a = ScanStore.start("com.example.a", now = 30)!!
        ScanStore.failed(a.id, "stopped", interrupted = true)
        // A newer job really owns the slot now (the old test never had one, so it
        // proved nothing about the id guard).
        ScanStore.executionFinished(a.id)
        val b = ScanStore.start("com.example.b", now = 31)!!
        assertEquals(b.id, ScanStore.executingJob)
        // A late release from the older job must not free the newer job's slot.
        ScanStore.executionFinished(a.id)
        assertEquals(b.id, ScanStore.executingJob)
        assertTrue(ScanStore.isExecuting())
        ScanStore.executionFinished(b.id)
        assertFalse(ScanStore.isExecuting())
        ScanStore.reset()
    }

    @Test
    fun aLaunchCancelledBeforeTheBodyStartsFreesTheExecutionSlot() = runBlocking {
        // N4: the claim is released even when the launched body never runs, or the
        // store would refuse every later scan until process death.
        ScanStore.reset()
        val a = ScanStore.start("com.example.never", now = 50)!!
        val dead = CoroutineScope(SupervisorJob()).apply { cancel() }
        var ran = false
        ScanStore.launchExecution(dead, a.id) { ran = true }
        assertFalse("the cancelled body must not run", ran)
        // The release is completion-driven, so it may land just after the launch
        // returns — but it must land, and promptly.
        withTimeout(5_000) { while (ScanStore.isExecuting()) delay(10) }
        assertFalse("a start whose body never ran must not brick the store", ScanStore.isExecuting())
        assertTrue(ScanStore.state.value.phase is ScanPhase.Failed)
        assertEquals("com.example.next", ScanStore.start("com.example.next", now = 51)?.packageName)
        ScanStore.reset()
    }

    @Test
    fun aNormalLaunchReleasesTheSlotWhenItsBodyReturns() = runBlocking {
        ScanStore.reset()
        val a = ScanStore.start("com.example.runs", now = 60)!!
        var ran = false
        val launched = ScanStore.launchExecution(CoroutineScope(SupervisorJob() + Dispatchers.Unconfined), a.id) {
            ran = true
            assertTrue(ScanStore.isExecuting())
        }
        assertNotNull(launched)
        launched!!.join()
        assertTrue(ran)
        assertFalse(ScanStore.isExecuting())
        ScanStore.reset()
    }

    @Test
    fun auditScreenStartsOnlyWhenNothingRunsAndThisPackageHasNoResult() {
        assertTrue(ScanStartPolicy.shouldAutoStart(ScanPhase.Idle, "com.example.app"))

        val (runningOther, _) = ScanState().start(job(1, "com.other.app"))
        assertFalse(ScanStartPolicy.shouldAutoStart(runningOther.phase, "com.example.app"))
        assertFalse(ScanStartPolicy.shouldAutoStart(runningOther.phase, "com.other.app"))

        val (runningMine, _) = ScanState().start(job(2))
        assertFalse(ScanStartPolicy.shouldAutoStart(runningMine.phase, "com.example.app"))

        // Another package's finished/failed/cancelled scan must not block this screen.
        val doneOther = runningOther.succeeded(1, report("com.other.app"), "/tmp/a.json", null, emptyList())
        assertTrue(ScanStartPolicy.shouldAutoStart(doneOther.phase, "com.example.app"))
        assertFalse(ScanStartPolicy.shouldAutoStart(doneOther.phase, "com.other.app"))

        val failedOther = runningOther.failed(1, "boom")
        assertTrue(ScanStartPolicy.shouldAutoStart(failedOther.phase, "com.example.app"))
        assertFalse(ScanStartPolicy.shouldAutoStart(failedOther.phase, "com.other.app"))

        val cancelledOther = runningOther.cancelled(1)
        assertTrue(ScanStartPolicy.shouldAutoStart(cancelledOther.phase, "com.example.app"))
        // A finished picked-APK scan of this very package says nothing about the
        // installed app: opening it must still start a scan, and opening the file
        // route must not start a second one.
        val (fileRunning, _) = ScanState().start(job(4, "com.example.app").copy(fileScan = true))
        val doneFile = fileRunning.succeeded(4, report("com.example.app"), "/tmp/a.file.json", null, emptyList())
        assertTrue(ScanStartPolicy.shouldAutoStart(doneFile.phase, "com.example.app", fileScan = false))
        assertFalse(ScanStartPolicy.shouldAutoStart(doneFile.phase, "com.example.app", fileScan = true))
        assertFalse(ScanStartPolicy.shouldAutoStart(cancelledOther.phase, "com.other.app"))
    }
}
