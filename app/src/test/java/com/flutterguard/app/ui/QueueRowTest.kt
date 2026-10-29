package com.flutterguard.app.ui

import com.flutterguard.app.scan.ScanJob
import com.flutterguard.app.scan.ScanPhase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Queue route renders exactly what these helpers return, so every state
 * label, failure reason and tap target is pinned here instead of in a
 * screenshot. Queue *semantics* stay in `ScanQueueMachine`; this is only how a
 * finished machine state reads on screen.
 */
class QueueRowTest {

    private fun item(state: QueueItemState, note: String? = null, pkg: String = "com.example.app") =
        QueueItem(packageName = pkg, label = "Example", state = state, note = note)

    private fun running(pkg: String, stage: String = "Strings", pct: Int = 42) =
        ScanPhase.Running(ScanJob(9L, pkg, 0L), stage = stage, pct = pct)

    @Test
    fun everyStateHasOneHonestLabelAndOnlyFinishedRowsOpenDetails() {
        val labels = QueueItemState.entries.associateWith {
            queueRowState(item(it), ScanPhase.Idle).stateLabel
        }
        assertEquals("queued", labels[QueueItemState.PENDING])
        // One state word per intent: a row that is starting is already running.
        assertEquals("running", labels[QueueItemState.STARTING])
        assertEquals("running", labels[QueueItemState.RUNNING])
        assertEquals("done", labels[QueueItemState.DONE])
        assertEquals("failed", labels[QueueItemState.FAILED])
        assertEquals("cancelled", labels[QueueItemState.CANCELLED])

        for (state in QueueItemState.entries) {
            val row = queueRowState(item(state), ScanPhase.Idle)
            assertEquals(
                "$state opens Details only when it finished",
                state == QueueItemState.DONE || state == QueueItemState.FAILED,
                row.opensDetails,
            )
            // Nothing else may claim to be tappable.
            assertEquals(row.opensDetails, row.action == QueueRowAction.OPEN_DETAILS)
        }
    }

    @Test
    fun theRowCarriesTheLabelAndThePackage() {
        val row = queueRowState(item(QueueItemState.PENDING, pkg = "com.other.app"), ScanPhase.Idle)
        assertEquals("Example", row.title)
        assertEquals("com.other.app", row.subtitle)
    }

    @Test
    fun theScanningRowCarriesItsOwnStageAndPercent() {
        val scanning = queueRowState(item(QueueItemState.RUNNING), running("com.example.app", "Rules", 61))
        assertEquals("running · Rules 61%", scanning.stateLabel)
        assertTrue("a live row is marked active", scanning.active)
        assertFalse("an unfinished scan has no report to open", scanning.opensDetails)

        // The store keeps one phase: never lend another app's percent to this row.
        val foreign = queueRowState(item(QueueItemState.RUNNING), running("com.other.app", "Rules", 61))
        assertEquals("running", foreign.stateLabel)
        // A terminal phase must not decorate a row that is still marked running.
        val stale = queueRowState(
            item(QueueItemState.RUNNING),
            ScanPhase.Failed(ScanJob(9L, "com.example.app", 0L), "boom"),
        )
        assertEquals("running", stale.stateLabel)
    }

    @Test
    fun theFailureReasonIsPartOfTheRow() {
        val failed = queueRowState(item(QueueItemState.FAILED, note = "timed out"), ScanPhase.Idle)
        assertEquals("failed · timed out", failed.stateLabel)
        assertTrue(failed.failed)
        assertTrue("a failed row opens Details and its last report, if any", failed.opensDetails)

        assertEquals("failed", queueRowState(item(QueueItemState.FAILED), ScanPhase.Idle).stateLabel)
    }

    @Test
    fun theHomeEntryRowUsesTheQueueSummaryAndItsOwnStateWord() {
        val begun = ScanQueueMachine.begin(listOf(QueueApp("a", "A"), QueueApp("b", "B"), QueueApp("c", "C")))
        val afterA = ScanQueueMachine.onTerminal(
            ScanQueueMachine.onRunning(ScanQueueMachine.onStarted(begun, "a"), "a"),
            "a",
            QueueItemState.DONE,
        )
        assertEquals("running · 1 of 3 scanned · 2 queued", queueEntrySubtitle(afterA))
        assertEquals(1f / 3f, queueProgress(afterA), 0.0001f)

        val finished = ScanQueueMachine.onTerminal(
            ScanQueueMachine.onTerminal(afterA, "b", QueueItemState.DONE),
            "c",
            QueueItemState.DONE,
        )
        assertFalse(finished.active)
        assertEquals("done · 3 of 3 scanned", queueEntrySubtitle(finished))
        assertEquals(1f, queueProgress(finished), 0.0001f)

        val cancelled = ScanQueueMachine.onCancelAll(begun)
        assertEquals("cancelled · 0 of 3 scanned · 3 cancelled", queueEntrySubtitle(cancelled))

        // An empty (dismissed) queue has no progress to claim.
        assertEquals(0f, queueProgress(ScanQueueState()), 0.0001f)
    }
}
