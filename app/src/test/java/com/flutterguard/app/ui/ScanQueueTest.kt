package com.flutterguard.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Scan-all runs strictly one app at a time and cancel-all never leaves a pending start. */
class ScanQueueTest {

    private fun app(pkg: String, label: String = pkg) = QueueApp(packageName = pkg, label = label)

    @Test
    fun beginDeduplicatesAndActivates() {
        val queue = ScanQueueMachine.begin(listOf(app("a"), app("b"), app("a", "A again")))
        assertTrue(queue.active)
        assertEquals(listOf("a", "b"), queue.items.map { it.packageName })
        assertEquals(listOf("A again", "b"), queue.items.map { it.label })
        assertEquals(2, queue.total)
    }

    @Test
    fun beginRefusesAnEmptyListAndAnActiveQueue() {
        val empty = ScanQueueMachine.begin(emptyList())
        assertFalse(empty.active)
        assertTrue(empty.items.isEmpty())

        val active = ScanQueueMachine.begin(listOf(app("a")))
        val second = ScanQueueMachine.begin(listOf(app("b")), current = active)
        assertEquals(active, second)
    }

    @Test
    fun onlyOneAppIsEverStarted() {
        val queue = ScanQueueMachine.begin(listOf(app("a"), app("b")))
        assertEquals("a", ScanQueueMachine.nextPending(queue)?.packageName)

        val started = ScanQueueMachine.onStarted(queue, "a")
        assertEquals("a", started.current()?.packageName)
        assertNull(ScanQueueMachine.nextPending(started))
        assertEquals(QueueItemState.STARTING, started.items.first().state)
    }

    @Test
    fun nextAppStartsOnlyAfterTheTerminalState() {
        val queue = ScanQueueMachine.begin(listOf(app("a"), app("b")))
        val running = ScanQueueMachine.onRunning(ScanQueueMachine.onStarted(queue, "a"), "a")
        assertEquals(QueueItemState.RUNNING, running.current()?.state)
        assertNull(ScanQueueMachine.nextPending(running))

        val afterA = ScanQueueMachine.onTerminal(running, "a", QueueItemState.DONE)
        assertEquals(QueueItemState.DONE, afterA.items.first().state)
        assertNull(afterA.current())
        assertEquals("b", ScanQueueMachine.nextPending(afterA)?.packageName)
        assertTrue(afterA.active)
    }

    @Test
    fun queueDeactivatesAfterTheLastApp() {
        val queue = ScanQueueMachine.begin(listOf(app("a")))
        val finished = ScanQueueMachine.onTerminal(ScanQueueMachine.onStarted(queue, "a"), "a", QueueItemState.FAILED)
        assertNull(ScanQueueMachine.nextPending(finished))
        assertFalse(finished.active)
        assertEquals(1, finished.failures)
        assertEquals(1, finished.finished)
    }

    @Test
    fun cancelAllStopsPendingStartsAndDropsActivity() {
        val queue = ScanQueueMachine.begin(listOf(app("a"), app("b"), app("c")))
        val running = ScanQueueMachine.onRunning(ScanQueueMachine.onStarted(queue, "a"), "a")
        val cancelled = ScanQueueMachine.onCancelAll(running)

        assertEquals(QueueItemState.CANCELLED, cancelled.items[1].state)
        assertEquals(QueueItemState.CANCELLED, cancelled.items[2].state)
        assertNull(ScanQueueMachine.nextPending(cancelled))
        assertTrue(cancelled.cancelRequested)

        val settled = ScanQueueMachine.onTerminal(cancelled, "a", QueueItemState.CANCELLED)
        assertFalse(settled.active)
        assertNull(ScanQueueMachine.nextPending(settled))
    }

    @Test
    fun cancelAllBeforeTheStartPreventsIt() {
        val queue = ScanQueueMachine.begin(listOf(app("a"), app("b")))
        val cancelled = ScanQueueMachine.onCancelAll(queue)
        assertNull(ScanQueueMachine.nextPending(cancelled))
        // A start that was already in flight must not flip a cancelled item.
        assertEquals(cancelled, ScanQueueMachine.onStarted(cancelled, "a"))
        assertTrue(cancelled.cancelRequested)
    }

    @Test
    fun terminalForAnUnknownPackageIsIgnored() {
        val queue = ScanQueueMachine.begin(listOf(app("a")))
        assertEquals(queue, ScanQueueMachine.onTerminal(queue, "zzz", QueueItemState.DONE))
    }

    @Test
    fun aCancelledAppIsNotCountedAsAScannedOne() {
        // Device defect B2: "11 of 11 finished" was shown when 10 apps were cancelled.
        val queue = ScanQueueMachine.begin((1..11).map { app("p$it") })
        val running = ScanQueueMachine.onRunning(ScanQueueMachine.onStarted(queue, "p1"), "p1")
        val done = ScanQueueMachine.onTerminal(running, "p1", QueueItemState.DONE)
        val cancelled = ScanQueueMachine.onCancelAll(done)

        assertEquals(1, cancelled.done)
        assertEquals(0, cancelled.failures)
        assertEquals(10, cancelled.cancelled)
        assertEquals(11, cancelled.finished) // every item is terminal, but not every one scanned

        val text = queueSummaryText(
            done = cancelled.done,
            failed = cancelled.failures,
            cancelled = cancelled.cancelled,
            total = cancelled.total,
            pending = cancelled.remaining,
        )
        assertEquals("1 of 11 scanned · 10 cancelled", text)
        assertFalse(text, text.contains("of 11 finished"))
    }

    @Test
    fun aPartialQueueReportsEachOutcomeSeparately() {
        val queue = ScanQueueMachine.begin(listOf(app("a"), app("b"), app("c")))
        val running = ScanQueueMachine.onRunning(ScanQueueMachine.onStarted(queue, "a"), "a")
        val afterA = ScanQueueMachine.onTerminal(running, "a", QueueItemState.FAILED, "timed out")
        assertEquals(
            "0 of 3 scanned · 1 failed · 2 queued",
            queueSummaryText(afterA.done, afterA.failures, afterA.cancelled, afterA.total, afterA.remaining),
        )
    }
}
