package com.flutterguard.app.ui

import com.flutterguard.app.scan.AppMeta
import com.flutterguard.app.scan.FrameworkInfo
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportStats
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.ScanStore
import com.flutterguard.app.scan.SigningInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A3: the terminal-notification observer must watch the real StateFlow. `ScanStore`
 * is a plain `MutableStateFlow`, so a Compose `snapshotFlow` over it reads no
 * snapshot state and may never re-emit — the exact case (scan ends while the user
 * sits on Home) would stay silent.
 */
class ScanPhaseFeedTest {

    private fun report(pkg: String) = Report(
        meta = AppMeta(pkg, "X", "1", 1, 26, 35, null, 0, 0, false, 0, 0, emptyList(), emptyList(), ""),
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
    fun everyTerminalPhaseOfTheStoreIsEmitted() = runBlocking {
        ScanStore.reset()
        val seen = mutableListOf<ScanPhase>()
        val collector = launch(Dispatchers.Unconfined) { scanPhaseFeed().collect { seen += it } }

        val job = ScanStore.start("com.feed.done")!!
        ScanStore.succeeded(job.id, report(job.packageName), "/tmp/x.json", null, emptyList())
        assertEquals(ScanPhase.Done::class.java, seen.last()::class.java)
        assertTrue(seen.last() is ScanPhase.Done)
        ScanStore.executionFinished(job.id)

        val second = ScanStore.start("com.feed.cancel")!!
        ScanStore.cancelled(second.id)
        assertTrue("a cancellation while the user is elsewhere must reach the observer", seen.last() is ScanPhase.Cancelled)
        ScanStore.executionFinished(second.id)

        val third = ScanStore.start("com.feed.fail")!!
        ScanStore.failed(third.id, "boom")
        assertTrue(seen.last() is ScanPhase.Failed)
        ScanStore.executionFinished(third.id)

        collector.cancel()
        ScanStore.reset()
    }
}
