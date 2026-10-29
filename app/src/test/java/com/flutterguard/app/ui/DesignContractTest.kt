package com.flutterguard.app.ui

import com.flutterguard.app.scan.InstalledApp
import com.flutterguard.app.scan.ReportSection
import com.flutterguard.app.scan.ReportStats
import com.flutterguard.app.scan.ScanJob
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.Severity
import com.flutterguard.app.scan.gradeOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The design/content contract that has to hold in every state, not only the
 * happy one: an all-zero severity summary, a bare grade letter, one "unknown"
 * word, no fabricated split count, and state that survives a tab switch.
 *
 * Rendered spacing, colour and radius live in `Theme.kt` and need a screenshot;
 * everything decision-shaped is pinned here without touching Compose.
 */
class DesignContractTest {

    private fun stats(c: Int = 0, h: Int = 0, m: Int = 0, l: Int = 0, i: Int = 0) =
        ReportStats(c, h, m, l, i, stringsScanned = 1_000, durationMs = 1_000)

    private fun app(
        versionName: String? = "1.0",
        minSdk: Int? = 26,
        targetSdk: Int? = 35,
        sizeBytes: Long = 1024,
        splitCount: Int = 0,
        system: Boolean = false,
    ) = InstalledApp(
        packageName = "com.example.app", label = "Example", versionName = versionName, versionCode = 7,
        minSdk = minSdk, targetSdk = targetSdk, isFlutter = true, isSystem = system,
        sizeBytes = sizeBytes, splitCount = splitCount, icon = null,
    )

    // ---------------------------------------------------------------- D1

    @Test
    fun theSeveritySummaryKeepsEveryLevelAndNeverMergesLowWithInfo() {
        val rows = severitySummary(stats(c = 2, h = 0, m = 4, l = 3, i = 7))
        assertEquals(listOf("Critical", "High", "Medium", "Low", "Info"), rows.map { it.label })
        assertEquals(
            listOf(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO),
            rows.map { it.severity },
        )
        assertEquals(listOf(2, 0, 4, 3, 7), rows.map { it.count })
    }

    @Test
    fun aZeroCountRowIsStillEvidenceThatTheCheckRan() {
        val rows = severitySummary(stats())
        assertEquals("all five levels must render even when nothing was found", 5, rows.size)
        assertTrue("no row may be dropped for being zero", rows.all { it.count == 0 })
        assertEquals(
            "a clean report is not silent about what was checked",
            listOf("Critical", "High", "Medium", "Low", "Info"),
            rows.map { it.label },
        )
    }

    // ---------------------------------------------------------------- D2

    @Test
    fun theGradeLetterCarriesAVisibleMeaning() {
        assertEquals("critical findings present", gradeLegend('F', hasCritical = true))
        assertTrue(gradeLegend('A').startsWith("no critical"))
        assertNotEquals("an A and an F must never read the same", gradeLegend('A'), gradeLegend('F'))
        for (grade in listOf('A', 'B', 'C', 'D', 'F')) {
            assertNotEquals("$grade needs a legend", ReportMetadata.UNAVAILABLE, gradeLegend(grade))
        }
        assertEquals(ReportMetadata.UNAVAILABLE, gradeLegend('Z'))
    }

    /** `gradeOf` also returns F on weighted severity alone, so the legend must not claim Critical. */
    @Test
    fun anFWithoutCriticalFindingsDoesNotClaimCriticalOnes() {
        val weightedOnly = gradeOf(c = 0, h = 2, m = 10, l = 13)
        assertEquals("that fixture must be an F without a Critical", 'F', weightedOnly)
        val legend = gradeLegend(weightedOnly, hasCritical = false)
        assertTrue("legend lied: $legend", !legend.contains("critical findings present"))
        assertTrue(legend.startsWith("no critical findings"))
        assertNotEquals(gradeLegend('F', hasCritical = true), legend)
    }

    // ---------------------------------------------------------------- C5

    @Test
    fun onePlaceholderStandsInForEveryUnknownTileValue() {
        assertEquals(ReportMetadata.UNAVAILABLE, humanBytes(0))
        assertEquals(ReportMetadata.UNAVAILABLE, humanBytes(-1))
        assertEquals("2 KB", humanBytes(2048))

        val noVersion = tileMetaLines(app(versionName = null))
        assertEquals("three metadata lines stay three lines", 3, noVersion.size)
        assertTrue("no bare '?' marker: $noVersion", noVersion.none { it.contains("?") })
        assertTrue("the unknown version says so", noVersion.any { it.contains(ReportMetadata.UNAVAILABLE) })

        val noSdk = tileMetaLines(app(minSdk = null, targetSdk = null))
        assertEquals(3, noSdk.size)
        assertTrue("no 'SDK ?→?' marker: $noSdk", noSdk.none { it.contains("?") })
        assertTrue(noSdk.any { it.contains("SDK ${ReportMetadata.UNAVAILABLE}") })
    }

    // ---------------------------------------------------------------- C6

    @Test
    fun theSizeLineNeverFabricatesAZeroSplitCount() {
        val size = 176L * 1024 * 1024
        assertEquals("176 MB", sizeAndSplits(size, 0))
        assertEquals("176 MB · 2 split(s)", sizeAndSplits(size, 2))
        assertEquals(ReportMetadata.UNAVAILABLE, sizeAndSplits(0, 0))
    }

    // ---------------------------------------------------------------- D5

    @Test
    fun theExportSelectionSurvivesRotationIncludingAnEmptyOne() {
        val choice = ExportChoice(
            json = false,
            sections = setOf(ReportSection.FINDINGS, ReportSection.ARTIFACTS),
            sensitive = true,
        )
        assertEquals(choice, exportChoiceOf(choice.encode()))

        // "nothing ticked" is a real user state; it must round-trip, not fall back to everything.
        val empty = ExportChoice(sections = emptySet())
        assertEquals(empty, exportChoiceOf(empty.encode()))
        assertFalse(exportChoiceOf(empty.encode()).canExport)

        // A save we cannot read must never silently enable a sensitive or full export.
        assertEquals(ExportChoice(), exportChoiceOf(emptyList()))
        assertFalse(exportChoiceOf(listOf("true", "false", "NOT_A_SECTION")).canExport)
    }

    // ---------------------------------------------------------------- D4

    @Test
    fun aTabSwitchIsTheSameRouteSoItsSavedStateSurvives() {
        val overview = Destination.Details("com.a.app")
        val findings = overview.copy(section = "Findings")
        assertEquals(
            "switching tabs must not throw away this app's saved state",
            NavStack.stateKey(overview),
            NavStack.stateKey(findings),
        )
        assertNotEquals(NavStack.stateKey(overview), NavStack.stateKey(Destination.Details("com.b.app")))
        assertNotEquals(NavStack.stateKey(Destination.Home), NavStack.stateKey(Destination.Queue))
        assertNotEquals(
            NavStack.stateKey(Destination.Section("com.a.app", SeeAllTarget.HOSTS)),
            NavStack.stateKey(Destination.Section("com.a.app", SeeAllTarget.ROUTES)),
        )
        assertNotEquals(
            NavStack.stateKey(Destination.Details("com.a.app")),
            NavStack.stateKey(Destination.Section("com.a.app", SeeAllTarget.HOSTS)),
        )
    }

    // ---------------------------------------------------------------- C5 state words

    @Test
    fun queueRowsUseTheOneStateWordPerIntent() {
        val live = ScanPhase.Running(ScanJob(9L, "com.example.app", 0L), stage = "Rules", pct = 61)
        assertEquals("queued", queueStateWord(QueueItemState.PENDING, null))
        assertEquals("running", queueStateWord(QueueItemState.STARTING, null))
        assertEquals("running", queueStateWord(QueueItemState.RUNNING, null))
        assertEquals("running · Rules 61%", queueStateWord(QueueItemState.RUNNING, live))
        assertEquals("done", queueStateWord(QueueItemState.DONE, null))
        assertEquals("failed", queueStateWord(QueueItemState.FAILED, null))
        assertEquals("cancelled", queueStateWord(QueueItemState.CANCELLED, null))
    }

    @Test
    fun stepperStepsUseTheSameStateWords() {
        assertEquals("done", stepStateWord(StepPhase.DONE))
        assertEquals("running", stepStateWord(StepPhase.ACTIVE))
        assertEquals("queued", stepStateWord(StepPhase.PENDING))
    }
}
