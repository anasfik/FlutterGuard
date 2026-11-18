package com.flutterguard.app.ui

import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.FindingKind
import com.flutterguard.app.scan.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** W1: the findings list is grouped by what the artifact proves, in one order. */
class FindingGroupsTest {

    private fun finding(id: String, severity: Severity = Severity.MEDIUM) =
        Finding(id, "t", severity, "d", emptyList(), "r")

    @Test
    fun groupsAreOrderedFactsThenLeadsThenInventory() {
        val findings = listOf(
            finding("FLUT-NOTICES", Severity.INFO),
            finding("SEC-KEY-AWS", Severity.HIGH),
            finding("MAN-DEBUG", Severity.HIGH),
            finding("NET-CLEARTEXT", Severity.INFO),
            finding("SEC-KEY-GENERIC"),
        )
        val groups = findingGroups(findings)

        assertEquals(listOf(FindingKind.CONFIRMED, FindingKind.SUSPECTED, FindingKind.INFORMATIONAL), groups.map { it.first })
        assertEquals(listOf("MAN-DEBUG"), groups[0].second.map { it.id })
        assertEquals(listOf("SEC-KEY-AWS", "SEC-KEY-GENERIC"), groups[1].second.map { it.id })
        assertEquals(listOf("FLUT-NOTICES", "NET-CLEARTEXT"), groups[2].second.map { it.id })
        // Every finding appears exactly once; nothing is invented or dropped.
        assertEquals(findings.size, groups.sumOf { it.second.size })
    }

    @Test
    fun emptyGroupsAreKeptSoZeroConfirmedIsVisible() {
        val groups = findingGroups(listOf(finding("SEC-KEY-AWS", Severity.CRITICAL)))
        assertEquals(3, groups.size)
        assertTrue(groups[0].second.isEmpty())
        assertEquals(1, groups[1].second.size)
        assertTrue(groups[2].second.isEmpty())
    }

    @Test
    fun theThreeGroupLabelsAreStable() {
        assertEquals("Confirmed artifact facts", findingGroupLabel(FindingKind.CONFIRMED))
        assertEquals("Leads worth checking", findingGroupLabel(FindingKind.SUSPECTED))
        assertEquals("Inventory", findingGroupLabel(FindingKind.INFORMATIONAL))
    }
}
