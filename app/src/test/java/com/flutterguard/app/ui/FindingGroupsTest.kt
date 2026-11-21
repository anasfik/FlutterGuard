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
    fun findingsAreOrderedCriticalToLowInsideEachGroup() {
        // Unknown IDs are leads by default, so one group holds every severity here.
        val findings = listOf(
            finding("SEC-TEST-INFO", Severity.INFO),
            finding("SEC-TEST-LOW", Severity.LOW),
            finding("SEC-TEST-CRIT", Severity.CRITICAL),
            finding("SEC-TEST-MED", Severity.MEDIUM),
            finding("SEC-TEST-HIGH", Severity.HIGH),
            finding("SEC-TEST-CRIT2", Severity.CRITICAL),
        )
        val ordered = findingGroups(findings).single { it.first == FindingKind.SUSPECTED }.second.map { it.id }
        assertEquals(
            listOf("SEC-TEST-CRIT", "SEC-TEST-CRIT2", "SEC-TEST-HIGH", "SEC-TEST-MED", "SEC-TEST-LOW", "SEC-TEST-INFO"),
            ordered,
        )
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
