package com.flutterguard.app.ui

import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.FindingKind
import com.flutterguard.app.scan.Severity
import org.junit.Assert.assertEquals
import org.junit.Test

/** The findings list is one severity-ordered list, worst first. */
class FindingGroupsTest {

    private fun finding(id: String, severity: Severity = Severity.MEDIUM) =
        Finding(id, "t", severity, "d", emptyList(), "r")

    @Test
    fun findingsAreOrderedGloballyCriticalToLow() {
        // A CRITICAL lead must precede a LOW confirmed fact: severity dominates kind.
        val findings = listOf(
            finding("MAN-SHAREDUID", Severity.LOW),       // confirmed LOW
            finding("SEC-TEST-INFO", Severity.INFO),
            finding("MAN-DEBUG", Severity.HIGH),          // confirmed HIGH
            finding("SEC-TEST-CRIT", Severity.CRITICAL),  // lead CRITICAL
            finding("SEC-TEST-LOW", Severity.LOW),
            finding("SEC-TEST-HIGH", Severity.HIGH),
            finding("SEC-TEST-MED", Severity.MEDIUM),
        )
        assertEquals(
            listOf(
                "SEC-TEST-CRIT", "MAN-DEBUG", "SEC-TEST-HIGH", "SEC-TEST-MED",
                "MAN-SHAREDUID", "SEC-TEST-LOW", "SEC-TEST-INFO",
            ),
            sortedFindings(findings).map { it.id },
        )
    }

    @Test
    fun equalSeverityBreaksTiesConfirmedBeforeLead() {
        val findings = listOf(
            finding("SEC-TEST-A", Severity.CRITICAL),
            finding("MAN-DEBUG", Severity.CRITICAL),
        )
        assertEquals(
            listOf("MAN-DEBUG", "SEC-TEST-A"),
            sortedFindings(findings).map { it.id },
        )
    }

    @Test
    fun everyFindingAppearsExactlyOnce() {
        val findings = listOf(
            finding("FLUT-NOTICES", Severity.INFO),
            finding("SEC-KEY-AWS", Severity.HIGH),
            finding("MAN-DEBUG", Severity.HIGH),
        )
        val sorted = sortedFindings(findings)
        assertEquals(findings.size, sorted.size)
        assertEquals(findings.toSet(), sorted.toSet())
    }

    @Test
    fun emptyInputStaysEmpty() {
        assertEquals(emptyList<Finding>(), sortedFindings(emptyList()))
    }

    @Test
    fun theThreeGroupLabelsAreStable() {
        assertEquals("Confirmed artifact facts", findingGroupLabel(FindingKind.CONFIRMED))
        assertEquals("Leads worth checking", findingGroupLabel(FindingKind.SUSPECTED))
        assertEquals("Inventory", findingGroupLabel(FindingKind.INFORMATIONAL))
    }
}
