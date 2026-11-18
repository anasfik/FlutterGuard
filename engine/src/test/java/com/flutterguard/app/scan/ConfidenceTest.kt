package com.flutterguard.app.scan

import com.flutterguard.app.scan.rules.SecretScanner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * W1: a finding's kind says what the artifact proves, never whether the app is
 * exploitable. CONFIRMED is reserved for decoded artifact configuration and
 * material; every string-pattern lead and credential shape stays SUSPECTED;
 * inventory and public identifiers are INFORMATIONAL.
 */
class ConfidenceTest {

    private fun finding(id: String, severity: Severity = Severity.HIGH) =
        Finding(id, "t", severity, "d", emptyList(), "r")

    @Test
    fun decodedArtifactFactsAreConfirmed() {
        // Manifest flags/components, decoded NSC policy, certificate identity,
        // Flutter artifact entries: all read straight out of the artifact.
        for (id in listOf(
            "MAN-DEBUG", "MAN-BACKUP", "MAN-CLEARTEXT", "MAN-CUSTOMPERM", "MAN-DEEPLINK",
            "MAN-EXPORTED-activity", "MAN-EXPORTED-service", "MAN-EXPORTED-receiver", "MAN-EXPORTED-provider",
            "NET-CLEARTEXT", "NET-CLEARTEXT-DEFAULT", "NET-USERCA", "NET-PINS",
            "SIG-DEBUG", "FLUT-DEBUG-BUILD", "FLUT-JIT-SNAPSHOT", "FLUT-NO-AOT",
        )) {
            assertEquals("$id must be a confirmed artifact fact", FindingKind.CONFIRMED, FindingCatalog.kindOf(id))
            assertEquals(id, FindingKind.CONFIRMED, finding(id, Severity.MEDIUM).kind)
        }
    }

    @Test
    fun patternLeadsAndCredentialShapesStaySuspected() {
        // A string in the pool proves the string, not a reachable code path or a
        // live credential. PEM header/body matches remain SUSPECTED on purpose.
        for (id in listOf(
            "SEC-KEY-PRIVATE", "SEC-PRIVATE-KEY", "SEC-KEY-AWS", "SEC-KEY-GENERIC", "SEC-DB-URI",
            "SEC-GCP-SERVICE-ACCOUNT", "SEC-CRYPTO-ECB",
            "WEB-addJavascriptInterface", "WEB-setAllowUniversalAccessFromFileURLs",
            "FLUT-TLS-badCertificateCallback", "FLUT-NO-OBFUSCATION", "NET-HTTP-HOSTS",
            "AST-KEYMATERIAL", "AST-KEYFILE", "AST-DOTENV", "AST-ENV",
        )) {
            assertEquals("$id must stay a lead", FindingKind.SUSPECTED, FindingCatalog.kindOf(id))
        }
        // Even at CRITICAL severity a PEM/capture-group match is never confirmed.
        assertEquals(FindingKind.SUSPECTED, finding("SEC-KEY-PRIVATE", Severity.CRITICAL).kind)
        assertEquals(FindingKind.SUSPECTED, finding("SEC-PRIVATE-KEY", Severity.CRITICAL).kind)
        // The plan's explicit exception: a signing-block read failure looks like
        // "no v2", so the v1-only lead is not a confirmed signing fact.
        assertEquals(FindingKind.SUSPECTED, FindingCatalog.kindOf("SIG-V1-ONLY"))
    }

    @Test
    fun publicIdentifiersAndInventoryAreInformational() {
        for (id in listOf(
            "SEC-FIREBASE", "SEC-SUPABASE", "SEC-ENV-KEY", "SEC-MAPBOX", "SEC-KEY-OAUTH-CLIENT",
            "FLUT-NOTICES", "FLUT-PUBSPEC", "FLUT-FINGERPRINT", "FLUT-JNI-SURFACE",
            "WEB-PAYLOAD", "SDK-MARKER", "AST-CONFIG", "AST-FIREBASE-JSON", "CRYPTO-X509",
        )) {
            assertEquals("$id is inventory, not a defect", FindingKind.INFORMATIONAL, FindingCatalog.kindOf(id))
        }
    }

    @Test
    fun unknownAndFutureIdsAreNeverConfirmed() {
        for (id in listOf("", "WEB-futureMarker", "SEC-KEY-FUTURE", "MAN-EXPORTED-activity-alias", "NET-NEW-RULE")) {
            assertEquals("$id must resolve conservatively", FindingKind.SUSPECTED, FindingCatalog.kindOf(id))
            // A higher severity must not flip an unknown ID to confirmed either.
            assertEquals(FindingKind.SUSPECTED, finding(id, Severity.CRITICAL).kind)
        }
    }

    @Test
    fun theSameIdInformationalBranchStaysInformational() {
        // NET-CLEARTEXT is a serious policy fact for real hosts but the loopback
        // branch is INFO: the ID alone must not grade it.
        assertEquals(FindingKind.CONFIRMED, finding("NET-CLEARTEXT", Severity.HIGH).kind)
        assertEquals(FindingKind.INFORMATIONAL, finding("NET-CLEARTEXT", Severity.INFO).kind)
        // NET-PINS is MEDIUM for SHA-1-only and INFO for SHA-256.
        assertEquals(FindingKind.CONFIRMED, finding("NET-PINS", Severity.MEDIUM).kind)
        assertEquals(FindingKind.INFORMATIONAL, finding("NET-PINS", Severity.INFO).kind)
        // No other ID is upgraded by severity: SUSPECTED stays SUSPECTED.
        assertEquals(FindingKind.SUSPECTED, finding("NET-HTTP-HOSTS", Severity.INFO).kind)
        assertEquals(FindingKind.SUSPECTED, finding("SEC-KEY-AWS", Severity.INFO).kind)
    }

    @Test
    fun credentialRuleIdsAreConsistentlyClassified() {
        val rules = SecretScanner().rules
        assertFalse("the secret rule tables must be discoverable", rules.isEmpty())
        for (rule in rules) {
            val kind = FindingCatalog.kindOf(rule.id)
            if (rule.secret) {
                // A masked credential-shape capture is a lead, never a fact.
                assertEquals("${rule.id} is a pattern lead", FindingKind.SUSPECTED, kind)
            } else {
                // Public identifiers and marker-only rules are inventory or leads,
                // never a confirmed artifact fact.
                assertNotEquals("${rule.id} must not be confirmed", FindingKind.CONFIRMED, kind)
            }
            if (!rule.secret && rule.severity == Severity.INFO) {
                assertEquals("${rule.id} is a public identifier", FindingKind.INFORMATIONAL, kind)
            }
        }
    }

    @Test
    fun catalogCoversEveryIdTheScannerCanEmit() {
        val dir = listOf(
            File("src/main/java/com/flutterguard/app/scan"),
            File("engine/src/main/java/com/flutterguard/app/scan"),
        ).firstOrNull { it.isDirectory }
            ?: error("engine source tree not found from ${File(".").absolutePath}")

        val text = dir.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "Confidence.kt" }
            .joinToString("\n") { it.readText() }
        val literal = Regex("""(?:id\s*=\s*|finding\(\s*|f\(\s*)"([A-Z][A-Z0-9-]+)"""")
            .findAll(text)
            .map { it.groupValues[1] }
            .filterNot { it.startsWith("MASVS-") }
            .toSet()

        // Generated families are built from maps/loops, so they cannot be scraped.
        val generated = buildSet {
            addAll(listOf("activity", "service", "receiver", "provider").map { "MAN-EXPORTED-$it" })
            addAll(
                listOf(
                    "addJavascriptInterface", "setAllowFileAccessFromFileURLs",
                    "setAllowUniversalAccessFromFileURLs", "setWebContentsDebuggingEnabled",
                    "setJavaScriptEnabled", "onReceivedSslError", "JavascriptInterface",
                    "loadDataWithBaseURL",
                ).map { "WEB-$it" },
            )
            addAll(
                listOf("badCertificateCallback", "setTrustedCertificates").map { "FLUT-TLS-$it" },
            )
        }
        val secretRules = SecretScanner().rules.map { it.id }.toSet()

        val emitted = literal + generated + secretRules
        val missing = emitted - FindingCatalog.knownIds
        val stale = FindingCatalog.knownIds - emitted
        assertTrue("rule IDs missing from the catalog: ${missing.sorted()}", missing.isEmpty())
        assertTrue("catalog IDs no rule can emit any more: ${stale.sorted()}", stale.isEmpty())
        assertEquals("catalog size", 102, FindingCatalog.knownIds.size)
    }

    @Test
    fun gradeCountsOnlyConfirmedFindings() {
        val confirmedHigh = finding("MAN-DEBUG", Severity.HIGH)
        val suspectedHigh = finding("SEC-KEY-AWS", Severity.HIGH)
        val suspectedCritical = finding("SEC-KEY-PRIVATE", Severity.CRITICAL)
        val informational = finding("FLUT-NOTICES", Severity.INFO)

        // One confirmed HIGH: score 25 -> C. Counting the lead too would be D.
        assertEquals('C', gradeOf(listOf(confirmedHigh, suspectedHigh)))
        // Two confirmed HIGHs: score 50 -> D.
        assertEquals('D', gradeOf(listOf(confirmedHigh, finding("MAN-CLEARTEXT", Severity.HIGH))))
        // Leads never grade: a CRITICAL-shaped pattern alone leaves a clean A.
        assertEquals('A', gradeOf(listOf(suspectedCritical, suspectedHigh, informational)))
        // A confirmed CRITICAL still caps at F.
        assertEquals('F', gradeOf(listOf(finding("MAN-DEBUG", Severity.CRITICAL))))
        // The legacy four-int overload stays verbatim.
        assertEquals('C', gradeOf(0, 1, 0, 0))
        assertEquals('F', gradeOf(1, 0, 0, 0))
    }

    @Test
    fun storedKindsNeverUpgradeAnId() {
        // CONFIRMED > SUSPECTED > INFORMATIONAL: the less certain kind wins.
        assertEquals(FindingKind.SUSPECTED, FindingKind.lessCertain(FindingKind.SUSPECTED, FindingKind.CONFIRMED))
        assertEquals(FindingKind.INFORMATIONAL, FindingKind.lessCertain(FindingKind.CONFIRMED, FindingKind.INFORMATIONAL))
        assertEquals(FindingKind.CONFIRMED, FindingKind.lessCertain(FindingKind.CONFIRMED, FindingKind.CONFIRMED))
        assertEquals(null, FindingKind.parse("not-a-kind"))
        assertEquals(FindingKind.SUSPECTED, FindingKind.parse("SUSPECTED"))
    }
}
