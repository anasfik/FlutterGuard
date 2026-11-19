package com.flutterguard.app.scan

import java.security.MessageDigest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A secret planted in evidence values/snippets and source strings must not
 * survive into a comparison, a history summary or an export — in raw form or
 * as a hash. Rule identity plus safe provenance is all a comparison may carry.
 */
class ReportDiffSecretTest {

    private val sentinel = "fg-sentinel-SECRET-9f3a2b7c"
    private val mask = Evidence.mask(sentinel)

    private fun before() = DiffFixture.report(
        findings = listOf(
            DiffFixture.finding(
                id = "SEC-KEY-GENERIC",
                severity = Severity.MEDIUM,
                sources = listOf("classes.dex?api_key=$sentinel"),
                value = sentinel,
                snippet = "api_key=$mask",
            ),
        ),
    )

    private fun after() = DiffFixture.report(
        versionName = "1.0.1",
        versionCode = 2,
        hosts = listOf("api.example"),
        findings = listOf(
            DiffFixture.finding(
                id = "SEC-KEY-GENERIC",
                severity = Severity.HIGH,
                sources = listOf("libapp.so?token=$sentinel"),
                value = sentinel,
                snippet = "token=$mask",
            ),
        ),
    )

    private fun hashes(): List<String> = listOf(
        digest("SHA-256", sentinel),
        digest("SHA-1", sentinel),
        digest("MD5", sentinel),
    ).flatMap { hex -> listOf(hex, hex.take(24), hex.take(16)) }

    private fun digest(algorithm: String, value: String): String =
        MessageDigest.getInstance(algorithm).digest(value.toByteArray()).joinToString("") { "%02x".format(it) }

    @Test
    fun findingIdentitiesCarryRuleAndMaskedProvenanceOnly() {
        val comparison = ReportDiff.compare(before(), after())
        val texts = comparison.changes.mapNotNull { it.identity } + comparison.changes.mapNotNull { it.detail }

        assertTrue("expected a masked provenance, got $texts", texts.any { it.contains(mask) })
        assertTrue(texts.none { it.contains(sentinel) })
        hashes().forEach { hash ->
            assertTrue("a hash of the secret leaked: $hash", texts.none { it.contains(hash) })
        }
        // The rule identity itself must survive: this is what a researcher compares.
        assertTrue(texts.any { it.startsWith("SEC-KEY-GENERIC") })
    }

    @Test
    fun jsonAndMarkdownExportsNeverContainTheSecretOrItsHash() {
        val comparison = ReportDiff.compare(before(), after())
        val json = ReportExport.comparisonJson(comparison)
        val markdown = ReportExport.comparisonMarkdown(comparison)

        for (text in listOf(json, markdown)) {
            assertFalse("secret in export: $text", text.contains(sentinel))
            hashes().forEach { hash ->
                assertFalse("hash of the secret in export: $hash", text.contains(hash))
            }
        }
        assertTrue(json, json.contains("SEC-KEY-GENERIC"))
        assertTrue(json, json.contains("chars hidden"))
        assertTrue(markdown, markdown.contains("SEC-KEY-GENERIC"))
    }

    @Test
    fun historySummaryAndComparisonNeverContainTheSecret() {
        val snapshot = History.snapshot(after())
        assertFalse("secret in history snapshot", snapshot.contains(sentinel))

        val log = ScanLog.append(ScanLog.append(null, History.snapshot(before())), snapshot)
        val entries = ScanLog.decode(log)
        val lines = History.diff(entries[0].snapshot, entries[1].snapshot)
        assertTrue(lines.any { it.contains("chars hidden") })
        for (line in lines) {
            assertFalse("secret in history diff line: $line", line.contains(sentinel))
            hashes().forEach { hash -> assertFalse("hash in history diff: $line", line.contains(hash)) }
        }

        val comparison = History.comparison(entries, 1, "com.example.app", ScanNamespace.INSTALLED)
        assertNotNull(comparison)
        val exported = ReportExport.comparisonJson(comparison!!)
        assertFalse(exported, exported.contains(sentinel))
        hashes().forEach { hash -> assertFalse("hash in history comparison export", exported.contains(hash)) }
    }

    @Test
    fun scrubbedSnapshotCanStillBeDiffedByTheSameRuleIdentity() {
        // Scrubbing is lossy by design, but the rule identity survives, so two
        // reports that differ only by which source matched stay distinguishable.
        val left = ScanLog.decode(ScanLog.append(null, History.snapshot(before()))).single()
        val right = ScanLog.decode(ScanLog.append(null, History.snapshot(after()))).single()
        val lines = History.diff(left.snapshot, right.snapshot)
        assertTrue(lines.any { it.contains("SEC-KEY-GENERIC") && it.contains("classes.dex") })
        assertTrue(lines.any { it.contains("SEC-KEY-GENERIC") && it.contains("libapp.so") })
    }
}
