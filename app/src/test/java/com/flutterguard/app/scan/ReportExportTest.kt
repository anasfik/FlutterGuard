package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Export policy tests. org.json is Android-stubbed in unit tests, so JSON
 * runtime is not exercised here: the JSON-specific value gating is tested via
 * [ReportExport.evidenceFields] (shared by toJson) and the Markdown renderer.
 */
class ReportExportTest {

    // Assembled at runtime: a literal key-shaped string trips push protection.
    private val secret = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dcAbCdEf12"

    private fun report(): Report {
        val meta = AppMeta(
            "com.example.app", "Example", "1.0", 1, 26, 35, null, 0, 0, false, 0, 0,
            emptyList(), emptyList(), "",
        )
        return Report(
            meta = meta,
            framework = FrameworkInfo(isFlutter = true, dartDeps = listOf("dio", "Foo-Bar")),
            signing = SigningInfo(null, null, null, false, false, false, null, null, null, emptyList(), emptyList()),
            findings = listOf(
                Finding(
                    "SEC-KEY-GENERIC", "Hardcoded secret", Severity.MEDIUM,
                    "Value found in assets/.env. Pattern: SEC-KEY-GENERIC. raw=$secret",
                    listOf(Evidence("assets/$secret.env", 12, Evidence.mask(secret), secret)),
                    "rotate",
                ),
            ),
            hosts = listOf(HostInfo("$secret.api.example.com", "first-party", listOf("https://api.example.com/v1/key/$secret"))),
            channels = listOf(ChannelInfo("app/bus", "classes.dex", "custom")),
            thirdParty = listOf(ThirdPartyHit("Sentry", listOf("sentry.java"))),
            permissions = listOf(PermissionHit("android.permission.INTERNET", "normal", "network")),
            deepLinks = emptyList(),
            stats = ReportStats(0, 0, 1, 0, 1, 10, 5),
            grade = 'C',
            routes = listOf("/api/v1/things"),
            dartSources = listOf("package:app/main"),
            artifacts = listOf(
                ArtifactEntry(0, "base", "lib/$secret/libapp.so", 100, 400, ArtifactCategory.NATIVE_LIB),
            ),
        )
    }

    @Test
    fun defaultMarkdownNeverContainsRawSecretValues() {
        val md = ReportExport.toMarkdown(report())
        assertFalse("raw value leaked into default markdown", md.contains(secret))
        assertTrue("masked value missing", md.contains(Evidence.mask(secret)))
        assertTrue(md.contains("redacted", ignoreCase = true))
        assertFalse("default export must not print evidence values", md.contains("value: `$secret`"))
        assertFalse("sensitive banner must not appear by default", md.contains("SENSITIVE EXPORT"))
    }

    @Test
    fun sensitiveMarkdownIsExplicitlyWarnedAndCarriesRawValues() {
        val md = ReportExport.toMarkdown(report(), sensitive = true)
        assertTrue("sensitive export must warn", md.contains("SENSITIVE EXPORT"))
        assertTrue("sensitive export must carry the raw value", md.contains(secret))
        assertTrue("sensitive export must print the evidence value line", md.contains("value: `$secret`"))
    }

    @Test
    fun defaultMarkdownScrubsTheAncillaryFieldsToo() {
        val md = ReportExport.toMarkdown(report())
        assertFalse("detail leaked", md.contains("raw=$secret"))
        assertFalse("host sample leaked", md.contains("key/$secret"))
    }

    @Test
    fun selectedSectionsAreHonoredInMarkdown() {
        val md = ReportExport.toMarkdown(report(), sections = setOf(ReportSection.FINDINGS))
        assertTrue(md.contains("## Findings"))
        assertTrue(md.contains("## Third-party services"))
        assertFalse("endpoints must be excluded", md.contains("## Endpoints"))
        assertFalse("routes must be excluded", md.contains("## Candidate routes"))
        assertFalse("dependencies must be excluded", md.contains("## Dart dependencies"))
        assertFalse("channels must be excluded", md.contains("## Platform channels"))
        assertFalse("artifacts must be excluded", md.contains("## Artifacts"))
        assertFalse("permissions must be excluded", md.contains("## Permissions"))
        assertFalse("overview bullets must be excluded", md.contains("- Version:"))
        assertFalse("sensitive export must be absent entirely", md.contains(secret))
    }

    @Test
    fun defaultMarkdownRendersEverySection() {
        val md = ReportExport.toMarkdown(report())
        assertTrue(md.contains("# FlutterGuard report"))
        assertTrue(md.contains("- Version:"))
        assertTrue(md.contains("## Findings"))
        assertTrue(md.contains("## Endpoints (1)"))
        assertTrue(md.contains("## Candidate routes (1)"))
        assertTrue(md.contains("## Dart source files (1)"))
        assertTrue(md.contains("## Dart dependencies (2)"))
        assertTrue(md.contains("## Platform channels (1)"))
        assertTrue(md.contains("## Third-party services (1)"))
        assertTrue(md.contains("## Artifacts (1)"))
        assertTrue(md.contains("## Permissions (1)"))
    }

    @Test
    fun routeAndDependencySectionsAreLabeledAsCandidates() {
        val md = ReportExport.toMarkdown(report())
        assertTrue("routes must be labeled candidates", md.contains("Candidate routes"))
        assertTrue("dependencies must be labeled candidates", md.contains("candidate"))
        assertTrue("dependency URL must not be invented in exports", md.contains("`dio`"))
    }

    @Test
    fun emptySelectionProducesNoHeadings() {
        val md = ReportExport.toMarkdown(report(), sections = emptySet())
        assertFalse("no section headings expected: $md", md.contains("## "))
        assertFalse("raw value leaked: $md", md.contains(secret))
    }

    @Test
    fun unsupportedFormatFailsLoudlyInsteadOfFallingThrough() {
        val e = runCatching { ReportExport.render(report(), "txt") }.exceptionOrNull()
        assertTrue("unknown extension must throw", e is IllegalArgumentException)
        assertTrue("md dispatch broken", ReportExport.render(report(), "md").contains("# FlutterGuard report"))
        assertTrue(ReportExport.render(report(), "markdown").contains("# FlutterGuard report"))
    }

    @Test
    fun jsonEvidenceFieldsNeverCarryValueByDefault() {
        val e = Evidence("assets/.env", 12, Evidence.mask(secret), secret)
        val def = ReportExport.evidenceFields(e, sensitive = false).map { it.first }
        assertEquals(listOf("source", "offset", "snippet"), def)
        val sen = ReportExport.evidenceFields(e, sensitive = true).toMap()
        assertEquals(secret, sen["value"])
        // Sensitive mode may also render a snippet scrubbed against known secrets.
        val scrubbed = ReportExport.evidenceFields(e, sensitive = false, secrets = listOf(secret)).toMap()
        assertFalse((scrubbed["snippet"] as String).contains(secret))
    }

    @Test
    fun jsonEvidenceFieldsWithoutValueStayMinimalEvenWhenSensitive() {
        val e = Evidence("manifest", 0, "scheme → activity")
        assertEquals(
            listOf("source", "offset", "snippet"),
            ReportExport.evidenceFields(e, sensitive = true).map { it.first },
        )
    }

    @Test
    fun sectionSelectionIsTheSameEnumSetTheExportersConsume() {
        assertEquals(8, ReportExport.allSections.size)
        assertEquals(ReportSection.entries.toSet(), ReportExport.allSections)
        assertTrue(ReportSection.ARTIFACTS in ReportExport.allSections)
    }

    // ---- JSON payload regressions (no org.json needed: the serializer consumes this tree) ----

    @Suppress("UNCHECKED_CAST")
    private fun map(v: Any?) = v as Map<String, Any?>

    @Test
    fun jsonPayloadEmitsDependenciesEvenWhenOverviewIsNotSelected() {
        val fw = map(ReportExport.payload(report(), setOf(ReportSection.DEPENDENCIES))["framework"])
        assertEquals(listOf("dio", "Foo-Bar"), fw["dartDeps"])
        assertFalse("dependencies-only export must not smuggle overview fields", fw.containsKey("isFlutter"))
    }

    @Test
    fun jsonPayloadMapsDeepLinksToEndpointsInBothFormats() {
        val r = report().copy(deepLinks = listOf(DeepLink("c", "s", "h", true)))
        assertTrue(ReportExport.payload(r, setOf(ReportSection.ENDPOINTS)).containsKey("deepLinks"))
        assertFalse(ReportExport.payload(r, setOf(ReportSection.PERMISSIONS)).containsKey("deepLinks"))
    }

    @Test
    fun jsonPayloadNeverCarriesEvidenceValueByDefault() {
        val findings = ReportExport.payload(report(), ReportExport.allSections)["findings"] as List<*>
        val evidence = map(findings.single()).let { (it as Map<*, *>)["evidence"] } as List<*>
        assertFalse("default JSON payload carried the raw value", map(evidence.single()).containsKey("value"))
    }

    @Test
    fun jsonPayloadScrubsAncillaryFields() {
        val json = ReportExport.payload(report(), ReportExport.allSections).toString()
        assertFalse("payload leaked a secret", json.contains(secret))
    }

    @Test
    fun evidenceFieldsScrubsTheSourcePath() {
        val e = Evidence("assets/$secret.env", 0, "masked")
        val fields = ReportExport.evidenceFields(e, sensitive = false, secrets = listOf(secret)).toMap()
        assertFalse("evidence source leaked", (fields["source"] as String).contains(secret))
    }
}
