package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mask/scrub policy for private evidence: raw values live only in `value`. */
class EvidenceTest {

    // Assembled at runtime on purpose: a literal secret-shaped string in a
    // repository trips GitHub push protection, and this fixture is not a key.
    private val secret = "sk_" + "live_" + "42".repeat(12) + "TESTONLY"

    @Test
    fun maskRevealsLengthButNoCharacters() {
        val m = Evidence.mask(secret)
        assertFalse("mask leaked a prefix", m.contains(secret.substring(0, 8)))
        assertFalse("mask leaked a suffix", m.contains(secret.substring(secret.length - 4)))
        assertTrue("mask should state the length", m.contains(secret.length.toString()))
        assertEquals(m, Evidence.mask(secret)) // deterministic: history diffs stay quiet
    }

    @Test
    fun maskNeverContainsAnySixCharWindowOfTheValue() {
        val m = Evidence.mask(secret)
        for (i in 0..secret.length - 6) {
            assertFalse("mask leaked window at $i", m.contains(secret.substring(i, i + 6)))
        }
    }

    @Test
    fun scrubReplacesEveryOccurrenceWithTheMask() {
        val text = "first=$secret then $secret again"
        val out = Evidence.scrub(text, listOf(secret))
        assertFalse(out.contains(secret))
        assertEquals(2, out.split(Evidence.mask(secret)).size - 1)
    }

    @Test
    fun scrubIsIdempotentAndIgnoresAbsentSecrets() {
        val once = Evidence.scrub("keep text $secret", listOf(secret))
        val twice = Evidence.scrub(once, listOf(secret))
        assertEquals(once, twice)
        assertTrue("absent secret changed unrelated text", twice.contains("keep text"))
    }

    @Test
    fun scrubPrefersTheLongestSecretFirst() {
        val long = "prefix_AND_the_rest_of_this_credential_value_0123456789"
        val short = "prefix_AND"
        val out = Evidence.scrub("x $long y", listOf(short, long))
        assertFalse(out.contains(long))
        assertTrue("longest-first replacement did not win: $out", out.contains(Evidence.mask(long)))
        assertFalse("short secret replaced inside the long one: $out", out.contains(Evidence.mask(short)))
    }

    @Test
    fun scrubbedReportCoversDetailsSamplesRoutesAndSources() {
        val r = reportWithSecret()
        val scrubbed = r.scrubSecrets(listOf(secret))
        assertFalse(scrubbed.findings[0].detail.contains(secret))
        assertFalse("evidence source leaked", scrubbed.findings[0].evidence[0].source.contains(secret))
        assertFalse(scrubbed.hosts[0].samples[0].contains(secret))
        assertFalse(scrubbed.routes[0].contains(secret))
        assertFalse(scrubbed.dartSources[0].contains(secret))
        // The private channel itself survives for explicit reveal/copy.
        assertEquals(secret, scrubbed.findings[0].evidence[0].value)
        // Unrelated fields are untouched.
        assertEquals(scrubbed.findings[0].title, r.findings[0].title)
        assertTrue(scrubbed.scrubSecrets(listOf(secret)).findings[0].detail == scrubbed.findings[0].detail)
    }

    @Test
    fun scrubbedReportWithoutSecretsIsTheSameReport() {
        val r = reportWithSecret()
        assertEquals(r, r.scrubSecrets(emptyList()))
    }

    @Test
    fun scrubbedReportCoversHostNameChannelsThirdPartyPermissionsAndDeepLinks() {
        val r = reportWithSecret().copy(
            channels = listOf(ChannelInfo("$secret/channel", "$secret", "custom")),
            thirdParty = listOf(ThirdPartyHit("Sentry", listOf("$secret.java"))),
            permissions = listOf(PermissionHit("perm", "normal", "desc $secret")),
            deepLinks = listOf(DeepLink("$secret.Activity", "$secret", "$secret.example.com", true)),
        )
        val s = r.scrubSecrets(listOf(secret))
        assertFalse("host leaked", s.hosts[0].host.contains(secret))
        assertFalse("channel name leaked", s.channels[0].name.contains(secret))
        assertFalse("channel origin leaked", s.channels[0].origin.contains(secret))
        assertFalse("third-party evidence leaked", s.thirdParty[0].evidence[0].contains(secret))
        assertFalse("permission description leaked", s.permissions[0].description.contains(secret))
        assertFalse("deep-link component leaked", s.deepLinks[0].component.contains(secret))
        assertFalse("deep-link scheme leaked", s.deepLinks[0].scheme.contains(secret))
        assertFalse("deep-link host leaked", s.deepLinks[0].host!!.contains(secret))
        assertFalse("history snapshot leaked", History.snapshot(s).contains(secret))
    }

    @Test
    fun scrubFailsClosedBeyond256Secrets() {
        val many = (0 until 300).map { "secret_${it}_padding" }
        val out = Evidence.scrub(many.joinToString(" "), many)
        val leaked = many.filter { out.contains(it) }
        assertTrue("scrub cap left ${leaked.size} secrets raw", leaked.isEmpty())
        many.forEach { assertTrue("mask for ${it.length}-char secret missing", out.contains(Evidence.mask(it))) }
    }

    @Test
    fun scrubFailsClosedForShortSecretsInsteadOfLeavingThemRaw() {
        val out = Evidence.scrub("keep short text", listOf("short"))
        assertFalse("short detected value was left raw", out.contains("short"))
        assertTrue("fail-closed text should say it was hidden", out.contains("hidden"))
    }

    @Test
    fun failClosedMasksTheWholeFieldNeverPartially() {
        val field = "keep short text plus $secret"
        val out = Evidence.scrub(field, listOf("short"))
        assertEquals("a short supplied value must mask the whole field", Evidence.mask(field), out)
        assertFalse("fail-closed field kept raw text", out.contains("keep"))
    }

    @Test
    fun artifactDisplayNameRequiresTheReportSecretSet() {
        val entry = ArtifactEntry(0, "base", "assets/$secret.json", 0, 0, ArtifactCategory.ASSET)
        val report = reportWithSecret().copy(artifacts = listOf(entry))
        assertEquals("public secret set must match retained evidence values", listOf(secret), report.secretValues())
        val shown = entry.displayName(report.secretValues())
        assertFalse("artifact display name leaked", shown.contains(secret))
        assertTrue("artifact display name lost its mask", shown.contains(Evidence.mask(secret)))
    }

    private fun reportWithSecret(): Report {
        val meta = AppMeta(
            "com.example.app", "Example", "1.0", 1, 26, 35, null, 0, 0, false, 0, 0,
            emptyList(), emptyList(), "",
        )
        return Report(
            meta = meta,
            framework = FrameworkInfo(isFlutter = true),
            signing = SigningInfo(null, null, null, false, false, false, null, null, null, emptyList(), emptyList()),
            findings = listOf(
                Finding(
                    "SEC-KEY-GENERIC", "Hardcoded secret", Severity.MEDIUM,
                    "detail embedding $secret verbatim",
                    listOf(Evidence("assets/$secret.env", 0, Evidence.mask(secret), secret)),
                    "rotate",
                ),
            ),
            hosts = listOf(HostInfo("$secret.api.example.com", "first-party", listOf("https://api.example.com/v1/$secret"))),
            channels = emptyList(),
            thirdParty = emptyList(),
            permissions = emptyList(),
            deepLinks = emptyList(),
            stats = ReportStats(0, 0, 1, 0, 0, 10, 5),
            grade = 'C',
            routes = listOf("/api/v1/$secret"),
            dartSources = listOf("package:app/$secret.dart".removeSuffix(".dart")),
        )
    }
}
