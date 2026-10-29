package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Evidence
import com.flutterguard.app.scan.Provenance
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Recognition and evidence-policy regressions for [SecretScanner]. Phase A:
 * these compile against the current API, so a failure is a real assertion
 * failure, not a missing symbol.
 */
class SecretScannerTest {

    private fun feed(s: SecretScanner, raw: String, layer: Layer = Layer.ASSET, off: Long = 0) =
        s.feed(raw, Provenance("assets/test.txt", off), layer)

    @Test
    fun credentialPastThe512CharLowercaseGateIsStillFound() {
        val s = SecretScanner()
        // Strings >=512 chars currently skip every lowercase gate, silently
        // dropping credentials embedded in longer asset text.
        val pad = "noise ".repeat(120) // 720 chars
        feed(s, pad + "api_key=Abcdef1234567890Zx")
        assertTrue(
            "credential in a 794-char asset string was not found",
            s.findings.any { it.id == "SEC-KEY-GENERIC" },
        )
    }

    @Test
    fun supabaseSecretKeyIsRecognized() {
        val s = SecretScanner()
        // Assembled at runtime: a literal key-shaped string trips push protection.
        val key = "sb_" + "secret_" + "AbCdEfGhIjKlMnOpQrStUv" + "_12345678"
        feed(s, "const k = '$key'", Layer.SO)
        assertTrue(
            "modern Supabase sb_secret_ key not matched",
            s.findings.any { it.id == "SEC-KEY-SUPABASE-SECRET" },
        )
    }

    @Test
    fun namedNavigationRoutesOutsideApiPrefixesAreCandidateRoutes() {
        val s = SecretScanner()
        feed(s, "/settings/profile", Layer.SO)
        feed(s, "/onboarding/step1", Layer.SO, 40)
        assertTrue("named route /settings/profile missed", "/settings/profile" in s.routes)
        assertTrue("named route /onboarding/step1 missed", "/onboarding/step1" in s.routes)
    }

    @Test
    fun standaloneNamedRouteIsCapturedAsCandidate() {
        val s = SecretScanner()
        feed(s, "/profile", Layer.SO)
        assertTrue("standalone named route /profile missed", "/profile" in s.routes)
    }

    @Test
    fun publicIdentifiersAreLabeledAsHypotheses() {
        val s = SecretScanner()
        feed(s, "senderId 1:123456789012:android:abcdef123456")
        val f = s.findings.firstOrNull { it.id == "SEC-FIREBASE" }
        assertEquals("SEC-FIREBASE finding missing", "SEC-FIREBASE", f?.id)
        assertTrue(
            "public identifier finding does not say it is a hypothesis: ${f?.detail}",
            f!!.detail.contains("hypothesis"),
        )
    }

    @Test
    fun staticMethodMarkersAreLabeledAsHypotheses() {
        val s = SecretScanner()
        s.feed("setJavaScriptEnabled", Provenance("classes.dex", 5), Layer.DEX)
        val desc = s.dexMarkers["setJavaScriptEnabled"]
        assertTrue("base marker text lost: $desc", desc!!.startsWith("WebView JavaScript enabled"))
        assertTrue("marker description does not say it is a hypothesis: $desc", desc!!.contains("hypothesis"))
    }

    @Test
    fun repeatEvidenceForTheSameValueStaysOnOneFinding() {
        val s = SecretScanner()
        val raw = "password=SeCretPassw0rd1234"
        feed(s, raw, Layer.ASSET, 1)
        feed(s, raw, Layer.ASSET, 99)
        val hits = s.findings.filter { it.id == "SEC-KEY-GENERIC" }
        assertEquals("duplicate finding for the same raw value", 1, hits.size)
        assertEquals("evidence not appended for the repeat", 2, hits[0].evidence.size)
    }

    @Test
    fun evidencePerUniqueValueIsCappedAtThree() {
        val s = SecretScanner()
        val raw = "password=SeCretPassw0rd1234"
        repeat(5) { feed(s, raw, Layer.ASSET, it * 10L) }
        val hits = s.findings.filter { it.id == "SEC-KEY-GENERIC" }
        assertEquals(1, hits.size)
        assertEquals("evidence cap broken", 3, hits[0].evidence.size)
    }

    // ---- Phase B: private full-value retention and masked-by-construction snippets ----

    // Assembled at runtime: a literal key-shaped string trips push protection.
    private val liveStripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dcAbCdEf12"

    @Test
    fun secretValueIsRetainedInFullForRevealButNeverInSnippet() {
        val s = SecretScanner()
        feed(s, "auth token is $liveStripe in config", Layer.ASSET, 7)
        val f = s.findings.first { it.id == "SEC-KEY-STRIPE-SECRET" }
        val e = f.evidence.single()
        assertEquals("full match must be retained for explicit reveal", liveStripe, e.value)
        assertFalse("snippet leaked the raw value", e.snippet.contains(liveStripe))
        assertFalse("snippet leaked a redact-style prefix", e.snippet.contains(liveStripe.take(8)))
        assertEquals(Evidence.mask(liveStripe), e.snippet)
        assertEquals("assets/test.txt", e.source)
        assertEquals(7L, e.offset)
    }

    @Test
    fun adjacentCredentialsNeverAppearInEitherSnippet() {
        val s = SecretScanner()
        val awsId = "AKIA" + "IOSFODNN7EXAMPLE"
        val pw = "Sup3rS3cretPassw0rdValue"
        feed(s, "AKIA key $awsId and password=$pw together", Layer.ASSET, 3)
        val snippets = s.findings
            .filter { it.id == "SEC-KEY-AWS" || it.id == "SEC-KEY-GENERIC" }
            .flatMap { it.evidence }
            .map { it.snippet }
        assertTrue("expected both rules to fire, got ${s.findings.map { it.id }}", snippets.size >= 2)
        for (sn in snippets) {
            assertFalse("first credential leaked: $sn", sn.contains(awsId))
            assertFalse("adjacent credential leaked: $sn", sn.contains(pw))
            assertFalse("adjacent partial leaked: $sn", sn.contains(pw.take(8)))
        }
        // Both full values are still available privately.
        val values = s.findings.flatMap { it.evidence }.mapNotNull { it.value }.toSet()
        assertTrue(awsId in values)
        assertTrue(pw in values)
    }

    @Test
    fun distinctValuesProduceDistinctFindingsWithTheirOwnRetainedValues() {
        val s = SecretScanner()
        feed(s, "password=FirstValue12345678", Layer.ASSET, 1)
        feed(s, "password=SecondValue98765432", Layer.ASSET, 2)
        val hits = s.findings.filter { it.id == "SEC-KEY-GENERIC" }
        assertEquals("one finding per distinct raw value", 2, hits.size)
        assertEquals(
            setOf("FirstValue12345678", "SecondValue98765432"),
            hits.flatMap { it.evidence }.mapNotNull { it.value }.toSet(),
        )
        hits.forEach { h -> h.evidence.forEach { assertFalse(it.snippet.contains(it.value!!)) } }
    }

    @Test
    fun publicIdentifierRulesKeepTheRawTextInTheSnippet() {
        val s = SecretScanner()
        feed(s, "senderId 1:123456789012:android:abcdef123456")
        val f = s.findings.first { it.id == "SEC-FIREBASE" }
        // The identifier is public by design: the evidence shows it verbatim …
        assertTrue("public id snippet should show the identifier", f.evidence.single().snippet.contains("android:abcdef123456"))
        // … and is still retained as the full value for uniform export gating.
        assertTrue(f.evidence.single().value!!.contains("1:123456789012"))
    }

    @Test
    fun routeCapsStillHoldWhileNewPrefixesAreAccepted() {
        val s = SecretScanner()
        repeat(70) { feed(s, "/settings/page$it", Layer.SO, it * 10L) }
        assertEquals("route cap broken", 60, s.routes.size)
    }

    @Test
    fun urlUserinfoNeverBecomesAHostOrSample() {
        val s = SecretScanner()
        feed(s, "https://user:pass@api.acme-corp.com/v1/key")
        assertTrue("real host missing: ${s.hosts.keys}", s.hosts.containsKey("api.acme-corp.com"))
        assertFalse("userinfo leaked into hosts", s.hosts.keys.any { it.contains("user:pass") })
        assertFalse(
            "userinfo leaked into samples",
            s.hostInfos().flatMap { it.samples }.any { it.contains("user:pass") },
        )
    }

    @Test
    fun sourcePathsStayOutOfRoutes() {
        val s = SecretScanner()
        feed(s, "/settings/lib/main.dart", Layer.SO)
        assertTrue("source path leaked into routes", s.routes.none { it.endsWith(".dart") })
        assertTrue("source path should be captured as a dart source", "/settings/lib/main.dart" in s.dartSources ||
            s.dartSources.any { it == "/settings/lib/main.dart" })
    }
}
