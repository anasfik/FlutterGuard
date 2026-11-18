package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.ThirdPartyHit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The service table is data, so the tests assert by evidence rather than by
 * display name: a name is prose that can be reworded, an evidence string is the
 * matched signal. `detect` keys `dexPrefixHits` by service name, which is also
 * why duplicate names would silently drop a whole detector — hence the
 * uniqueness test.
 */
class ThirdPartyRulesTest {

    private fun detect(
        zipNames: Set<String> = emptySet(),
        dex: Map<String, Set<String>> = emptyMap(),
        pub: Set<String> = emptySet(),
        hosts: Set<String> = emptySet(),
    ): List<ThirdPartyHit> =
        ThirdPartyRules.detect(zipNames, dex, pub, hosts.associateWith { "first-party" })

    private fun evidence(hits: List<ThirdPartyHit>): List<String> = hits.flatMap { it.evidence }

    @Test
    fun anLlmHostNamesTheProviderThatOwnsIt() {
        val hits = detect(hosts = setOf("api.anthropic.com", "api.openai.com"))
        val ev = evidence(hits)
        assertTrue("anthropic host not reported: $ev", ev.contains("host:api.anthropic.com"))
        assertTrue("openai host not reported: $ev", ev.contains("host:api.openai.com"))
    }

    @Test
    fun aProviderIsNotAnLlmProviderJustBecauseItHasAnApiHost() {
        // api.example.com is nobody's provider and must not invent a service.
        assertEquals(emptyList<ThirdPartyHit>(), detect(hosts = setOf("api.example.com")))
    }

    @Test
    fun pubPackagesAndDexDescriptorsAreSeparateEvidence() {
        val pubHits = detect(pub = setOf("flutter_gemini"))
        assertTrue(evidence(pubHits).contains("pub:flutter_gemini"))

        val firebase = ThirdPartyRules.services.first { "com/google/firebase" in it.dexPrefixes }
        val dexHits = detect(dex = mapOf(firebase.name to setOf("com/google/firebase")))
        assertTrue(evidence(dexHits).contains("dex:com/google/firebase"))
    }

    @Test
    fun aBundledFileIsEvidenceEvenWithNoOtherSignal() {
        val hits = detect(zipNames = setOf("google-services.json", "classes.dex"))
        assertTrue(evidence(hits).any { it.startsWith("file:*google-services.json") })
    }

    @Test
    fun serviceNamesAreUniqueBecauseDexHitsAreKeyedByName() {
        val names = ThirdPartyRules.services.map { it.name }
        assertEquals("duplicate service name drops a detector", names.size, names.toSet().size)
    }
}
