package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.Provenance
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A Dart AOT snapshot stores provider base URLs as plain strings with no scheme,
 * so the URL harvest alone never sees them. Conduit lists 22 LLM endpoints that
 * way and only four were reported before this rule existed.
 */
class ProviderHostTest {

    private fun hosts(vararg feeds: String): List<String> {
        val scanner = SecretScanner()
        for (f in feeds) scanner.feed(f, Provenance("test", 0), Layer.DEX)
        return scanner.hostInfos().map { it.host }
    }

    @Test
    fun aBareLlmHostReachesTheReport() {
        assertTrue("bare host dropped: ${hosts("api.anthropic.com")}", hosts("api.anthropic.com").contains("api.anthropic.com"))
    }

    @Test
    fun aFullUrlAndABareHostDoNotDoubleCount() {
        val found = hosts("https://api.anthropic.com/v1/messages", "api.anthropic.com")
        assertEquals("api.anthropic.com must appear once", 1, found.count { it == "api.anthropic.com" })
    }

    @Test
    fun unrelatedDomainsAreNotInventedAsProviders() {
        assertTrue(hosts("example.com", "notprovider.example").none { it.contains("anthropic") || it.contains("openai") })
    }

    /** The suffix list must not fire on a longer name that merely ends with the same text. */
    @Test
    fun aLookalikeDomainIsNotAProvider() {
        assertTrue(hosts("myopenai.com").none { it == "openai.com" })
    }
}
