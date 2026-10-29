package com.flutterguard.app.ui

import com.flutterguard.app.scan.HostInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A3/A4: a row opens exactly the URL it shows, and only for plausible public hosts. */
class EndpointsTest {

    private fun host(name: String, samples: List<String> = emptyList(), owned: Boolean = true) =
        HostInfo(host = name, classification = "app", samples = samples, appOwned = owned)

    @Test
    fun aRealHostOpensTheExactSampleUrlShown() {
        val row = Endpoints.row(host("appflowy.com", listOf("https://appflowy.com/privacy?x=1")))
        assertEquals("https://appflowy.com/privacy?x=1", row.displayUrl)
        assertEquals("https://appflowy.com/privacy?x=1", row.url)
        assertTrue(row.verified)
    }

    @Test
    fun aHostWithoutASampleFallsBackToItsOwnScheme() {
        val row = Endpoints.row(host("beta.appflowy.cloud"))
        assertEquals("https://beta.appflowy.cloud", row.displayUrl)
        assertEquals("https://beta.appflowy.cloud", row.url)
    }

    @Test
    fun localhostPortsAndMalformedHostsAreUnverifiedAndNotOpenable() {
        for (bad in listOf("localhost:11434", "127.0.0.1", "http://evil.example", "app flowy.com", "", "appflowy.com/x")) {
            val row = Endpoints.row(host(bad))
            assertFalse("$bad must not be verified", row.verified)
            assertNull("$bad must not open", row.url)
        }
    }

    @Test
    fun concatenationArtifactsAreDemoted() {
        // Device shot t4-06: "appflowy.comworkspace" was rendered as an app-owned endpoint.
        val row = Endpoints.row(host("appflowy.comworkspace"))
        assertFalse(row.verified)
        assertNull(row.url)
        assertEquals("appflowy.comworkspace", row.displayUrl)
    }

    @Test
    fun packageIdShapedStringsAreNotVerifiedHosts() {
        // N9: a recovered package id ending in a listed generic TLD must not become
        // a "verified host" with an Open link to a third-party domain.
        for (name in listOf("com.example.app", "androidx.core.app", "com.foo.dev", "com.bzta.my")) {
            val row = Endpoints.row(host(name))
            assertFalse("$name must not be verified", row.verified)
            assertNull("$name must not open", row.url)
            assertEquals(name, row.displayUrl)
        }
        // A real recovered URL for such a name is proof, and keeps the row usable.
        val proven = Endpoints.row(host("com.example.app", listOf("https://com.example.app/legal")))
        assertTrue(proven.verified)
        assertEquals("https://com.example.app/legal", proven.url)
    }

    @Test
    fun realHostsUnderUnlistedCountrySuffixesStayOpenable() {
        // N9 false-negative half: hidden real hosts were a recall loss, not safety.
        for (name in listOf("appflowy.id", "example.my", "example.cc", "example.so", "example.ws", "example.top")) {
            val row = Endpoints.row(host(name))
            assertTrue("$name must stay verified", row.verified)
            assertEquals("https://$name", row.url)
        }
    }

    @Test
    fun rowsPutVerifiedHostsFirstAndKeepEveryHost() {
        val rows = Endpoints.rows(
            listOf(
                host("appflowy.comworkspace"),
                host("appflowy.io"),
                host("localhost"),
                host("beta.appflowy.cloud"),
            ),
        )
        assertEquals(4, rows.size)
        assertEquals(listOf("appflowy.io", "beta.appflowy.cloud", "appflowy.comworkspace", "localhost"), rows.map { it.host.host })
        assertNotNull(rows.first().url)
        assertNull(rows.last().url)
    }
}
