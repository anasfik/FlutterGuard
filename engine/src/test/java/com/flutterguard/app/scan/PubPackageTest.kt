package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** pub.dev package-name validation and the only URL it may produce. */
class PubPackageTest {

    @Test
    fun acceptsRealPubNames() {
        for (name in listOf("http", "dio", "path_provider", "a", "a1", "flutter_secure_storage", "characters2")) {
            assertTrue("$name should be valid", PubPackage.isValid(name))
            assertEquals("https://pub.dev/packages/$name", PubPackage.url(name))
        }
    }

    @Test
    fun rejectsAnythingThatIsNotASimpleLowercasePackageName() {
        val bad = listOf(
            "",               // empty
            "HTTP",           // uppercase
            "1abc",           // digit first
            "foo-bar",        // hyphen (URL/traversal syntax)
            "foo.bar",        // dot / URL syntax
            "../secrets",     // traversal
            "/absolute",      // absolute path
            "foo/bar",        // path separator
            "http://x",       // URL syntax
            "foo bar",        // whitespace
            "foo?",           // query syntax
            "föö",            // non-ASCII
            "a".repeat(65),   // over length cap
        )
        for (name in bad) {
            assertFalse("$name must be rejected", PubPackage.isValid(name))
            assertNull("rejected name must not produce a URL: $name", PubPackage.url(name))
        }
    }

    @Test
    fun describeKeepsUnknownMetadataUnknown() {
        val d = PubPackage.describe("dio", provenance = "NOTICES.Z")
        assertEquals("dio", d.name)
        assertEquals("https://pub.dev/packages/dio", d.url)
        assertEquals("NOTICES.Z", d.provenance)
        assertNull("version must stay unknown", d.version)
        assertNull("license must stay unknown", d.license)
    }

    @Test
    fun describeCarriesRecoveredMetadataWhenProvided() {
        val d = PubPackage.describe("dio", provenance = "NOTICES.Z", version = "5.4.0", license = "MIT")
        assertEquals("5.4.0", d.version)
        assertEquals("MIT", d.license)
    }

    @Test
    fun describeOnInvalidNameStillReportsTheRawNameWithoutUrl() {
        val d = PubPackage.describe("Foo-Bar")
        assertEquals("Foo-Bar", d.name)
        assertNull(d.url)
        assertNull(d.version)
        assertNull(d.license)
    }
}
