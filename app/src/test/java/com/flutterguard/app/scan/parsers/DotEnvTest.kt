package com.flutterguard.app.scan.parsers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DotEnvTest {

    private val sample = """
        # shipped with the bundle
        BASE_URL=https://api.example.com
        export ORALIZE_X_SECRET="156acf5a9d1e"
        SENTRY_DSN='https://abc@o1.ingest.sentry.io/1' # prod
        FORCE_INVALID_STARTUP_AUTH_TOKENS=true
        EMPTY=
    """.trimIndent()

    @Test
    fun parsesNamesValuesAndComments() {
        val entries = DotEnv.parse(sample).associate { it.name to it.value }
        assertEquals("https://api.example.com", entries["BASE_URL"])
        assertEquals("156acf5a9d1e", entries["ORALIZE_X_SECRET"])
        assertEquals("https://abc@o1.ingest.sentry.io/1", entries["SENTRY_DSN"])
        assertEquals("true", entries["FORCE_INVALID_STARTUP_AUTH_TOKENS"])
        assertEquals("", entries["EMPTY"])
        assertEquals(5, entries.size) // '# shipped with the bundle' is a comment
    }

    @Test
    fun skipsCommentsAndSplitsOnlyOnFirstEquals() {
        val entries = DotEnv.parse("# c\nA=b=c\n")
        assertEquals(listOf(DotEnv.Entry("A", "b=c")), entries)
    }

    @Test
    fun recognisesCredentialLikeNames() {
        assertTrue(DotEnv.isSecret("ORALIZE_X_SECRET"))
        assertTrue(DotEnv.isSecret("GOOGLE_MAPS_ANDROID_API_KEY"))
        assertTrue(DotEnv.isSecret("SENTRY_DSN"))
        assertTrue(DotEnv.isSecret("hipP0_app_key"))
        assertFalse(DotEnv.isSecret("BASE_URL"))
        assertFalse(DotEnv.isSecret("ENABLE_NETWORK_LOGGING"))
    }
}
