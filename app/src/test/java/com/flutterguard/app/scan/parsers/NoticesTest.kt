package com.flutterguard.app.scan.parsers

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NoticesTest {

    /** NOTICES.Z shape: license text, a dashed rule, then the package name on its own line. */
    private val notices = """
        ------------------------------------------------------------
        flutter
        Copyright 2014 The Flutter Authors

        ------------------------------------------------------------
        package_info_plus
        Copyright 2019 The package_info_plus Authors

        ------------------------------------------------------------
        sentry_flutter
        Copyright 2020 Sentry
        ------------------------------------------------------------
        Not a package name
    """.trimIndent()

    private fun gzip(text: String): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(text.toByteArray()) }
        return out.toByteArray()
    }

    @Test
    fun extractsPackageNamesAfterDashedRules() {
        val packages = Notices.packages(ByteArrayInputStream(gzip(notices)))
        assertEquals(listOf("flutter", "package_info_plus", "sentry_flutter"), packages)
    }

    @Test
    fun ignoresGarbageAndEmptyInput() {
        assertTrue(Notices.packages(ByteArrayInputStream(gzip("no rules here"))).isEmpty())
        assertTrue(Notices.packages(ByteArrayInputStream(gzip(""))).isEmpty())
    }
}
