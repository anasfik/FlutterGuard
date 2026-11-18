package com.flutterguard.cli

import com.flutterguard.app.scan.parsers.AxmlDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/** The generated fixture only helps if the engine's own decoder reads it. */
class SyntheticApkTest {

    @Test
    fun manifestDecodesToTheExpectedIdentity() {
        val root = AxmlDecoder.decode(SyntheticApk.manifest(debuggable = true))
        assertNotNull("the synthetic manifest must decode", root)
        assertEquals("manifest", root!!.name)
        assertEquals("com.example.fixture", root.attr("package"))
        assertEquals("1.0", root.attr("versionName"))
        assertEquals("1", root.attr("versionCode"))
        val app = root.child("application")
        assertNotNull("the manifest must declare an application element", app)
        assertEquals("Fixture", app!!.attr("label"))
        assertEquals("true", app.attr("debuggable"))
    }
}
