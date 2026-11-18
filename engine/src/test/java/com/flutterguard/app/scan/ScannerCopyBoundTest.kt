package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * The snapshot temp copy must cap ACTUAL bytes, not the zip entry's declared size:
 * a crafted APK can declare a small `libapp.so` and inflate without bound.
 */
class ScannerCopyBoundTest {

    @Test
    fun copiesExactlyTheLimit() {
        val out = ByteArrayOutputStream()
        val ok = copyBounded(ByteArrayInputStream(ByteArray(8)), out, 8)
        assertTrue(ok)
        assertEquals(8, out.size())
    }

    @Test
    fun refusesAStreamOverTheLimitAndWritesNoMore() {
        val out = ByteArrayOutputStream()
        val ok = copyBounded(ByteArrayInputStream(ByteArray(9)), out, 8)
        assertFalse(ok)
        assertTrue("wrote ${out.size()} bytes past an 8-byte cap", out.size() <= 8)
    }

    @Test
    fun acceptsAShorterStream() {
        val out = ByteArrayOutputStream()
        assertTrue(copyBounded(ByteArrayInputStream(ByteArray(3)), out, 8))
        assertEquals(3, out.size())
    }
}
