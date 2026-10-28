package com.flutterguard.app.scan.parsers

import java.nio.ByteBuffer

/**
 * Extracts the global string pool of resources.arsc. That pool holds the
 * resource *values* (every string in strings.xml and friends), which is the
 * layer secret-scanner must cover. Package-level key pools hold entry names
 * and are less interesting for secrets, so they are skipped.
 */
object ArscReader {
    fun globalStrings(bytes: ByteArray): List<String> {
        if (bytes.size < 12) return emptyList()
        val b = Binary.buffer(bytes)
        val type = Binary.u16(b)
        if (type != Binary.RES_TABLE_TYPE) return emptyList()
        val headerSize = b.short.toInt() and 0xFFFF
        b.int // chunk size
        b.int // packageCount
        // The global string pool follows the table header, whose size is declared
        // in the header itself — not always the 12-byte minimum.
        if (headerSize < 12 || headerSize + 8 > bytes.size) return emptyList()
        b.position(headerSize)
        if (Binary.u16(b) != Binary.RES_STRING_POOL_TYPE) return emptyList()
        b.position(headerSize)
        return try {
            StringPool.parse(b)
        } catch (_: Exception) {
            emptyList()
        }
    }
}
