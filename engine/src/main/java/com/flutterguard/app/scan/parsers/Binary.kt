package com.flutterguard.app.scan.parsers

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal readers for Android binary formats. Everything works on ByteBuffers
 * in LITTLE_ENDIAN, matching the on-disk AXML / ARSC / DEX layouts.
 */
object Binary {
    const val RES_STRING_POOL_TYPE = 0x0001
    const val RES_XML_TYPE = 0x0003
    const val RES_TABLE_TYPE = 0x0002

    fun buffer(bytes: ByteArray): ByteBuffer =
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

    fun u16(b: ByteBuffer): Int = b.short.toInt() and 0xFFFF
    fun u32(b: ByteBuffer): Long = b.int.toLong() and 0xFFFFFFFFL
}

/**
 * Parses a RES_STRING_POOL_TYPE chunk (shared by AXML documents and resources.arsc).
 * Returns the decoded strings in pool order.
 */
object StringPool {
    fun parse(b: ByteBuffer): List<String> {
        val poolStart = b.position()
        Binary.u16(b) // chunk type (RES_STRING_POOL_TYPE)
        val headerSize = Binary.u16(b)
        val chunkSize = Binary.u32(b).toInt()
        val stringCount = b.int
        b.int // styleCount
        val flags = b.int
        val stringsStart = b.int
        b.int // stylesStart
        val isUtf8 = (flags and (1 shl 8)) != 0

        // Untrusted lengths: a bogus stringCount used to allocate an IntArray of
        // 80M+ entries and kill the app. Everything must fit inside the chunk.
        if (chunkSize <= headerSize || poolStart + chunkSize > b.limit()) return emptyList()
        if (stringCount < 0 || stringCount > (chunkSize - headerSize) / 4) return emptyList()

        // Offsets live immediately after the (variable-length) chunk header.
        b.position(poolStart + headerSize)
        val offsets = IntArray(stringCount)
        for (i in 0 until stringCount) offsets[i] = b.int

        val dataBase = poolStart + stringsStart
        val out = ArrayList<String>(stringCount)
        val chunkEnd = poolStart + chunkSize
        for (off in offsets) {
            val pos = dataBase + off
            if (pos < 0 || pos >= b.limit() || pos >= chunkEnd) {
                out.add(""); continue
            }
            b.position(pos)
            out.add(if (isUtf8) readUtf8(b) else readUtf16(b))
        }
        return out
    }

    private fun readLen8(b: ByteBuffer): Int {
        val first = b.get().toInt() and 0xFF
        return if (first and 0x80 != 0) ((first and 0x7F) shl 8) or (b.get().toInt() and 0xFF) else first
    }

    private fun readLen16(b: ByteBuffer): Int {
        val first = b.short.toInt() and 0xFFFF
        return if (first and 0x8000 != 0) ((first and 0x7FFF) shl 16) or (b.short.toInt() and 0xFFFF) else first
    }

    private fun readUtf8(b: ByteBuffer): String {
        readLen8(b) // character count (unused here, byte count follows)
        val byteLen = readLen8(b)
        val bytes = ByteArray(byteLen)
        b.get(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    private fun readUtf16(b: ByteBuffer): String {
        val len = readLen16(b)
        val sb = StringBuilder(len)
        var i = 0
        while (i < len && b.remaining() >= 2) {
            sb.append(b.char); i++
        }
        return sb.toString()
    }
}

/** ULEB128 reader used by the DEX string table. */
object Uleb128 {
    fun read(b: ByteBuffer): Int {
        var result = 0
        var shift = 0
        while (true) {
            val cur = b.get().toInt() and 0xFF
            result = result or ((cur and 0x7F) shl shift)
            if (cur and 0x80 == 0) break
            shift += 7
        }
        return result
    }
}
