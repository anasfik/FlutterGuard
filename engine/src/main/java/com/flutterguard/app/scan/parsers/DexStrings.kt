package com.flutterguard.app.scan.parsers

import java.nio.ByteBuffer

/**
 * Streams the string table of a classes*.dex. DEX header layout:
 *   0x38 string_ids_size (u32), 0x3C string_ids_off (u32).
 * Each string_id is a u32 offset to: uleb128(utf16_length) + MUTF-8 bytes + 0x00.
 *
 * Strings are handed to [consumer] one at a time to keep memory flat on large
 * multidex apps; [maxStrings] bounds pathological inputs.
 */
object DexStrings {
    private const val MAX_STRINGS = 1_500_000

    fun isDex(bytes: ByteArray): Boolean =
        bytes.size > 0x40 && bytes[0] == 'd'.code.toByte() && bytes[1] == 'e'.code.toByte() &&
            bytes[2] == 'x'.code.toByte() && bytes[3] == '\n'.code.toByte()

    fun forEach(bytes: ByteArray, source: String, maxStrings: Int = MAX_STRINGS, consumer: (String, String, Long) -> Unit) {
        if (!isDex(bytes)) return
        val b = Binary.buffer(bytes)
        b.position(0x38)
        val count = b.int
        val idsOff = b.int
        if (count <= 0 || idsOff <= 0 || idsOff.toLong() + count * 4L > bytes.size) return
        val limit = minOf(count, maxStrings)
        val sb = StringBuilder(64)
        for (i in 0 until limit) {
            b.position(idsOff + i * 4)
            val dataOff = b.int
            if (dataOff <= 0 || dataOff >= bytes.size) continue
            b.position(dataOff)
            val utf16Len = Uleb128.read(b)
            if (utf16Len <= 0 || utf16Len > 0x8000) continue
            sb.setLength(0)
            var units = 0
            var ok = true
            while (units < utf16Len && b.position() < bytes.size) {
                val c1 = b.get().toInt() and 0xFF
                when {
                    c1 and 0x80 == 0 -> {
                        if (c1 == 0) { ok = false; break }
                        sb.append(c1.toChar()); units++
                    }
                    c1 and 0xE0 == 0xC0 -> {
                        if (b.position() >= bytes.size) { ok = false; break }
                        val c2 = b.get().toInt() and 0x3F
                        sb.append((((c1 and 0x1F) shl 6) or c2).toChar()); units++
                    }
                    c1 and 0xF0 == 0xE0 -> {
                        if (b.position() + 1 >= bytes.size) { ok = false; break }
                        val c2 = b.get().toInt() and 0x3F
                        val c3 = b.get().toInt() and 0x3F
                        sb.append((((c1 and 0x0F) shl 12) or (c2 shl 6) or c3).toChar()); units++
                    }
                    else -> { ok = false; break }
                }
            }
            if (ok && sb.isNotEmpty()) consumer(sb.toString(), source, dataOff.toLong())
        }
    }
}
