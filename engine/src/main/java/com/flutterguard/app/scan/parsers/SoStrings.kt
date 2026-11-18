package com.flutterguard.app.scan.parsers

import java.io.InputStream

/**
 * Streaming printable-ASCII run extractor for native libraries (.so).
 * Dart AOT snapshots keep string literals as plain ASCII in .rodata, so this
 * recovers URLs, keys, package: URIs and channel names without a full ELF
 * parser. Strings are delivered to [consumer] with their file offset; memory
 * stays flat regardless of library size.
 */
object SoStrings {
    private const val MIN_RUN = 5
    private const val MAX_STRING_LEN = 4096

    fun forEach(input: InputStream, maxBytes: Long = Long.MAX_VALUE, consumer: (String, Long) -> Unit) {
        val buf = ByteArray(1 shl 20)
        var run = StringBuilder()
        var runStart = 0L
        var filePos = 0L
        var remaining = maxBytes
        while (remaining > 0) {
            val want = minOf(buf.size.toLong(), remaining).toInt()
            val n = input.read(buf, 0, want)
            if (n <= 0) break
            remaining -= n
            for (i in 0 until n) {
                val c = buf[i].toInt() and 0xFF
                if (c in 0x20..0x7E) {
                    if (run.isEmpty()) runStart = filePos + i
                    run.append(c.toChar())
                    if (run.length >= MAX_STRING_LEN) {
                        consumer(run.toString(), runStart)
                        run.setLength(0)
                    }
                } else {
                    if (run.length >= MIN_RUN) consumer(run.toString(), runStart)
                    run.setLength(0)
                }
            }
            filePos += n
        }
        if (run.length >= MIN_RUN) consumer(run.toString(), runStart)
    }
}
