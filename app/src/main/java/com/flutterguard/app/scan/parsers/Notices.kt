package com.flutterguard.app.scan.parsers

import java.io.InputStream
import java.util.zip.GZIPInputStream

/**
 * Flutter ships `assets/flutter_assets/NOTICES.Z` — a gzipped dump of every pub
 * package license, each block introduced by a line of dashes followed by the
 * package name. That list survives `--obfuscate`, so it recovers the dependency
 * inventory even when libapp.so symbols are stripped.
 */
object Notices {

    private val pkgName = Regex("""^[a-z][a-z0-9_]{1,40}$""")

    fun packages(input: InputStream, maxChars: Int = 12_000_000): List<String> {
        val names = LinkedHashSet<String>()
        var expectName = false
        var total = 0
        try {
            GZIPInputStream(input).bufferedReader(Charsets.UTF_8).use { r ->
                while (true) {
                    val line = r.readLine() ?: break
                    total += line.length
                    if (total > maxChars) break
                    if (expectName) {
                        expectName = false
                        val n = line.trim()
                        if (pkgName.matches(n)) names.add(n)
                        continue
                    }
                    if (line.length >= 10 && line.all { it == '-' }) expectName = true
                }
            }
        } catch (_: Exception) {
        }
        return names.toList()
    }
}
