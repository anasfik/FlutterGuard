package com.flutterguard.app.scan

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

class ApkPart(val file: File, val role: String)

/**
 * Read access to an installed app's artifacts: base.apk plus its split APKs.
 * Opens the world-readable files under /data/app directly; no copy needed on
 * stock Android (a ROM that blocks this fails fast with a clear error).
 */
class ApkSource(parts: List<ApkPart>) : AutoCloseable {

    private val zips: MutableList<ZipFile> = ArrayList()

    init {
        for (p in parts) zips.add(ZipFile(p.file))
    }

    val partCount: Int get() = zips.size

    /** All entries across all parts, prefixed by part role for provenance. */
    fun entries(): List<Pair<String, ZipEntry>> {
        val out = ArrayList<Pair<String, ZipEntry>>()
        for (z in zips) {
            val en = z.entries()
            while (en.hasMoreElements()) {
                val e = en.nextElement()
                out.add(e.name to e)
            }
        }
        return out
    }

    fun entry(name: String): Pair<ZipFile, ZipEntry>? {
        for (z in zips) {
            val e = z.getEntry(name)
            if (e != null) return z to e
        }
        return null
    }

    fun stream(name: String): InputStream? = entry(name)?.let { (z, e) -> z.getInputStream(e) }

    fun bytes(name: String, maxBytes: Int = 64 * 1024 * 1024): ByteArray? {
        val (z, e) = entry(name) ?: return null
        val expected = e.size
        if (expected < 0 || expected > maxBytes) return null
        return z.getInputStream(e).use { ins ->
            val buf = ByteArray(expected.toInt())
            var off = 0
            while (off < buf.size) {
                val n = ins.read(buf, off, buf.size - off)
                if (n <= 0) break
                off += n
            }
            if (off == buf.size) buf else buf.copyOf(off)
        }
    }

    fun names(): Set<String> {
        val set = HashSet<String>()
        for (z in zips) {
            val en = z.entries()
            while (en.hasMoreElements()) set.add(en.nextElement().name)
        }
        return set
    }

    override fun close() {
        for (z in zips) runCatching { z.close() }
    }

    companion object {
        fun sha256(file: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { ins ->
                val buf = ByteArray(1 shl 16)
                while (true) {
                    val n = ins.read(buf)
                    if (n <= 0) break
                    md.update(buf, 0, n)
                }
            }
            return md.digest().joinToString("") { "%02x".format(it) }
        }

        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        fun forApplication(ai: android.content.pm.ApplicationInfo): ApkSource {
            val parts = ArrayList<ApkPart>()
            val base = ai.publicSourceDir ?: ai.sourceDir
            if (base != null) parts.add(ApkPart(File(base), "base"))
            val splits = ai.splitSourceDirs
            if (splits != null) {
                for (s in splits) {
                    val f = File(s)
                    parts.add(ApkPart(f, f.name.removeSuffix(".apk")))
                }
            }
            return ApkSource(parts)
        }
    }
}
