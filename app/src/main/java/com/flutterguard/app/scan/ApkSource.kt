package com.flutterguard.app.scan

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

class ApkPart(val file: File, val role: String)

/**
 * One bounded preview read. [text] is null for binary content; [truncated] means
 * the entry held more bytes than were read (never assume the preview is whole).
 */
data class TextPreview(val text: String?, val binary: Boolean, val truncated: Boolean, val bytesRead: Int)

/**
 * Read access to an installed app's artifacts: base.apk plus its split APKs.
 * Opens the world-readable files under /data/app directly; no copy needed on
 * stock Android (a ROM that blocks this fails fast with a clear error).
 */
class ApkSource(parts: List<ApkPart>) : AutoCloseable {

    private val zips: MutableList<ZipFile> = ArrayList()
    private val roles: List<String> = parts.map { it.role }

    init {
        // A later part failing to open must not leak the zips already opened.
        try {
            for (p in parts) zips.add(ZipFile(p.file))
        } catch (t: Throwable) {
            close()
            throw t
        }
    }

    val partCount: Int get() = zips.size

    /** Typed inventory: one row per entry per part, duplicate split paths kept. */
    fun artifactEntries(): List<ArtifactEntry> {
        val out = ArrayList<ArtifactEntry>()
        for ((i, z) in zips.withIndex()) {
            val en = z.entries()
            while (en.hasMoreElements()) {
                val e = en.nextElement()
                if (e.isDirectory) continue
                out.add(
                    ArtifactEntry(
                        partIndex = i,
                        partRole = roles[i],
                        name = e.name,
                        compressedBytes = e.compressedSize.toLong(),
                        uncompressedBytes = e.size.toLong(),
                        category = classifyEntry(e.name),
                    ),
                )
            }
        }
        return out
    }

    /** Bounded text preview of one entry from one specific part. Never extracts. */
    fun preview(partIndex: Int, entryName: String, maxBytes: Int = DEFAULT_PREVIEW_BYTES): TextPreview? {
        if (partIndex !in zips.indices || !isSafeEntryName(entryName)) return null
        val z = zips[partIndex]
        val e = z.getEntry(entryName) ?: return null
        if (e.isDirectory) return null
        val cap = maxBytes.coerceIn(1, MAX_PREVIEW_BYTES)
        return z.getInputStream(e).use { ins ->
            val buf = ByteArray(cap)
            var off = 0
            while (off < cap) {
                val n = ins.read(buf, off, cap - off)
                if (n <= 0) break
                off += n
            }
            val data = buf.copyOf(off)
            val truncated = off >= cap && (e.size < 0 || e.size > off)
            if (data.any { it == 0.toByte() }) {
                TextPreview(text = null, binary = true, truncated = truncated, bytesRead = off)
            } else {
                TextPreview(String(data, Charsets.UTF_8), binary = false, truncated = truncated, bytesRead = off)
            }
        }
    }

    private fun isSafeEntryName(name: String): Boolean {
        if (name.isBlank() || name.startsWith("/") || name.contains('\\') || name.contains('\u0000')) return false
        val segs = name.split('/')
        return segs.none { it.isEmpty() || it == "." || it == ".." }
    }

    private fun classifyEntry(name: String): ArtifactCategory {
        val n = name.lowercase()
        return when {
            n == "androidmanifest.xml" -> ArtifactCategory.MANIFEST
            Regex("""^classes\d*\.dex$""").matches(n) -> ArtifactCategory.DEX
            n.startsWith("lib/") && n.endsWith(".so") -> ArtifactCategory.NATIVE_LIB
            n.endsWith("/kernel_blob.bin") || n == "kernel_blob.bin" -> ArtifactCategory.KERNEL
            n == ".env" || n.endsWith("/.env") || n.contains("/.env.") ||
                n == "google-services.json" || n.endsWith("/google-services.json") ||
                n.endsWith(".properties") && !n.contains('/') -> ArtifactCategory.CONFIG
            n.endsWith(".jks") || n.endsWith(".keystore") || n.endsWith(".p12") || n.endsWith(".pem") ->
                ArtifactCategory.KEY_MATERIAL
            n.startsWith("meta-inf/") && (n.endsWith(".rsa") || n.endsWith(".dsa") || n.endsWith(".ec") ||
                n.endsWith(".sf") || n.endsWith(".mf")) -> ArtifactCategory.SIGNING
            n.startsWith("assets/") -> ArtifactCategory.ASSET
            n.startsWith("res/") -> ArtifactCategory.RESOURCE
            else -> ArtifactCategory.OTHER
        }
    }


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
        /** Default bounded preview; a caller may ask for less, never for more than [MAX_PREVIEW_BYTES]. */
        const val DEFAULT_PREVIEW_BYTES = 32 * 1024
        const val MAX_PREVIEW_BYTES = 128 * 1024

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
