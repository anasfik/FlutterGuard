package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Typed APK entry inventory, bounded previews and part-scoped validation. */
class ApkPreviewTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun zip(name: String, entries: Map<String, ByteArray>): File {
        val f = tmp.newFile(name)
        ZipOutputStream(f.outputStream().buffered()).use { z ->
            for ((n, bytes) in entries) {
                z.putNextEntry(ZipEntry(n))
                z.write(bytes)
                z.closeEntry()
            }
        }
        return f
    }

    private fun fdCount(): Int? =
        File("/proc/self/fd").listFiles()?.size

    @Test
    fun constructorFailureClosesEarlierOpenedZips() {
        assumeTrue("fd accounting needs /proc", File("/proc/self/fd").isDirectory)
        val good = zip("base.apk", mapOf("AndroidManifest.xml" to bytes("<m/>")))
        val garbage = tmp.newFile("split.apk").apply { writeBytes(ByteArray(64) { 1 }) }
        val before = fdCount()
        val thrown = runCatching {
            ApkSource(listOf(ApkPart(good, "base"), ApkPart(garbage, "config")))
        }.exceptionOrNull()
        assertNotNull("a non-zip part must fail the constructor", thrown)
        val after = fdCount()
        if (before != null && after != null) {
            assertTrue("earlier zips leaked fds: before=$before after=$after", after <= before)
        }
    }

    @Test
    fun duplicateSplitPathsKeepDistinctProvenance() {
        val base = zip("base.apk", mapOf("lib/arm64-v8a/libapp.so" to bytes("FROM-BASE")))
        val split = zip("split.apk", mapOf("lib/arm64-v8a/libapp.so" to bytes("FROM-SPLIT")))
        ApkSource(listOf(ApkPart(base, "base"), ApkPart(split, "config_config"))).use { src ->
            val rows = src.artifactEntries().filter { it.name == "lib/arm64-v8a/libapp.so" }
            assertEquals("duplicate path must appear once per part", 2, rows.size)
            assertEquals(listOf(0, 1), rows.map { it.partIndex })
            assertEquals(listOf("base", "config_config"), rows.map { it.partRole })
            assertEquals(ArtifactCategory.NATIVE_LIB, rows[0].category)
            // Preview must read from the selected part, not the first match.
            val fromBase = src.preview(0, "lib/arm64-v8a/libapp.so")!!
            val fromSplit = src.preview(1, "lib/arm64-v8a/libapp.so")!!
            assertEquals("FROM-BASE", fromBase.text)
            assertEquals("FROM-SPLIT", fromSplit.text)
        }
    }

    @Test
    fun entryNotInTheSelectedPartIsRejected() {
        val base = zip("base.apk", mapOf("only/in/base.txt" to bytes("base-only")))
        val split = zip("split.apk", mapOf("only/in/split.txt" to bytes("split-only")))
        ApkSource(listOf(ApkPart(base, "base"), ApkPart(split, "split"))).use { src ->
            assertNull(src.preview(1, "only/in/base.txt"))
            assertNull(src.preview(0, "only/in/split.txt"))
            assertNull("out-of-range part must be rejected", src.preview(5, "only/in/base.txt"))
            assertNotNull(src.preview(0, "only/in/base.txt"))
        }
    }

    @Test
    fun traversalAndAbsoluteEntryNamesAreRejected() {
        val f = zip("base.apk", mapOf("../evil.txt" to bytes("x"), "/abs.txt" to bytes("y"), "a/../b.txt" to bytes("z")))
        ApkSource(listOf(ApkPart(f, "base"))).use { src ->
            // The malicious entries are listed as evidence …
            val names = src.artifactEntries().map { it.name }
            assertTrue("../evil.txt" in names)
            // … but never previewable.
            assertNull(src.preview(0, "../evil.txt"))
            assertNull(src.preview(0, "/abs.txt"))
            assertNull(src.preview(0, "a/../b.txt"))
            assertNull(src.preview(0, "..\\win.txt"))
            assertNull(src.preview(0, ""))
        }
    }

    @Test
    fun oversizedTextPreviewIsBoundedAndMarkedTruncated() {
        val big = ByteArray(100 * 1024) { i -> ('a' + (i % 26)).code.toByte() }
        val f = zip("base.apk", mapOf("assets/big.txt" to big))
        ApkSource(listOf(ApkPart(f, "base"))).use { src ->
            val p = src.preview(0, "assets/big.txt")!!
            assertFalse("plain ASCII text misclassified as binary", p.binary)
            assertTrue("truncation must be reported", p.truncated)
            assertEquals(ApkSource.DEFAULT_PREVIEW_BYTES, p.bytesRead)
            assertEquals(ApkSource.DEFAULT_PREVIEW_BYTES, p.text!!.length)
        }
    }

    @Test
    fun previewSizeArgumentIsCappedEvenWhenAbsurd() {
        val big = ByteArray(512 * 1024) { i -> ('a' + (i % 26)).code.toByte() }
        val f = zip("base.apk", mapOf("assets/big.txt" to big))
        ApkSource(listOf(ApkPart(f, "base"))).use { src ->
            val p = src.preview(0, "assets/big.txt", maxBytes = Int.MAX_VALUE)!!
            assertTrue(p.bytesRead <= ApkSource.MAX_PREVIEW_BYTES)
            assertTrue(p.truncated)
        }
    }

    @Test
    fun exactSizeTextIsNotTruncated() {
        val exact = ByteArray(ApkSource.DEFAULT_PREVIEW_BYTES) { i -> ('a' + (i % 26)).code.toByte() }
        val f = zip("base.apk", mapOf("assets/exact.txt" to exact))
        ApkSource(listOf(ApkPart(f, "base"))).use { src ->
            val p = src.preview(0, "assets/exact.txt")!!
            assertEquals(ApkSource.DEFAULT_PREVIEW_BYTES, p.bytesRead)
            assertFalse("exact-fit content must not be flagged truncated", p.truncated)
            assertEquals(ApkSource.DEFAULT_PREVIEW_BYTES, p.text!!.length)
        }
    }

    @Test
    fun binaryEntriesAreDistinguishedFromText() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01, 0x02)
        val f = zip("base.apk", mapOf("res/icon.png" to png, "assets/ok.txt" to bytes("hello world")))
        ApkSource(listOf(ApkPart(f, "base"))).use { src ->
            val bin = src.preview(0, "res/icon.png")!!
            assertTrue("PNG must be detected as binary", bin.binary)
            assertNull("binary preview must not fabricate text", bin.text)
            val txt = src.preview(0, "assets/ok.txt")!!
            assertFalse(txt.binary)
            assertEquals("hello world", txt.text)
            assertFalse(txt.truncated)
        }
    }

    @Test
    fun categoriesMatchKnownEntryRoles() {
        val f = zip(
            "base.apk",
            mapOf(
                "AndroidManifest.xml" to bytes("m"),
                "classes.dex" to bytes("d"),
                "classes2.dex" to bytes("d"),
                "lib/arm64-v8a/libapp.so" to bytes("s"),
                "assets/flutter_assets/kernel_blob.bin" to bytes("k"),
                "assets/flutter_assets/.env" to bytes("e"),
                "google-services.json" to bytes("{}"),
                "META-INF/CERT.RSA" to bytes("c"),
                "res/layout/main.xml" to bytes("x"),
                "assets/flutter_assets/AssetManifest.json" to bytes("{}"),
                "unknown.bin" to bytes("u"),
            ),
        )
        ApkSource(listOf(ApkPart(f, "base"))).use { src ->
            val byName = src.artifactEntries().associateBy { it.name }
            assertEquals(ArtifactCategory.MANIFEST, byName.getValue("AndroidManifest.xml").category)
            assertEquals(ArtifactCategory.DEX, byName.getValue("classes2.dex").category)
            assertEquals(ArtifactCategory.NATIVE_LIB, byName.getValue("lib/arm64-v8a/libapp.so").category)
            assertEquals(ArtifactCategory.KERNEL, byName.getValue("assets/flutter_assets/kernel_blob.bin").category)
            assertEquals(ArtifactCategory.CONFIG, byName.getValue("assets/flutter_assets/.env").category)
            assertEquals(ArtifactCategory.CONFIG, byName.getValue("google-services.json").category)
            assertEquals(ArtifactCategory.SIGNING, byName.getValue("META-INF/CERT.RSA").category)
            assertEquals(ArtifactCategory.RESOURCE, byName.getValue("res/layout/main.xml").category)
            assertEquals(ArtifactCategory.ASSET, byName.getValue("assets/flutter_assets/AssetManifest.json").category)
            assertEquals(ArtifactCategory.OTHER, byName.getValue("unknown.bin").category)
            val manifest = byName.getValue("AndroidManifest.xml")
            assertEquals(0, manifest.partIndex)
            assertEquals("base", manifest.partRole)
            assertTrue("compressed size reported", manifest.compressedBytes > 0)
            assertEquals(1, manifest.uncompressedBytes)
        }
    }

    private fun bytes(s: String) = s.toByteArray(Charsets.UTF_8)
}
