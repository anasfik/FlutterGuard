package com.flutterguard.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipFile

/**
 * Bounded Dart AOT snapshot header reader. Synthetic ELF fixtures for every
 * validation branch plus the two owned release APKs, which are skipped when the
 * benchmark artifacts are absent from this checkout.
 */
class DartSnapshotTest {

    // ---------------------------------------------------------------- fixtures

    private val hash = "ace654289f5abc240509fc941453ebc5"

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xFF).toByte()
        b[off + 1] = ((v ushr 8) and 0xFF).toByte()
    }

    private fun put32(b: ByteArray, off: Int, v: Long) {
        for (i in 0..3) b[off + i] = ((v ushr (8 * i)) and 0xFF).toByte()
    }

    private fun put64(b: ByteArray, off: Int, v: Long) {
        for (i in 0..7) b[off + i] = ((v ushr (8 * i)) and 0xFF).toByte()
    }

    private fun snapshotBytes(
        kind: Long = 3,
        magic: ByteArray = byteArrayOf(0xF5.toByte(), 0xF5.toByte(), 0xDC.toByte(), 0xDC.toByte()),
        features: String = "product arm64 android compressed-pointers",
        serializationHash: String = hash,
    ): ByteArray {
        val feat = features.toByteArray(Charsets.US_ASCII)
        val total = 20 + 32 + feat.size + 1
        val b = ByteArray(total)
        System.arraycopy(magic, 0, b, 0, 4)
        put64(b, 4, (total - 4).toLong())
        put64(b, 12, kind)
        System.arraycopy(serializationHash.toByteArray(Charsets.US_ASCII), 0, b, 20, 32)
        System.arraycopy(feat, 0, b, 52, feat.size)
        return b
    }

    /**
     * ELF64 LE shared object: one PT_LOAD covering the whole file, .dynsym and
     * .dynstr sections, and the snapshot bytes at 4096 addressed by one symbol.
     */
    private fun elf(
        snapshot: ByteArray,
        symbolName: String = "_kDartIsolateSnapshotData",
        elfClass: Byte = 2,
    ): ByteArray {
        val dynstr = symbolName.toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        val dynstrOff = 256
        val dynsymOff = 320
        val shoff = 512
        val snapshotOff = 4096
        val total = snapshotOff + snapshot.size
        val b = ByteArray(total)

        b[0] = 0x7F
        b[1] = 'E'.code.toByte()
        b[2] = 'L'.code.toByte()
        b[3] = 'F'.code.toByte()
        b[4] = elfClass
        b[5] = 1 // little endian
        b[6] = 1 // EV_CURRENT
        put16(b, 16, 3) // ET_DYN
        put16(b, 18, 183) // EM_AARCH64
        put32(b, 20, 1)
        put64(b, 32, 64) // e_phoff
        put64(b, 40, shoff.toLong())
        put16(b, 52, 64) // e_ehsize
        put16(b, 54, 56) // e_phentsize
        put16(b, 56, 1) // e_phnum
        put16(b, 58, 64) // e_shentsize
        put16(b, 60, 3) // e_shnum
        put16(b, 62, 0) // e_shstrndx: names are never read

        // PT_LOAD: offset == vaddr == 0, whole file.
        put32(b, 64, 1)
        put32(b, 64 + 4, 4)
        put64(b, 64 + 8, 0)
        put64(b, 64 + 16, 0)
        put64(b, 64 + 24, 0)
        put64(b, 64 + 32, total.toLong())
        put64(b, 64 + 40, total.toLong())
        put64(b, 64 + 48, 0x1000)

        System.arraycopy(dynstr, 0, b, dynstrOff, dynstr.size)

        // Elf64_Sym: st_name=0, st_info=GLOBAL|OBJECT, st_shndx=1.
        put32(b, dynsymOff, 0)
        b[dynsymOff + 4] = 0x11
        put16(b, dynsymOff + 6, 1)
        put64(b, dynsymOff + 8, snapshotOff.toLong())
        put64(b, dynsymOff + 16, snapshot.size.toLong())

        // Section 1: .dynsym (SHT_DYNSYM, link=2), section 2: .dynstr.
        val s1 = shoff + 64
        put32(b, s1 + 4, 11)
        put64(b, s1 + 16, dynsymOff.toLong())
        put64(b, s1 + 24, dynsymOff.toLong())
        put64(b, s1 + 32, 24)
        put32(b, s1 + 40, 2)
        put32(b, s1 + 44, 1)
        put64(b, s1 + 48, 8)
        put64(b, s1 + 56, 24)

        val s2 = shoff + 128
        put32(b, s2 + 4, 3)
        put64(b, s2 + 16, dynstrOff.toLong())
        put64(b, s2 + 24, dynstrOff.toLong())
        put64(b, s2 + 32, dynstr.size.toLong())
        put64(b, s2 + 48, 1)

        System.arraycopy(snapshot, 0, b, snapshotOff, snapshot.size)
        return b
    }

    private fun read(bytes: ByteArray): SnapshotMetadata? {
        val f = File.createTempFile("fg-snapshot-test", ".so")
        return try {
            f.writeBytes(bytes)
            DartSnapshot.read(f)
        } finally {
            f.delete()
        }
    }

    // ------------------------------------------------------------- valid/bounded

    @Test
    fun validFullAotHeaderIsRead() {
        val meta = read(elf(snapshotBytes()))
        assertNotNull("a well-formed full-AOT header must parse", meta)
        meta!!
        assertEquals("_kDartIsolateSnapshotData", meta.symbol)
        assertEquals(4096L, meta.fileOffset)
        assertEquals(SnapshotKind.FULL_AOT, meta.kind)
        assertEquals(hash, meta.serializationHash)
        assertTrue(
            "feature tokens must be split and preserved",
            meta.features.containsAll(listOf("product", "arm64", "android", "compressed-pointers")),
        )
        // 20-byte header + 32-byte hash + 41 feature bytes + NUL, minus 4 magic bytes.
        assertEquals("stored length excludes the four magic bytes", 90L, meta.storedLength)
    }

    @Test
    fun newerSnapshotSymbolAlsoResolves() {
        val meta = read(elf(snapshotBytes(), symbolName = "_kDartSnapshotData"))
        assertEquals(SnapshotKind.FULL_AOT, meta?.kind)
    }

    @Test
    fun nonAotKindParsesButIsNotAotEvidence() {
        val meta = read(elf(snapshotBytes(kind = 2)))
        assertEquals("the header is observed, not promoted", SnapshotKind.FULL_JIT, meta?.kind)
    }

    // ------------------------------------------------------------- negative cases

    @Test
    fun truncatedFileIsUnknown() {
        val valid = elf(snapshotBytes())
        assertNull(read(valid.copyOf(4096 + 30)))
    }

    @Test
    fun wrongMagicIsUnknown() {
        assertNull(read(elf(snapshotBytes(magic = byteArrayOf(0, 0, 0, 0)))))
    }

    @Test
    fun oversizedFeaturesAreUnknown() {
        val features = "a".repeat(1025)
        assertNull(read(elf(snapshotBytes(features = features))))
    }

    @Test
    fun badKindIsUnknown() {
        assertNull(read(elf(snapshotBytes(kind = 9))))
        assertNull(read(elf(snapshotBytes(kind = -1))))
    }

    @Test
    fun missingSymbolIsUnknown() {
        assertNull(read(elf(snapshotBytes(), symbolName = "_kNotTheSnapshot")))
    }

    @Test
    fun malformedSerializationHashIsUnknown() {
        assertNull(read(elf(snapshotBytes(serializationHash = "z".repeat(32)))))
    }

    @Test
    fun unsupportedElfClassIsUnknown() {
        assertNull(read(elf(snapshotBytes(), elfClass = 1)))
    }

    @Test
    fun missingFileIsUnknown() {
        assertNull(DartSnapshot.read(File("/nonexistent/fg/libapp.so")))
    }

    // ------------------------------------------------------ owned real artifacts

    private fun apk(name: String): File? =
        listOf("../benchmark-app/dist/$name", "benchmark-app/dist/$name")
            .map { File(it) }
            .firstOrNull { it.isFile }

    private fun readFromApk(apk: File): SnapshotMetadata? {
        ZipFile(apk).use { z ->
            val entry = z.getEntry("lib/arm64-v8a/libapp.so") ?: return null
            val tmp = File.createTempFile("fg-libapp", ".so")
            return try {
                z.getInputStream(entry).use { ins -> tmp.outputStream().use { out -> ins.copyTo(out) } }
                DartSnapshot.read(tmp)
            } finally {
                tmp.delete()
            }
        }
    }

    private fun assertOwnedFixture(name: String, storedLength: Long) {
        val apk = apk(name)
        assumeTrue("owned fixture absent: $name", apk != null)
        val meta = readFromApk(apk!!)
        assertNotNull("$name must expose a readable snapshot header", meta)
        meta!!
        assertEquals(17856L, meta.fileOffset)
        assertEquals(SnapshotKind.FULL_AOT, meta.kind)
        assertEquals(hash, meta.serializationHash)
        assertEquals(storedLength, meta.storedLength)
        assertTrue(
            "features must record the observed arm64 product configuration: ${meta.features}",
            // The header stores these space-separated. The brief's
            // "product/arm64/android/compressed-pointers" is shorthand for the
            // triple, not a literal token in the header.
            meta.features.containsAll(listOf("product", "arm64", "android", "compressed-pointers")),
        )
    }

    @Test
    fun plainReleaseApkHeader() = assertOwnedFixture("benchmark-plain-release.apk", 1232199L)

    @Test
    fun obfuscatedReleaseApkHeader() = assertOwnedFixture("benchmark-obfuscated-release.apk", 545060L)
}
