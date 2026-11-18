package com.flutterguard.app.scan

import java.io.File
import java.io.RandomAccessFile

/**
 * Dart VM snapshot kind. The numeric value is the on-disk header field from
 * `runtime/vm/snapshot.h` (`Snapshot::Kind`); it is never inferred from size,
 * file names or string counts.
 */
enum class SnapshotKind(val wire: Long, val label: String) {
    FULL(0, "full"),
    FULL_CORE(1, "full-core"),
    FULL_JIT(2, "full-JIT"),
    FULL_AOT(3, "full-AOT"),
    MODULE(4, "module"),
    NONE(5, "none"),
    INVALID(6, "invalid"),
    ;

    companion object {
        /** Only an exact wire value is a kind; everything else stays unknown. */
        fun of(wire: Long): SnapshotKind? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * Observed AOT snapshot header facts.
 *
 * [storedLength] is the header field at offset 4 (everything after the four
 * magic bytes). [serializationHash] is the opaque 32-char hash; it identifies a
 * snapshot serialization format, not an engine version. [features] are VM build
 * configuration tokens, not app identity and not an obfuscation flag.
 */
data class SnapshotMetadata(
    val symbol: String,
    val fileOffset: Long,
    val storedLength: Long,
    val kind: SnapshotKind,
    val serializationHash: String,
    val features: List<String>,
)

/**
 * Bounded reader for the Dart AOT snapshot header inside one native library.
 *
 * Only the 64-bit little-endian ELF layouts Dart ships for Android are read,
 * and only through the exported snapshot symbol resolved by PT_LOAD virtual
 * address: a magic sequence elsewhere in .rodata is not evidence. Reads are
 * seek+small-buffer; the whole library is never loaded. Any malformed or
 * ambiguous input returns null, so a scan can never fail or guess from this.
 *
 * ponytail: header facts only. Ownership, Dart/Flutter version and the object
 * graph end here; use a host-side Blutter/aotopsy run as the oracle once those
 * questions are actually needed.
 */
object DartSnapshot {

    private const val HEADER = 20
    private const val HASH_LEN = 32
    private const val MAX_FEATURES = 1024
    private const val MAX_PHDRS = 512
    private const val MAX_SHDRS = 1024
    private const val MAX_SYMBOLS = 65536
    private const val MAX_SYMBOL_NAME = 64
    private const val MIN_SNAPSHOT: Long = 53 // 20-byte header + 32-byte hash + at least a NUL
    private const val ELF_HEADER = 64
    private const val PT_LOAD = 1L
    private const val SHT_SYMTAB = 2L
    private const val SHT_DYNSYM = 11L
    private const val SYM_ENTRY = 24

    /** Older Dart exports the isolate symbol; newer builds drop the isolate prefix. */
    private val SYMBOLS = listOf("_kDartIsolateSnapshotData", "_kDartSnapshotData")

    private val HASH = Regex("[0-9a-f]{32}")

    /** Null for anything this reader does not fully verify. Never throws. */
    fun read(file: File): SnapshotMetadata? = runCatching { readOrNull(file) }.getOrNull()

    private class Load(val offset: Long, val vaddr: Long, val size: Long)
    private class Section(val symOffset: Long, val symSize: Long, val strOffset: Long, val strSize: Long)

    private fun readOrNull(file: File): SnapshotMetadata? {
        if (!file.isFile) return null
        val fileLength = file.length()
        if (fileLength < ELF_HEADER) return null
        RandomAccessFile(file, "r").use { f ->
            val ehdr = readAt(f, 0, ELF_HEADER, fileLength) ?: return null
            if (ehdr[0] != 0x7F.toByte() || ehdr[1] != 'E'.code.toByte() ||
                ehdr[2] != 'L'.code.toByte() || ehdr[3] != 'F'.code.toByte()
            ) return null
            // 64-bit, little-endian, EV_CURRENT. No big-endian/32-bit guessing.
            if (ehdr[4] != 2.toByte() || ehdr[5] != 1.toByte() || ehdr[6] != 1.toByte()) return null

            val phoff = u64(ehdr, 32)
            val shoff = u64(ehdr, 40)
            val phentsize = u16(ehdr, 54)
            val phnum = u16(ehdr, 56)
            val shentsize = u16(ehdr, 58)
            val shnum = u16(ehdr, 60)
            if (phentsize < 56 || phnum == 0 || phnum > MAX_PHDRS) return null
            if (shentsize < 64 || shnum == 0 || shnum > MAX_SHDRS) return null
            if (!fits(phoff, phentsize.toLong() * phnum, fileLength)) return null
            if (!fits(shoff, shentsize.toLong() * shnum, fileLength)) return null

            val loads = ArrayList<Load>()
            for (i in 0 until phnum) {
                val h = readAt(f, phoff + i.toLong() * phentsize, 56, fileLength) ?: return null
                if (u32(h, 0) != PT_LOAD) continue
                val offset = u64(h, 8)
                val vaddr = u64(h, 16)
                val size = u64(h, 32)
                if (!fits(offset, size, fileLength)) return null
                loads.add(Load(offset, vaddr, size))
            }
            if (loads.isEmpty()) return null

            val sections = ArrayList<Section>()
            for (i in 0 until shnum) {
                val h = readAt(f, shoff + i.toLong() * shentsize, 64, fileLength) ?: return null
                val type = u32(h, 4)
                if (type != SHT_SYMTAB && type != SHT_DYNSYM) continue
                val offset = u64(h, 24)
                val size = u64(h, 32)
                val link = u32(h, 40)
                val entsize = u64(h, 56)
                if (entsize < SYM_ENTRY || size < SYM_ENTRY || size % SYM_ENTRY != 0L) continue
                if (link >= shnum || !fits(offset, size, fileLength)) continue
                val strHeader = readAt(f, shoff + link * shentsize, 64, fileLength) ?: continue
                val strOffset = u64(strHeader, 24)
                val strSize = u64(strHeader, 32)
                if (!fits(strOffset, strSize, fileLength)) continue
                sections.add(Section(offset, size, strOffset, strSize))
            }
            if (sections.isEmpty()) return null

            for (section in sections) {
                val count = minOf(section.symSize / SYM_ENTRY, MAX_SYMBOLS.toLong())
                for (i in 0 until count) {
                    val sym = readAt(f, section.symOffset + i * SYM_ENTRY, SYM_ENTRY, fileLength) ?: continue
                    val nameOffset = u32(sym, 0)
                    val value = u64(sym, 8)
                    val symbolSize = u64(sym, 16)
                    if (symbolSize < MIN_SNAPSHOT) continue
                    if (nameOffset >= section.strSize) continue
                    val name = readCString(
                        f, section.strOffset + nameOffset, section.strSize - nameOffset, fileLength,
                        MAX_SYMBOL_NAME,
                    ) ?: continue
                    if (name !in SYMBOLS) continue
                    val offset = mapVaddr(loads, value, fileLength) ?: continue
                    parseAt(f, offset, symbolSize, fileLength, name)?.let { return it }
                }
            }
        }
        return null
    }

    private fun parseAt(
        f: RandomAccessFile,
        offset: Long,
        symbolSize: Long,
        fileLength: Long,
        symbol: String,
    ): SnapshotMetadata? {
        if (symbolSize < MIN_SNAPSHOT || !fits(offset, MIN_SNAPSHOT, fileLength)) return null
        val header = readAt(f, offset, HEADER, fileLength) ?: return null
        if (header[0] != 0xF5.toByte() || header[1] != 0xF5.toByte() ||
            header[2] != 0xDC.toByte() || header[3] != 0xDC.toByte()
        ) return null

        val stored = u64(header, 4)
        if (stored < HEADER || stored > fileLength - 4) return null
        val total = 4 + stored
        if (total < MIN_SNAPSHOT || total > symbolSize || !fits(offset, total, fileLength)) return null

        val kind = SnapshotKind.of(u64(header, 12)) ?: return null

        val hashBytes = readAt(f, offset + HEADER, HASH_LEN, fileLength) ?: return null
        val serializationHash = String(hashBytes, Charsets.US_ASCII)
        if (!HASH.matches(serializationHash)) return null

        // Feature bytes are capped and must terminate with NUL inside the cap.
        val available = total - HEADER - HASH_LEN
        val featureLimit = minOf(MAX_FEATURES.toLong(), available)
        if (featureLimit <= 0) return null
        val featureBytes = readAt(f, offset + HEADER + HASH_LEN, featureLimit.toInt(), fileLength) ?: return null
        val nul = featureBytes.indexOf(0)
        if (nul < 0) return null
        if (featureBytes.take(nul).any { it < 0x20 || it > 0x7E }) return null
        val features = String(featureBytes, 0, nul, Charsets.US_ASCII)
            .split(' ')
            .filter { it.isNotEmpty() }

        return SnapshotMetadata(symbol, offset, stored, kind, serializationHash, features)
    }

    private fun mapVaddr(loads: List<Load>, value: Long, fileLength: Long): Long? {
        for (load in loads) {
            if (value < load.vaddr) continue
            val delta = value - load.vaddr
            if (delta >= load.size) continue
            val offset = load.offset + delta
            if (fits(offset, 1, fileLength)) return offset
        }
        return null
    }

    /** Bounded seek+read: never allocates more than [n] bytes. */
    private fun readAt(f: RandomAccessFile, offset: Long, n: Int, fileLength: Long): ByteArray? {
        if (!fits(offset, n.toLong(), fileLength)) return null
        val buf = ByteArray(n)
        f.seek(offset)
        f.readFully(buf)
        return buf
    }

    private fun readCString(
        f: RandomAccessFile,
        offset: Long,
        available: Long,
        fileLength: Long,
        maxLen: Int,
    ): String? {
        val n = minOf(available, maxLen.toLong())
        if (n <= 0) return null
        val bytes = readAt(f, offset, n.toInt(), fileLength) ?: return null
        val nul = bytes.indexOf(0)
        if (nul <= 0) return null
        return String(bytes, 0, nul, Charsets.US_ASCII)
    }

    private fun fits(offset: Long, size: Long, length: Long): Boolean =
        offset >= 0 && size >= 0 && offset <= length && size <= length - offset

    private fun u16(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

    private fun u32(b: ByteArray, off: Int): Long =
        (b[off].toLong() and 0xFF) or
            ((b[off + 1].toLong() and 0xFF) shl 8) or
            ((b[off + 2].toLong() and 0xFF) shl 16) or
            ((b[off + 3].toLong() and 0xFF) shl 24)

    private fun u64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0..7) v = v or ((b[off + i].toLong() and 0xFF) shl (8 * i))
        return v
    }
}
