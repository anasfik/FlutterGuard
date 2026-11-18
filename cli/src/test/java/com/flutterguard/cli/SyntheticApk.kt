package com.flutterguard.cli

import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Minimal Android binary-XML manifest writer plus zip wrapper, so the end-to-end
 * tests always have an owned APK-shaped input in the repository — no private
 * corpus, no skip.
 *
 * Layout follows the decoder the engine uses (`AxmlDecoder`/`StringPool`):
 * XML header, one UTF-16 string pool, then start/end element chunks.
 */
internal object SyntheticApk {

    fun build(dir: File, debuggable: Boolean = true, name: String = "fixture.apk"): File {
        val apk = File(dir, name)
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(manifest(debuggable))
            zip.closeEntry()
        }
        return apk
    }

    private val strings = listOf(
        "manifest", "package", "com.example.fixture", "versionName", "1.0",
        "versionCode", "1", "application", "label", "Fixture", "debuggable",
        "allowBackup", "usesCleartextTraffic",
    )
    private const val MANIFEST = 0
    private const val PACKAGE = 1
    private const val PACKAGE_VALUE = 2
    private const val VERSION_NAME = 3
    private const val VERSION_NAME_VALUE = 4
    private const val VERSION_CODE = 5
    private const val VERSION_CODE_VALUE = 6
    private const val APPLICATION = 7
    private const val LABEL = 8
    private const val LABEL_VALUE = 9
    private const val DEBUGGABLE = 10
    private const val ALLOW_BACKUP = 11
    private const val USES_CLEARTEXT = 12

    private const val NODE_START = 0x0102
    private const val NODE_END = 0x0103

    fun manifest(debuggable: Boolean): ByteArray {
        val body = ByteArrayOutputStream()
        body.write(pool())
        body.write(start(MANIFEST, listOf(stringAttr(PACKAGE, PACKAGE_VALUE), stringAttr(VERSION_NAME, VERSION_NAME_VALUE), stringAttr(VERSION_CODE, VERSION_CODE_VALUE))))
        body.write(
            start(
                APPLICATION,
                listOf(
                    stringAttr(LABEL, LABEL_VALUE),
                    booleanAttr(DEBUGGABLE, debuggable),
                    booleanAttr(ALLOW_BACKUP, false),
                    booleanAttr(USES_CLEARTEXT, false),
                ),
            ),
        )
        body.write(end())
        body.write(end())
        val out = ByteArrayOutputStream()
        out.writeLe16(0x0003) // RES_XML_TYPE
        out.writeLe16(8)
        out.writeLe32(8 + body.size())
        out.write(body.toByteArray())
        return out.toByteArray()
    }

    private fun pool(): ByteArray {
        val data = ByteArrayOutputStream()
        val offsets = IntArray(strings.size)
        strings.forEachIndexed { i, s ->
            offsets[i] = data.size()
            data.writeLe16(s.length)
            for (c in s) data.writeLe16(c.code)
            data.writeLe16(0)
        }
        while (data.size() % 4 != 0) data.write(0)
        val out = ByteArrayOutputStream()
        out.writeLe16(0x0001) // RES_STRING_POOL_TYPE
        out.writeLe16(28)
        out.writeLe32(28 + 4 * strings.size + data.size())
        out.writeLe32(strings.size)
        out.writeLe32(0) // styleCount
        out.writeLe32(0) // flags: UTF-16
        out.writeLe32(28 + 4 * strings.size) // stringsStart: after the offset table
        out.writeLe32(0) // stylesStart
        offsets.forEach { out.writeLe32(it) }
        out.write(data.toByteArray())
        return out.toByteArray()
    }

    private fun start(nameIdx: Int, attrs: List<ByteArray>): ByteArray {
        val ext = ByteArrayOutputStream()
        ext.writeLe32(0) // lineNumber
        ext.writeLe32(-1) // comment
        ext.writeLe32(-1) // ns
        ext.writeLe32(nameIdx)
        ext.writeLe16(20) // attributeStart, from the attrExt struct
        ext.writeLe16(20) // attributeSize
        ext.writeLe16(attrs.size)
        ext.writeLe16(0) // idIndex
        ext.writeLe16(0) // classIndex
        ext.writeLe16(0) // styleIndex
        attrs.forEach { ext.write(it) }
        return chunk(NODE_START, ext.toByteArray())
    }

    private fun end(): ByteArray {
        val ext = ByteArrayOutputStream()
        ext.writeLe32(0)
        ext.writeLe32(-1)
        return chunk(NODE_END, ext.toByteArray())
    }

    private fun chunk(type: Int, ext: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeLe16(type)
        out.writeLe16(16)
        out.writeLe32(8 + ext.size)
        out.write(ext)
        return out.toByteArray()
    }

    private fun stringAttr(nameIdx: Int, valueIdx: Int): ByteArray = attr(nameIdx, raw = valueIdx, type = 0x03, data = 0)

    private fun booleanAttr(nameIdx: Int, value: Boolean): ByteArray =
        attr(nameIdx, raw = -1, type = 0x12, data = if (value) 1 else 0)

    private fun attr(nameIdx: Int, raw: Int, type: Int, data: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeLe32(-1) // ns
        out.writeLe32(nameIdx)
        out.writeLe32(raw)
        out.writeLe16(8) // value size
        out.write(0) // res0
        out.write(type)
        out.writeLe32(data)
        return out.toByteArray()
    }
}

private fun ByteArrayOutputStream.writeLe16(v: Int) {
    write(v and 0xFF)
    write((v shr 8) and 0xFF)
}

private fun ByteArrayOutputStream.writeLe32(v: Int) {
    write(v and 0xFF)
    write((v shr 8) and 0xFF)
    write((v shr 16) and 0xFF)
    write((v shr 24) and 0xFF)
}
