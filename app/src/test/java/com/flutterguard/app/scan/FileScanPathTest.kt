package com.flutterguard.app.scan

import com.flutterguard.app.scan.parsers.AxmlNode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * The file-pick scan path without Android: copy the picked bytes, identify the
 * APK from its manifest, open it as a file-backed [ApkSource] and confirm the
 * scanner sees the same entries an installed-app source would.
 */
class FileScanPathTest {

    @Test
    fun boundedCopyWritesThePickedBytes() {
        val dir = createTempDir("fg-import")
        try {
            val target = File(dir, "picked.apk")
            FileImport.copyBounded(ByteArrayInputStream("apk-bytes".toByteArray()), target, 1024)
            assertEquals("apk-bytes", target.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun anOversizeOrEmptyPickLeavesNoPartialFile() {
        val dir = createTempDir("fg-import-refuse")
        try {
            val oversize = File(dir, "big.apk")
            try {
                FileImport.copyBounded(ByteArrayInputStream(ByteArray(64)), oversize, 32)
                fail("an oversize copy must fail")
            } catch (_: FileImportException) {
                // expected
            }
            assertTrue("no partial copy may remain", !oversize.exists())

            val empty = File(dir, "empty.apk")
            try {
                FileImport.copyBounded(ByteArrayInputStream(ByteArray(0)), empty, 32)
                fail("an empty file is not an APK")
            } catch (_: FileImportException) {
                // expected
            }
            assertTrue(!empty.exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aPickedApkOpensAsAFileBackedSource() {
        val dir = createTempDir("fg-file-source")
        try {
            val apk = File(dir, "sample.apk")
            ZipOutputStream(apk.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("assets/flutter_assets/kernel_blob.bin"))
                zip.write("flutter".toByteArray())
                zip.closeEntry()
            }
            ApkSource.forFile(apk).use { src ->
                assertEquals(apk, src.files.single())
                assertEquals(apk, src.primaryFile)
                assertEquals(apk.length(), src.totalBytes())
                assertEquals(1, src.partCount)
                assertTrue(src.names().contains("assets/flutter_assets/kernel_blob.bin"))
                assertNotNull(src.bytes("AndroidManifest.xml"))
                assertEquals("flutter", String(src.bytes("assets/flutter_assets/kernel_blob.bin")!!))
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun manifestIdentityComesFromTheApkNotTheFileName() {
        val manifest = AxmlNode("manifest").apply {
            attrs["package"] = "com.picked.app"
            attrs["versionName"] = "2.4.0"
            attrs["versionCode"] = "240"
            children.add(AxmlNode("uses-sdk").apply {
                attrs["minSdkVersion"] = "26"
                attrs["targetSdkVersion"] = "36"
            })
            children.add(AxmlNode("application").apply { attrs["label"] = "Picked App" })
        }
        val meta = Scanner.fileMeta(manifest, "renamed_by_user")
        assertNotNull(meta)
        assertEquals("com.picked.app", meta!!.packageName)
        assertEquals("Picked App", meta.label)
        assertEquals("2.4.0", meta.versionName)
        assertEquals(240L, meta.versionCode)
        assertEquals(26, meta.minSdk)
        assertEquals(36, meta.targetSdk)
    }

    @Test
    fun resourceReferencesFallBackInsteadOfInventingValues() {
        val manifest = AxmlNode("manifest").apply {
            attrs["package"] = "com.picked.app"
            attrs["versionName"] = "@string/app_name"
            attrs["versionCode"] = "@integer/version"
            children.add(AxmlNode("application").apply { attrs["label"] = "@string/app_name" })
        }
        val meta = Scanner.fileMeta(manifest, "sample")!!
        assertNull(meta.versionName)
        assertEquals(-1L, meta.versionCode)
        assertEquals("sample", meta.label)
    }

    @Test
    fun aManifestWithoutPackageIsRefused() {
        assertNull(Scanner.fileMeta(AxmlNode("manifest"), "sample"))
    }

    @Test
    fun aPackageNameThatCouldBreakARouteIsRefused() {
        fun manifest(pkg: String) = AxmlNode("manifest").apply { attrs["package"] = pkg }
        // The separator Nav.kt joins fields with: accepted, it would forge a
        // second route field and land on the installed app after a restart.
        assertNull(Scanner.fileMeta(manifest("com.example.app\u001Ftrue"), "x"))
        assertNull(Scanner.fileMeta(manifest("com"), "x"))
        assertNull(Scanner.fileMeta(manifest("9com.example"), "x"))
        assertNull(Scanner.fileMeta(manifest("com..example"), "x"))
        assertEquals("com.example", Scanner.fileMeta(manifest("com.example"), "x")?.packageName)
        assertEquals("com.example.app", Scanner.fileMeta(manifest("com.example.app"), "x")?.packageName)
        assertEquals("com.example_app.a1", Scanner.fileMeta(manifest("com.example_app.a1"), "x")?.packageName)
    }

    @Test
    fun fileScanReportsAreLabelledAndDecodeBack() {
        val meta = AppMeta(
            "com.picked.app", "Picked App", "2.4.0", 240, 26, 36, null, 0, 0, false, 0, 0,
            emptyList(), emptyList(), "", fileScan = true,
        )
        val report = Report(
            meta = meta,
            framework = FrameworkInfo(isFlutter = true),
            signing = SigningInfo(null, null, null, false, false, false, null, null, null, emptyList(), emptyList()),
            findings = emptyList(), hosts = emptyList(), channels = emptyList(), thirdParty = emptyList(),
            permissions = emptyList(), deepLinks = emptyList(),
            stats = ReportStats(0, 0, 0, 0, 0, 0, 0), grade = 'A',
        )
        // org.json is stubbed in JVM tests, so assert the tree the serializer
        // consumes plus the Markdown export (which is plain buildString).
        val metaMap = ReportExport.payload(report)["meta"] as Map<*, *>
        assertEquals(true, metaMap["fileScan"])
        assertTrue(
            "a file scan must be labelled in the Markdown export",
            ReportExport.toMarkdown(report).contains("picked APK file"),
        )
    }

    @Test
    fun historyCanBeTurnedOffWithoutLosingTheReport() {
        val dir = createTempDir("fg-import-history")
        try {
            val saved = ReportFiles.save(dir, "com.picked.app", "{\"a\":1}", "version:1", writeHistory = false)
            assertEquals("{\"a\":1}", saved.json.readText())
            assertNull(saved.history)
            assertTrue(saved.historyNote!!.contains("turned off"))
            assertTrue(!File(dir, "com_picked_app.hist").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun deletingAllReportsRemovesReportsHistoryAndMarkers() {
        val dir = createTempDir("fg-delete-all")
        try {
            ReportFiles.save(dir, "com.one.app", "{\"a\":1}", "version:1")
            ReportFiles.markInflight(dir, "com.two.app")
            File(dir, "unrelated.txt").writeText("keep me")

            assertEquals(3, ReportFiles.deleteAll(dir))
            assertEquals(listOf("unrelated.txt"), dir.listFiles()!!.map { it.name })
        } finally {
            dir.deleteRecursively()
        }
    }
}
