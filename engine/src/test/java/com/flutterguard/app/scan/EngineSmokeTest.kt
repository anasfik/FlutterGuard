package com.flutterguard.app.scan

import com.flutterguard.app.scan.parsers.AxmlNode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Proves the shipped analysis pipeline runs on a plain JVM: a generated APK
 * archive plus an independently built manifest tree, real report JSON, real
 * cancellation checkpoints and a malformed-archive failure.
 *
 * No Android class may be needed here; if one is, the engine extraction failed.
 */
class EngineSmokeTest {

    private fun generatedApk(dir: File): File {
        val apk = File(dir, "smoke.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("assets/config.yml"))
            zip.write("server: api.smoke.example.com\n".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/flutter_assets/pubspec.yaml"))
            zip.write("name: smoke_app\ndependencies:\n  dio: ^5.0.0\n".toByteArray())
            zip.closeEntry()
        }
        return apk
    }

    private fun manifest(): AxmlNode = AxmlNode("manifest").apply {
        attrs["package"] = "com.example.smoke"
        attrs["versionName"] = "1.2.3"
        attrs["versionCode"] = "12"
        children.add(AxmlNode("uses-sdk").apply {
            attrs["minSdkVersion"] = "26"
            attrs["targetSdkVersion"] = "35"
        })
        children.add(AxmlNode("application").apply {
            attrs["label"] = "Smoke"
            attrs["debuggable"] = "true"
            attrs["allowBackup"] = "false"
            attrs["usesCleartextTraffic"] = "false"
        })
    }

    private fun target() = ScanTarget(
        packageName = "com.example.smoke",
        label = "Smoke",
        versionName = "1.2.3",
        versionCode = 12,
        minSdk = 26,
        targetSdk = 35,
        isSystem = false,
    )

    @Test
    fun generatedApkRunsTheRealPipelineAndRoundtripsJson() = runBlocking {
        val dir = Files.createTempDirectory("fg-engine").toFile()
        try {
            val apk = generatedApk(dir)
            val stages = ArrayList<String>()
            val report = Scanner.scan(
                parts = listOf(ApkPart(apk, "base")),
                target = target(),
                manifestHint = manifest(),
                onProgress = { step, _ -> stages.add(step) },
            )

            assertEquals("Reading package info", stages.first())
            assertEquals("Done", stages.last())
            assertTrue(stages.contains("Decoding AndroidManifest"))
            assertTrue(stages.contains("Verifying signing"))
            assertEquals("com.example.smoke", report.meta.packageName)
            assertTrue(report.meta.fileScan)
            assertEquals(12L, report.meta.versionCode)
            assertEquals(26, report.meta.minSdk)
            assertEquals(35, report.meta.targetSdk)
            assertTrue("a HIGH debuggable finding must lower the grade", report.grade != 'A')

            assertTrue("debug manifest finding missing", report.findings.any { it.id == "MAN-DEBUG" })
            assertTrue("pubspec finding missing", report.findings.any { it.id == "FLUT-PUBSPEC" })
            assertTrue(
                "asset endpoint host missing: ${report.hosts}",
                report.hosts.any { it.host == "api.smoke.example.com" },
            )
            assertFalse(report.meta.baseSha256.isBlank())

            val json = ReportExport.toJson(report)
            assertTrue(json.contains("flutterguard/report/2"))
            val decoded = ReportJson.decode(json)
            assertNotNull("real org.json roundtrip failed", decoded)
            assertEquals(report.meta.packageName, decoded!!.meta.packageName)
            assertEquals(report.meta.versionCode, decoded.meta.versionCode)
            assertEquals(report.grade, decoded.grade)
            assertTrue(decoded.findings.any { it.id == "MAN-DEBUG" })
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun cancellationThrowsWithoutAReport() {
        val dir = Files.createTempDirectory("fg-engine-cancel").toFile()
        try {
            val apk = generatedApk(dir)
            val stages = ArrayList<String>()
            try {
                runBlocking {
                    Scanner.scan(
                        parts = listOf(ApkPart(apk, "base")),
                        target = target(),
                        manifestHint = manifest(),
                        onProgress = { step, _ -> stages.add(step) },
                        isCancelled = { true },
                    )
                }
                fail("a cancelled scan must not return a report")
            } catch (_: ScanCancelledException) {
                assertTrue("cancellation must be checked before progress", stages.isEmpty())
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun malformedApkFailsLoudly() {
        val dir = Files.createTempDirectory("fg-engine-bad").toFile()
        try {
            val bad = File(dir, "bad.apk").apply { writeText("not a zip archive") }
            val failure = runCatching {
                runBlocking { Scanner.scanFile(bad, onProgress = { _, _ -> }) }
            }.exceptionOrNull()
            assertTrue("a non-archive must fail with an input error, not return a report", failure is IOException)
        } finally {
            dir.deleteRecursively()
        }
    }
}
