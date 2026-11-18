package com.flutterguard.cli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Output destinations may never be the scanned artifact, and an existing output
 * may never be truncated by a failing run.
 */
class OutputSafetyTest {

    private fun run(vararg argv: String): Pair<Int, String> {
        val out = StringBuilder()
        val err = StringBuilder()
        return runCli(arrayOf(*argv), out, err) to (out.toString() + err.toString())
    }

    private fun tempDir(): File = Files.createTempDirectory("fg-out").toFile()

    @Test
    fun rejectsOutputEqualToInput() {
        val dir = tempDir()
        try {
            val apk = File(dir, "in.apk").apply { writeText("original-apk-bytes") }
            val before = apk.readBytes()
            val (code, log) = run("scan", apk.path, "--json", apk.path)
            assertEquals("exit code ($log)", 2, code)
            assertTrue("input bytes changed", before.contentEquals(apk.readBytes()))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rejectsSymlinkToInput() {
        val dir = tempDir()
        try {
            val apk = File(dir, "in.apk").apply { writeText("original-apk-bytes") }
            val link = File(dir, "out.json").toPath()
            Files.createSymbolicLink(link, apk.toPath())
            val before = apk.readBytes()
            val (code, log) = run("scan", apk.path, "--json", link.toString())
            assertEquals("exit code ($log)", 2, code)
            assertTrue("input bytes changed", before.contentEquals(apk.readBytes()))
            assertTrue("the symlink must still point at the input", Files.isSymbolicLink(link))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rejectsHardlinkAliasOfInput() {
        val dir = tempDir()
        try {
            val apk = File(dir, "in.apk").apply { writeText("original-apk-bytes") }
            val link = File(dir, "out.json")
            Files.createLink(link.toPath(), apk.toPath())
            val (code, log) = run("scan", apk.path, "--json", link.path)
            assertEquals("a hardlink is the same file, so it must be refused ($log)", 2, code)
            assertEquals("original-apk-bytes", apk.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun existingOutputIsRefusedAndNeverTruncated() {
        val dir = tempDir()
        try {
            val apk = File(dir, "in.apk").apply { writeText("not an apk at all") }
            val output = File(dir, "report.json").apply { writeText("PREVIOUS REPORT") }
            val (code, log) = run("scan", apk.path, "--json", output.path)
            assertEquals("exit code ($log)", 2, code)
            assertEquals("PREVIOUS REPORT", output.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun missingOutputDirectoryIsAnOutputError() {
        val dir = tempDir()
        try {
            val apk = SyntheticApk.build(dir)
            val output = File(dir, "missing/report.json")
            val (code, log) = run("scan", apk.path, "--json", output.path)
            assertEquals("a missing output directory must be exit 2 ($log)", 2, code)
            assertFalse("no file may be created", output.exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun sarifFailurePublishesNoJson() {
        val dir = tempDir()
        try {
            val apk = SyntheticApk.build(dir)
            val json = File(dir, "report.json")
            val sarif = File(dir, "missing/report.sarif")
            val (code, log) = run("scan", apk.path, "--json", json.path, "--sarif", sarif.path)
            assertEquals("an unwritable SARIF destination must be exit 2 ($log)", 2, code)
            assertFalse("a half-published pair must not leave the JSON behind", json.exists())
            val leftovers = dir.listFiles()!!.map { it.name }.filter { it != "in.apk" && it != "fixture.apk" }
            assertTrue("temporary files must be removed: $leftovers", leftovers.isEmpty())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun failedScanLeavesNoPartialOrTemporaryOutput() {
        val dir = tempDir()
        try {
            val apk = File(dir, "in.apk").apply { writeText("definitely not a zip archive") }
            val output = File(dir, "report.json")
            val (code, log) = run("scan", apk.path, "--json", output.path)
            assertEquals("exit code ($log)", 2, code)
            assertFalse("no report may be published for a failed scan", output.exists())
            val leftovers = dir.listFiles()!!.map { it.name }.filter { it != "in.apk" }
            assertTrue("temporary files must be removed: $leftovers", leftovers.isEmpty())
        } finally {
            dir.deleteRecursively()
        }
    }
}
