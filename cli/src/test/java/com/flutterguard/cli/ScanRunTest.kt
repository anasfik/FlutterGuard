package com.flutterguard.cli

import com.flutterguard.app.scan.ReportExport
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * End-to-end runner contract: exit codes, published JSON/SARIF, the confirmed
 * gate, cancellation, output failures and the real process entry point.
 *
 * The input is generated in-test ([SyntheticApk]) so there is no private corpus
 * and no skip: every assertion below runs on every machine.
 */
class ScanRunTest {

    private class Run(val code: Int, val out: String, val err: String)

    private fun run(vararg argv: String): Run {
        val out = StringBuilder()
        val err = StringBuilder()
        val code = runCli(arrayOf(*argv), out, err)
        return Run(code, out.toString(), err.toString())
    }

    private fun withApk(debuggable: Boolean = true, block: (File, File) -> Unit) {
        val dir = Files.createTempDirectory("fg-cli").toFile()
        try {
            block(dir, SyntheticApk.build(dir, debuggable))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun scansFixtureAndPublishesRedactedJsonAndSarif() = withApk { dir, apk ->
        val json = File(dir, "report.json")
        val sarif = File(dir, "report.sarif")
        val r = run("scan", apk.path, "--json", json.path, "--sarif", sarif.path)
        assertEquals("scan must succeed: ${r.err}", 0, r.code)
        assertEquals("stdout must stay empty", "", r.out)
        assertTrue("progress must reach stderr", r.err.isNotBlank())

        val report = JSONObject(json.readText())
        assertEquals("flutterguard/report/2", report.getString("schema"))
        assertEquals("com.example.fixture", report.getJSONObject("meta").getString("packageName"))
        assertTrue(report.getJSONArray("findings").length() > 0)

        val sarifRoot = JSONObject(sarif.readText())
        assertEquals("2.1.0", sarifRoot.getString("version"))
        assertEquals(1, sarifRoot.getJSONArray("runs").length())
        assertFalse("binary artifacts carry no source regions", sarif.readText().contains("\"region\""))
        val uri = sarifRoot.getJSONArray("runs").getJSONObject(0).getJSONArray("results")
            .getJSONObject(0).getJSONArray("locations").getJSONObject(0)
            .getJSONObject("physicalLocation").getJSONObject("artifactLocation").getString("uri")
        assertEquals("the location must be the scanned APK, not the report", apk.absoluteFile.toURI().toString(), uri)
    }

    @Test
    fun garbageInputFailsWithoutPublishingAnything() {
        val dir = Files.createTempDirectory("fg-cli-bad").toFile()
        try {
            val bad = File(dir, "bad.apk").apply { writeText("this is not a zip archive") }
            val json = File(dir, "report.json")
            val r = run("scan", bad.path, "--json", json.path)
            assertEquals("unsupported input must exit 2: ${r.err}", 2, r.code)
            assertFalse("no output may be published", json.exists())
            assertEquals("stdout must stay empty", "", r.out)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun confirmedGateExitsOneOnADebuggableFixture() = withApk { dir, apk ->
        val json = File(dir, "report.json")
        val r = run("scan", apk.path, "--json", json.path, "--fail-on", "confirmed")
        assertEquals("a CONFIRMED finding must exit 1: ${r.err}", 1, r.code)

        val findings = JSONObject(json.readText()).getJSONArray("findings")
        val confirmed = (0 until findings.length()).count { findings.getJSONObject(it).getString("kind") == "CONFIRMED" }
        assertTrue("fixture must prove at least one confirmed fact", confirmed > 0)
        assertTrue(r.err.contains("gate: $confirmed confirmed finding(s)"))
    }

    @Test
    fun noConfirmedFindingsMeansTheGateDoesNotFire() = withApk(debuggable = false) { dir, apk ->
        val json = File(dir, "release-like.json")
        val r = run("scan", apk.path, "--json", json.path)
        assertEquals("scan must succeed: ${r.err}", 0, r.code)
        val findings = JSONObject(json.readText()).getJSONArray("findings")
        val confirmedIds = (0 until findings.length())
            .map { findings.getJSONObject(it) }
            .filter { it.getString("kind") == "CONFIRMED" }
            .map { it.getString("id") }
        assertEquals("a non-debuggable manifest must not be a confirmed fact: $confirmedIds", 0, confirmedIds.size)

        val gated = File(dir, "release-like-gated.json")
        val g = run("scan", apk.path, "--json", gated.path, "--fail-on", "confirmed")
        assertEquals("no CONFIRMED finding must exit 0: ${g.err}", 0, g.code)
        assertTrue(gated.exists())
    }

    @Test
    fun interruptedCliThreadCancelsTheScan() = withApk { dir, apk ->
        val json = File(dir, "report.json")
        val out = StringBuilder()
        val err = StringBuilder()
        val code = try {
            Thread.currentThread().interrupt()
            runCli(arrayOf("scan", apk.path, "--json", json.path), out, err)
        } finally {
            Thread.interrupted() // clear the flag for the rest of the suite
        }
        assertEquals("cancellation must exit 2: $err", 2, code)
        assertFalse("no output may be published", json.exists())
        assertTrue("the message must say the scan was cancelled: $err", err.contains("cancelled"))
    }

    @Test
    fun unbuildableReportIsExitTwoAndNeverTheGateCode() = withApk { dir, apk ->
        val json = File(dir, "report.json")
        val out = StringBuilder()
        val err = StringBuilder()
        val code = runCli(
            arrayOf("scan", apk.path, "--json", json.path),
            out,
            err,
            render = { throw org.json.JSONException("unserializable report") },
        )
        assertEquals("a report projection failure must be exit 2, not 1: $err", 2, code)
        assertFalse(json.exists())
        assertTrue("the error must name the failed step: $err", err.contains("cannot build report"))
    }

    @Test
    fun outputCreatedDuringTheScanIsNotOverwritten() = withApk { dir, apk ->
        val json = File(dir, "report.json")
        val out = StringBuilder()
        val err = StringBuilder()
        val code = runCli(
            arrayOf("scan", apk.path, "--json", json.path),
            out,
            err,
            render = { report ->
                json.writeText("RACING JOB")
                ReportExport.toJson(report)
            },
        )
        assertEquals("a destination that appeared mid-run must be refused: $err", 2, code)
        assertEquals("RACING JOB", json.readText())
    }

    @Test
    fun launcherProcessReportsThroughStderrAndExitsTwo() {
        val dir = Files.createTempDirectory("fg-cli-proc").toFile()
        try {
            val bad = File(dir, "bad.apk").apply { writeText("not an archive") }
            val json = File(dir, "report.json")
            val java = File(System.getProperty("java.home"), "bin/java").path
            val process = ProcessBuilder(
                java, "-cp", System.getProperty("java.class.path"),
                "com.flutterguard.cli.MainKt",
                "scan", bad.path, "--json", json.path,
            ).redirectErrorStream(false).start()
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            val code = process.waitFor()
            assertEquals("process exit code ($stderr)", 2, code)
            assertEquals("stdout must stay empty", "", stdout)
            assertTrue("stderr must carry the error", stderr.isNotBlank())
            assertFalse(json.exists())
        } finally {
            dir.deleteRecursively()
        }
    }
}
