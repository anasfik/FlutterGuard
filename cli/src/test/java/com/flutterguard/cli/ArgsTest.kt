package com.flutterguard.cli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Argument contract: every malformed invocation must fail with exit 2 before any
 * filesystem effect. Exit codes are asserted through [runCli], never a process.
 */
class ArgsTest {

    private class Run(val code: Int, val out: String, val err: String)

    private fun run(vararg argv: String): Run {
        val out = StringBuilder()
        val err = StringBuilder()
        val code = runCli(arrayOf(*argv), out, err)
        return Run(code, out.toString(), err.toString())
    }

    private fun assertUsageError(name: String, vararg argv: String) {
        val r = run(*argv)
        assertEquals("$name: exit code", 2, r.code)
        assertEquals("$name: stdout must stay empty", "", r.out)
        assertTrue("$name: stderr must explain the usage error", r.err.isNotBlank())
    }

    @Test
    fun rejectsUnknownSwitch() {
        val dir = Files.createTempDirectory("fg-argv").toFile()
        try {
            val apk = File(dir, "in.apk").apply { writeText("x") }
            assertUsageError("unknown switch", "scan", apk.path, "--json", File(dir, "o.json").path, "--bogus")
            assertTrue("no output may be created", File(dir, "o.json").exists().not())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rejectsRepeatedSwitch() {
        val dir = Files.createTempDirectory("fg-argv").toFile()
        try {
            val apk = File(dir, "in.apk").apply { writeText("x") }
            assertUsageError(
                "repeated --json", "scan", apk.path,
                "--json", File(dir, "a.json").path, "--json", File(dir, "b.json").path,
            )
            assertTrue(!File(dir, "a.json").exists() && !File(dir, "b.json").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rejectsMissingValue() {
        val dir = Files.createTempDirectory("fg-argv").toFile()
        try {
            val apk = File(dir, "in.apk").apply { writeText("x") }
            assertUsageError("missing --json value", "scan", apk.path, "--json")
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rejectsUnknownFailOnValue() {
        val dir = Files.createTempDirectory("fg-argv").toFile()
        try {
            val apk = File(dir, "in.apk").apply { writeText("x") }
            assertUsageError(
                "bad --fail-on", "scan", apk.path,
                "--json", File(dir, "o.json").path, "--fail-on", "suspected",
            )
            assertTrue(!File(dir, "o.json").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rejectsMissingInput() {
        assertUsageError("missing input", "scan", "--json", "/tmp/never-written.json")
    }

    @Test
    fun rejectsMissingJsonOutput() {
        val dir = Files.createTempDirectory("fg-argv").toFile()
        try {
            val apk = File(dir, "in.apk").apply { writeText("x") }
            assertUsageError("missing --json", "scan", apk.path)
        } finally {
            dir.deleteRecursively()
        }
    }
}
