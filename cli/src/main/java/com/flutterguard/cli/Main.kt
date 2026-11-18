package com.flutterguard.cli

import com.flutterguard.app.scan.FindingKind
import com.flutterguard.app.scan.ReportExport
import com.flutterguard.app.scan.ScanCancelledException
import com.flutterguard.app.scan.Scanner
import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

private const val USAGE =
    "usage: flutterguard scan INPUT.apk --json OUTPUT.json [--sarif OUTPUT.sarif] [--fail-on confirmed]"

private class UsageException(message: String) : Exception(message)

private class CliArgs(val input: File, val json: File, val sarif: File?, val failOnConfirmed: Boolean)

fun main(args: Array<String>) {
    kotlin.system.exitProcess(runCli(args, System.out, System.err))
}

/**
 * Testable entry point. Returns the process exit code; never calls exitProcess.
 *
 * 0 completed scan, 1 completed scan that hit the requested gate, 2 anything
 * that prevented a trustworthy report. The gate is evaluated only after every
 * output has been published, so it can never mask a scan or write failure.
 */
fun runCli(
    args: Array<String>,
    out: Appendable,
    err: Appendable,
    render: (com.flutterguard.app.scan.Report) -> String = {
        ReportExport.toJson(it, ReportExport.allSections, sensitive = false)
    },
): Int {
    val parsed = try {
        parse(args)
    } catch (e: UsageException) {
        err.appendLine("flutterguard: ${e.message}")
        err.appendLine(USAGE)
        return 2
    }

    if (!parsed.input.isFile) return fail(err, "input is not a file: ${parsed.input.path}")
    if (!Files.isReadable(parsed.input.toPath())) return fail(err, "input is not readable: ${parsed.input.path}")

    val inputPath = resolved(parsed.input)
    for (o in listOfNotNull(parsed.json, parsed.sarif)) {
        if (resolved(o) == inputPath) return fail(err, "output must not be the input APK: ${o.path}")
        // A hardlink is a different path but the same file; resolved paths miss it.
        val same = o.exists() && runCatching { Files.isSameFile(o.toPath(), parsed.input.toPath()) }.getOrDefault(false)
        if (same) return fail(err, "output must not be the input APK: ${o.path}")
    }
    if (parsed.sarif != null && resolved(parsed.json) == resolved(parsed.sarif!!)) {
        return fail(err, "--json and --sarif must be different files")
    }
    for (o in listOfNotNull(parsed.json, parsed.sarif)) {
        if (o.exists()) return fail(err, "output already exists: ${o.path}")
    }

    // Cancellation must observe the thread the caller interrupted, not an IO
    // worker inside the engine.
    val caller = Thread.currentThread()
    lateinit var report: com.flutterguard.app.scan.Report
    try {
        report = runBlocking {
            Scanner.scanFile(
                parsed.input,
                onProgress = { step, pct -> err.appendLine("[$pct%] $step") },
                isCancelled = { caller.isInterrupted || Thread.currentThread().isInterrupted },
            )
        }
    } catch (e: ScanCancelledException) {
        return fail(err, "scan cancelled")
    } catch (e: InterruptedException) {
        return fail(err, "scan cancelled")
    } catch (e: IllegalArgumentException) {
        return fail(err, "invalid input: ${e.message}")
    } catch (e: IOException) {
        return fail(err, "cannot read input: ${e.message}")
    } catch (e: Exception) {
        return fail(err, "scan failed: ${e.javaClass.simpleName}: ${e.message}")
    }

    // Build every payload before publishing any of them.
    val json = try {
        render(report)
    } catch (e: Exception) {
        return fail(err, "cannot build report: ${e.message}")
    }
    val sarif = parsed.sarif?.let {
        try {
            Sarif.document(report, parsed.input.absoluteFile.toURI().toString()).also { doc -> Sarif.validate(doc) }
        } catch (e: Exception) {
            return fail(err, "cannot build SARIF: ${e.message}")
        }
    }

    try {
        val payloads = buildList {
            add(parsed.json to json.toByteArray(Charsets.UTF_8))
            if (parsed.sarif != null && sarif != null) add(parsed.sarif!! to sarif.toByteArray(Charsets.UTF_8))
        }
        publishAll(payloads)
    } catch (e: FileAlreadyExistsException) {
        return fail(err, "output already exists: ${e.file}")
    } catch (e: Exception) {
        return fail(err, "cannot write output: ${e.message}")
    }

    if (parsed.failOnConfirmed) {
        val confirmed = report.findings.count { it.kind == FindingKind.CONFIRMED }
        if (confirmed > 0) {
            err.appendLine("gate: $confirmed confirmed finding(s)")
            return 1
        }
    }
    return 0
}

private fun fail(err: Appendable, message: String): Int {
    err.appendLine("flutterguard: $message")
    return 2
}

private fun parse(argv: Array<String>): CliArgs {
    if (argv.isEmpty()) throw UsageException("missing command")
    if (argv[0] != "scan") throw UsageException("unknown command '${argv[0]}'")
    var input: File? = null
    var json: File? = null
    var sarif: File? = null
    var failOn: String? = null
    var i = 1
    while (i < argv.size) {
        val a = argv[i]
        if (a.startsWith("-")) {
            if (a != "--json" && a != "--sarif" && a != "--fail-on") throw UsageException("unknown switch '$a'")
            val value = argv.getOrNull(i + 1)?.takeIf { it.isNotEmpty() && !it.startsWith("--") }
                ?: throw UsageException("missing value for $a")
            when (a) {
                "--json" -> {
                    if (json != null) throw UsageException("repeated switch --json")
                    json = File(value)
                }
                "--sarif" -> {
                    if (sarif != null) throw UsageException("repeated switch --sarif")
                    sarif = File(value)
                }
                "--fail-on" -> {
                    if (failOn != null) throw UsageException("repeated switch --fail-on")
                    if (value != "confirmed") throw UsageException("unsupported --fail-on value '$value' (only 'confirmed')")
                    failOn = value
                }
            }
            i += 2
        } else {
            if (input != null) throw UsageException("unexpected argument '$a'")
            input = File(a)
            i++
        }
    }
    return CliArgs(
        input = input ?: throw UsageException("missing input APK"),
        json = json ?: throw UsageException("missing --json output"),
        sarif = sarif,
        failOnConfirmed = failOn != null,
    )
}

/**
 * The path a write would actually touch: real path when it exists, otherwise
 * real parent + file name, so a symlinked parent directory cannot disguise an
 * alias of the input.
 */
private fun resolved(file: File): Path {
    val p = file.toPath()
    runCatching { return p.toRealPath() }
    val abs = p.toAbsolutePath().normalize()
    val parent = abs.parent
    if (parent != null) {
        runCatching { return parent.toRealPath().resolve(abs.fileName) }
    }
    return abs
}

/**
 * Write every payload to its own sibling temporary file and fsync it, then
 * publish them all with atomic moves. A destination that appeared during the
 * scan is refused (no REPLACE_EXISTING), and a failed publication rolls back
 * anything already moved so no half-published pair is left behind.
 */
private fun publishAll(payloads: List<Pair<File, ByteArray>>) {
    val staged = ArrayList<Pair<File, File>>(payloads.size)
    val published = ArrayList<File>(payloads.size)
    try {
        for ((target, bytes) in payloads) staged.add(stage(target, bytes) to target.absoluteFile)
        for ((tmp, target) in staged) {
            // ponytail: exists-check immediately before an atomic rename. POSIX
            // rename() always replaces, so ATOMIC_MOVE alone cannot refuse a
            // destination that appeared mid-run; this narrows the window to the
            // rename itself. Upgrade path: a directory-level lock file.
            if (target.exists()) throw FileAlreadyExistsException(target.path)
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
            published.add(target)
        }
    } catch (e: Exception) {
        for (p in published) runCatching { Files.deleteIfExists(p.toPath()) }
        throw e
    } finally {
        for ((tmp, _) in staged) if (tmp.exists()) tmp.delete()
    }
}

private fun stage(target: File, bytes: ByteArray): File {
    val abs = target.absoluteFile
    val dir = abs.parentFile ?: throw IOException("no parent directory for ${target.path}")
    if (!dir.isDirectory) throw IOException("output directory does not exist: ${dir.path}")
    val tmp = File.createTempFile(".${abs.name}.", ".tmp", dir)
    try {
        FileOutputStream(tmp).use { fos ->
            fos.write(bytes)
            fos.fd.sync()
        }
    } catch (e: Exception) {
        tmp.delete()
        throw e
    }
    return tmp
}
