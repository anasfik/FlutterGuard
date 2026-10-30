package com.flutterguard.app.scan

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/** Result of atomically storing a finished report. */
data class SavedReport(val json: File, val history: File?, val historyNote: String?)

/** Outcome of reading a stored report: absent, readable, or present but unreadable. */
sealed interface StoredReport {
    data object Missing : StoredReport

    data class Loaded(val report: Report, val file: File) : StoredReport

    data class Unreadable(val message: String) : StoredReport
}

/**
 * Report storage. Successful output only: each file is fully written to a
 * temporary sibling, fsynced, then renamed over the target. A failed scan
 * therefore never replaces the previous good report or history.
 */
object ReportFiles {

    val JSON_SUFFIX = ".json"
    val HISTORY_SUFFIX = ".hist"
    private const val INFLIGHT_SUFFIX = ".inflight"
    private const val TMP_SUFFIX = ".tmp"

    /**
     * Bounded read: a report is ≈1 MB, so anything far above that is not one of
     * ours (or is damaged) and must be rejected before `readText()` allocates it.
     */
    const val MAX_REPORT_BYTES = 64L * 1024 * 1024

    /** App-specific external storage so `adb pull` works on the signed release build. */
    fun appDir(context: Context): File =
        File(context.getExternalFilesDir(null) ?: context.filesDir, "reports").apply { mkdirs() }

    fun baseName(packageName: String): String = packageName.replace('.', '_')

    fun jsonFile(dir: File, packageName: String): File = File(dir, baseName(packageName) + JSON_SUFFIX)

    fun historyFile(dir: File, packageName: String): File = File(dir, baseName(packageName) + HISTORY_SUFFIX)

    /**
     * Reads the persisted report for [packageName]. A present-but-unreadable
     * file is reported as such, never as "no report": the UI must be able to
     * say so and offer a rescan.
     */
    fun load(dir: File, packageName: String): StoredReport {
        val file = jsonFile(dir, packageName)
        if (!file.isFile) return StoredReport.Missing
        if (file.length() > MAX_REPORT_BYTES) {
            return StoredReport.Unreadable("stored report is too large (${file.length()} bytes)")
        }
        return try {
            val report = ReportJson.decode(file.readText())
                ?: return StoredReport.Unreadable("stored report is not a FlutterGuard report")
            // `com.a_b` and `com.a.b` share one file name, and a pushed file is
            // allowed to be any report: never show another app's data here.
            if (!ownedBy(packageName, report)) {
                return StoredReport.Unreadable("stored report belongs to ${report.meta.packageName}")
            }
            StoredReport.Loaded(report, file)
        } catch (t: Throwable) {
            StoredReport.Unreadable(t.message ?: t::class.java.simpleName)
        }
    }

    /** True when a decoded report is the report of [packageName]. */
    fun ownedBy(packageName: String, report: Report): Boolean = report.meta.packageName == packageName

    /** Previous history snapshot, or null when there is none (first scan). */
    fun previousHistory(dir: File, packageName: String): String? =
        runCatching { historyFile(dir, packageName).readText() }.getOrNull()

    fun save(
        dir: File,
        packageName: String,
        json: String,
        history: String,
        /** False when the user turned scan history off: the report is still written. */
        writeHistory: Boolean = true,
    ): SavedReport {
        dir.mkdirs()
        val jsonTarget = jsonFile(dir, packageName)
        writeAtomically(jsonTarget, json)

        if (!writeHistory) {
            return SavedReport(
                jsonTarget,
                null,
                "Scan history is turned off in Settings, so no version log was written for this scan.",
            )
        }

        val histTarget = historyFile(dir, packageName)
        // One retained log per app (bounded), merged into the same atomic write.
        // A read failure must not be mistaken for "no history": never overwrite
        // an unreadable log with a single new block.
        val previous: String? = if (!histTarget.exists()) {
            null
        } else {
            try {
                histTarget.readText()
            } catch (t: Throwable) {
                return SavedReport(
                    jsonTarget,
                    null,
                    "History log left untouched: it exists but could not be read " +
                        "(${t.message ?: t::class.java.simpleName}). The report is complete.",
                )
            }
        }
        val note = runCatching { writeAtomically(histTarget, ScanLog.append(previous, history)) }
            .exceptionOrNull()
            ?.let { "History snapshot not saved (${it.message ?: it.toString()}) — report is complete." }
        return SavedReport(jsonTarget, if (note == null) histTarget else null, note)
    }

    /**
     * Marks a scan as in flight. A marker left behind after process death is
     * read back as an interrupted scan, never as a success.
     */
    fun markInflight(dir: File, packageName: String) {
        runCatching {
            dir.mkdirs()
            inflightFile(dir, packageName).writeText(packageName)
        }
    }

    fun clearInflight(dir: File, packageName: String) {
        runCatching { inflightFile(dir, packageName).delete() }
    }

    /** Package names whose scan never reached a terminal state, excluding [keep]. */
    fun interrupted(dir: File, keep: Collection<String> = emptyList()): List<String> =
        dir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(INFLIGHT_SUFFIX) }
            ?.mapNotNull { f -> runCatching { f.readText().trim() }.getOrNull()?.takeIf { it.isNotEmpty() } }
            ?.filter { it !in keep }
            ?.sorted()
            ?: emptyList()

    /**
     * Removes interrupted markers except the ones in [keep] — a scan that is still
     * running owns its marker and must keep it until it reaches a terminal state.
     */
    fun clearInterrupted(dir: File, keep: Collection<String> = emptyList()) {
        dir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(INFLIGHT_SUFFIX) }
            ?.forEach { f ->
                val pkg = runCatching { f.readText().trim() }.getOrNull()
                if (pkg == null || pkg.isEmpty() || pkg !in keep) runCatching { f.delete() }
            }
    }

    private fun inflightFile(dir: File, packageName: String): File =
        File(dir, baseName(packageName) + INFLIGHT_SUFFIX)

    /**
     * Deletes every artifact this app wrote into [dir]: reports, history logs,
     * interrupted markers and half-written temporaries. Used by the confirmed
     * "Delete all reports" action. Returns how many files were removed.
     */
    fun deleteAll(dir: File): Int =
        dir.listFiles()
            ?.filter { f ->
                f.isFile && (f.name.endsWith(JSON_SUFFIX) || f.name.endsWith(HISTORY_SUFFIX) ||
                    f.name.endsWith(INFLIGHT_SUFFIX) || f.name.endsWith(TMP_SUFFIX))
            }
            ?.count { runCatching { it.delete() }.getOrDefault(false) }
            ?: 0

    private fun writeAtomically(target: File, text: String) {
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, target.name + TMP_SUFFIX)
        try {
            FileOutputStream(tmp).use { out ->
                out.write(text.toByteArray(Charsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
            if (!tmp.renameTo(target)) throw IOException("could not replace ${target.name}")
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
    }
}
