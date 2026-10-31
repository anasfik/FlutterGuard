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

    /**
     * Legacy files above [MAX_REPORT_BYTES] are not reports this app can ever
     * load, so migration drops them instead of leaving them in shared storage.
     * Everything it *would* display is copied — deleting a readable report to
     * keep the move cheap would be data loss.
     */
    private const val MIGRATION_MAX_BYTES = MAX_REPORT_BYTES

    /**
     * Reports live in internal storage. App-specific external storage was the
     * original choice, but on API 26-28 any app holding READ_EXTERNAL_STORAGE
     * can read it (the privacy policy promises it cannot), and after a reinstall
     * that reuses the data directory the old files belong to the previous UID,
     * so saving a new report fails with EACCES. Internal storage has neither
     * problem, and exports already leave through the FileProvider.
     */
    fun appDir(context: Context): File {
        val dir = File(context.filesDir, "reports")
        dir.mkdirs()
        if (!migrated) {
            synchronized(this) {
                if (!migrated) {
                    val legacy = context.getExternalFilesDir(null)?.let { File(it, "reports") }
                    // Final only when shared storage holds nothing of ours any
                    // more: a file we could not copy, or an unmounted volume, is
                    // retried on the next call rather than stranded forever.
                    migrated = runCatching {
                        // No shared volume at all: nothing to move, and nothing
                        // that could appear later, so this is final too.
                        if (legacy == null) true else {
                            if (legacy.isDirectory) moveReports(legacy, dir)
                            legacy.listFiles().orEmpty().none { it.isFile && isOurName(it.name) }
                        }
                    }.getOrDefault(false)
                }
            }
        }
        return dir
    }

    @Volatile
    private var migrated = false

    /**
     * Moves reports written by a build that still used external storage into
     * [to]: copy first, then delete the source, so an interrupted move never
     * loses the only copy. Anything that already exists in [to] wins, and an
     * unreadable legacy directory is simply skipped (see [appDir]).
     *
     * @return how many of our files (report, history log, inflight marker) were
     * cleared from [from] — half-written temps are removed but not counted.
     */
    fun moveReports(from: File, to: File): Int {
        to.mkdirs()
        val sources = from.listFiles() ?: return 0
        var moved = 0
        for (src in sources) {
            if (!src.isFile) continue
            val name = src.name
            // A half-written temp can hold a complete report (including recovered
            // secret values) and is never one we keep: delete, never copy.
            if (name.endsWith(TMP_SUFFIX)) {
                // Housekeeping, not a report: deleted but not counted.
                runCatching { src.delete() }
                continue
            }
            if (!isOurName(name)) continue
            val target = File(to, name)
            val handled = when {
                // A complete target already exists: the new build wrote it, so the
                // legacy copy is stale. A zero-length one is a crashed copy, not a
                // report, and must be replaced by the source we still have.
                target.isFile && target.length() > 0 -> true
                // Far too large to be one of ours, and possibly holding recovered
                // secrets: drop it rather than leave it in shared storage, which
                // "Delete all reports" cannot reach.
                src.length() > MIGRATION_MAX_BYTES -> true
                copyAtomically(src, target) -> true
                else -> false
            }
            if (handled && runCatching { src.delete() }.getOrDefault(false)) moved++
        }
        return moved
    }

    /** A legacy file this module owns: a report, a history log or an inflight marker. */
    private fun isOurName(name: String): Boolean =
        name.endsWith(JSON_SUFFIX) || name.endsWith(HISTORY_SUFFIX) || name.endsWith(INFLIGHT_SUFFIX)

    /**
     * Copy through a fsynced temporary sibling, so a crash or power loss mid-copy
     * cannot leave a truncated report that the next run would treat as complete.
     */
    private fun copyAtomically(src: File, target: File): Boolean {
        val tmp = File(target.parentFile, target.name + TMP_SUFFIX)
        return runCatching {
            src.inputStream().use { ins ->
                FileOutputStream(tmp).use { out ->
                    ins.copyTo(out, 64 * 1024)
                    out.flush()
                    out.fd.sync()
                }
            }
            if (!tmp.renameTo(target)) throw IOException("could not replace ${target.name}")
            true
        }.getOrElse {
            runCatching { tmp.delete() }
            false
        }
    }

    /**
     * Storage name for one package. A scan of a *picked or shared APK* is a
     * different subject from the installed app that happens to declare the same
     * package name: it gets its own `.file` namespace so a trojaned shared APK
     * can never overwrite, or append a forged history entry to, the verdict the
     * researcher has for the app actually on the device.
     */
    fun baseName(packageName: String, fileScan: Boolean = false): String =
        packageName.replace('.', '_') + if (fileScan) ".file" else ""

    fun jsonFile(dir: File, packageName: String, fileScan: Boolean = false): File =
        File(dir, baseName(packageName, fileScan) + JSON_SUFFIX)

    fun historyFile(dir: File, packageName: String, fileScan: Boolean = false): File =
        File(dir, baseName(packageName, fileScan) + HISTORY_SUFFIX)

    /**
     * Reads the persisted report for [packageName]. A present-but-unreadable
     * file is reported as such, never as "no report": the UI must be able to
     * say so and offer a rescan.
     */
    fun load(dir: File, packageName: String, fileScan: Boolean = false): StoredReport {
        val file = jsonFile(dir, packageName, fileScan)
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
    fun previousHistory(dir: File, packageName: String, fileScan: Boolean = false): String? =
        runCatching { historyFile(dir, packageName, fileScan).readText() }.getOrNull()

    fun save(
        dir: File,
        packageName: String,
        json: String,
        history: String,
        /** False when the user turned scan history off: the report is still written. */
        writeHistory: Boolean = true,
        /** True for a picked/shared APK: stored beside, never over, the installed app's report. */
        fileScan: Boolean = false,
    ): SavedReport {
        dir.mkdirs()
        val jsonTarget = jsonFile(dir, packageName, fileScan)
        writeAtomically(jsonTarget, json)

        if (!writeHistory) {
            return SavedReport(
                jsonTarget,
                null,
                "Scan history is turned off in Settings, so no version log was written for this scan.",
            )
        }

        val histTarget = historyFile(dir, packageName, fileScan)
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
    fun markInflight(dir: File, packageName: String, fileScan: Boolean = false) {
        runCatching {
            dir.mkdirs()
            // The file name carries the namespace; the content stays the bare
            // package name, so the interrupted banner shows an app, not a file path.
            inflightFile(dir, packageName, fileScan).writeText(packageName)
        }
    }

    fun clearInflight(dir: File, packageName: String, fileScan: Boolean = false) {
        runCatching { inflightFile(dir, packageName, fileScan).delete() }
    }

    /** Package names whose scan never reached a terminal state, excluding [keep]. */
    fun interrupted(dir: File, keep: Collection<String> = emptyList()): List<String> =
        dir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(INFLIGHT_SUFFIX) }
            ?.mapNotNull { f -> runCatching { f.readText().trim() }.getOrNull()?.takeIf { it.isNotEmpty() } }
            ?.filter { it !in keep }
            // One package can own a marker in each namespace; that is one app.
            ?.distinct()
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

    internal fun inflightFile(dir: File, packageName: String, fileScan: Boolean = false): File =
        File(dir, baseName(packageName, fileScan) + INFLIGHT_SUFFIX)

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
