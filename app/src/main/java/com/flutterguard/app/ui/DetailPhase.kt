package com.flutterguard.app.ui

import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.packageName

/** Which pane the audit screen shows for one package. */
enum class DetailPane { NOT_STARTED, PROGRESS, OTHER_SCAN, REPORT, FAILURE }

/**
 * A1/A2 resolution rules, kept pure so "a scan of another app never blanks the
 * report" and "a stored report is shown before anything auto-starts" are
 * regression-tested without Compose.
 */
object DetailPhase {

    /**
     * Live job of this package, then the last success of this process, then the
     * stored report.
     *
     * [fileScan] is part of the identity, not a hint: a finished scan of a
     * picked APK and the installed app of the same package name are different
     * artefacts, and showing one under the other's name is exactly the
     * confusion the `.file` namespace exists to prevent.
     */
    fun report(
        phase: ScanPhase,
        lastSuccess: ScanPhase.Done?,
        packageName: String,
        stored: Report?,
        fileScan: Boolean = false,
    ): Report? {
        val live = (phase as? ScanPhase.Done)
            ?.takeIf { it.job.packageName == packageName && it.report.meta.fileScan == fileScan }
            ?.report
        val retained = lastSuccess
            ?.takeIf { it.job.packageName == packageName && it.report.meta.fileScan == fileScan }
            ?.report
        return live ?: retained ?: stored
    }

    fun pane(phase: ScanPhase, packageName: String, hasReport: Boolean): DetailPane = when {
        // A scan of this package is the thing to watch, report or not.
        phase is ScanPhase.Running && phase.job.packageName == packageName -> DetailPane.PROGRESS
        // Anything else must never hide an existing report.
        hasReport -> DetailPane.REPORT
        phase is ScanPhase.Running -> DetailPane.OTHER_SCAN
        // Another package's failure is not this app's failure: an app that was
        // never scanned must not show "Scan cancelled" / "Could not audit this app".
        (phase is ScanPhase.Failed || phase is ScanPhase.Cancelled) && phase.packageName == packageName ->
            DetailPane.FAILURE
        else -> DetailPane.NOT_STARTED
    }

    /** Package of a scan running elsewhere, only when a report is already on screen. */
    fun runningElsewhere(phase: ScanPhase, packageName: String, hasReport: Boolean): String? =
        (phase as? ScanPhase.Running)
            ?.takeIf { hasReport && it.job.packageName != packageName }
            ?.job?.packageName
}
