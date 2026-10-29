package com.flutterguard.app.ui

import com.flutterguard.app.scan.Report
import java.util.Locale

/** One real, report-derived metadata row. Missing values say "not available". */
data class MetadataRow(val label: String, val value: String)

/**
 * Decompile/extraction metadata for an opened report. Every value comes from
 * the stored scan path; nothing is inferred, estimated or copied from a
 * previous version. Absent data renders as "not available".
 */
object ReportMetadata {

    const val UNAVAILABLE = "not available"

    fun rows(report: Report): List<MetadataRow> {
        val framework = report.framework
        val parts = report.meta.splitCount + 1
        return listOf(
            MetadataRow("Flutter check", flutterCheck(report)),
            MetadataRow("Flutter engine", framework.engineVersion?.take(80) ?: UNAVAILABLE),
            MetadataRow("Dart runtime", framework.dartVersion ?: UNAVAILABLE),
            MetadataRow("Build mode", framework.buildMode ?: UNAVAILABLE),
            MetadataRow("Obfuscated", framework.obfuscated?.toString() ?: UNAVAILABLE),
            MetadataRow(
                "APK parts",
                if (report.meta.splitCount > 0) "$parts parts (${report.meta.splitCount} split)"
                else "$parts part (no splits)",
            ),
            MetadataRow("Kernel blob", framework.kernelBlobBytes?.let { humanBytes(it) } ?: UNAVAILABLE),
            MetadataRow("Dart snapshots", framework.snapshotBytes?.takeIf { it > 0 }?.let { humanBytes(it) } ?: UNAVAILABLE),
            MetadataRow("APK entries in report", report.artifacts.size.toString()),
            MetadataRow("ABIs", report.meta.abis.joinToString().ifEmpty { UNAVAILABLE }),
            MetadataRow("Strings scanned", count(report.stats.stringsScanned)),
            MetadataRow(
                "Scan time",
                if (report.stats.durationMs > 0) "${count(report.stats.durationMs)} ms" else UNAVAILABLE,
            ),
            MetadataRow(
                "Scanned at",
                if (report.generatedAt > 0) formatTimestamp(report.generatedAt) else UNAVAILABLE,
            ),
        )
    }

    /** The signals that justified deep analysis, using only recovered evidence. */
    fun flutterCheck(report: Report): String {
        val framework = report.framework
        if (!framework.isFlutter) {
            val others = framework.otherFrameworks.joinToString()
            return if (others.isBlank()) "not a Flutter app" else "not a Flutter app ($others)"
        }
        val signals = buildList {
            if (framework.kernelBlobBytes != null) add("kernel_blob.bin readable Dart")
            if (!framework.libappMissing) add("libapp.so AOT snapshot")
            if (framework.engineDebug) add("debug engine")
            if (framework.dartDeps.isNotEmpty()) add("${framework.dartDeps.size} Dart package names")
        }
        return if (signals.isEmpty()) "Flutter artifacts present" else signals.joinToString(" · ")
    }

    private fun count(value: Long): String = String.format(Locale.US, "%,d", value)
}
