package com.flutterguard.app.ui

import com.flutterguard.app.scan.InstalledApp
import com.flutterguard.app.scan.ReportExport
import com.flutterguard.app.scan.ReportSection
import com.flutterguard.app.scan.ReportStats
import com.flutterguard.app.scan.RouteNode
import com.flutterguard.app.scan.Severity
import java.net.URI
import java.util.Locale

/**
 * Pure UI state/logic, unit-tested without Compose. Kept here so search,
 * validation, formatting and export selection behave the same across rotation
 * and are not re-implemented inside composables.
 */

/** Inventory search/filter. Normal mode supplies fixed flags; Advanced exposes them. */
data class AppFilter(
    val query: String = "",
    val flutterOnly: Boolean = true,
    val hideSystem: Boolean = true,
) {
    fun matches(app: InstalledApp): Boolean =
        (query.isBlank() || app.label.contains(query, true) || app.packageName.contains(query, true)) &&
            (!flutterOnly || app.isFlutter) &&
            (!hideSystem || !app.isSystem)
}

fun filterApps(apps: List<InstalledApp>, filter: AppFilter): List<InstalledApp> =
    apps.filter(filter::matches)

/** Search motion budget: 200–240 ms, transform/alpha only (no layout animation). */
const val SEARCH_DURATION_MS = 220

/**
 * Home search: a collapsed FAB that expands into the field.
 *
 * Retention rule: [collapse] and [back] keep [query], so a collapsed search
 * whose list is still filtered stays filtered — [cleared] is the only thing
 * that empties it. The FAB marks the collapsed-but-filtering state so the list
 * never looks mysteriously short.
 */
data class SearchUi(
    val expanded: Boolean = false,
    val query: String = "",
) {
    val filtering: Boolean get() = query.isNotBlank()

    fun expand(): SearchUi = copy(expanded = true)

    fun collapse(): SearchUi = copy(expanded = false)

    fun typed(value: String): SearchUi = copy(query = value)

    fun cleared(): SearchUi = copy(query = "")

    /** Hardware Back on Home: the open field closes first; null means the system gets the event. */
    fun back(): SearchUi? = if (expanded) collapse() else null
}

/**
 * Advanced Tools panel: one place that decides what the package row and the
 * scan-all row may do, so the inline error, the disabled action and the reason
 * in the subtitle cannot disagree with what a tap would actually run.
 */
data class AdvancedPanelState(
    /** The trailing action on the package row is enabled. */
    val scanPackageEnabled: Boolean,
    /** Inline message under the field; it is also the error-outline trigger. */
    val packageHint: String?,
    val scanAllEnabled: Boolean,
    /** "11 apps · one at a time", or why the row cannot start. */
    val scanAllSubtitle: String,
) {
    val packageInvalid: Boolean get() = packageHint != null
}

object AdvancedPanel {
    const val SYNTAX_HINT = "Enter a dotted Android package id."
}

fun advancedPanelState(
    packageInput: String,
    running: Boolean,
    queueActive: Boolean,
    appCount: Int,
    packageError: String? = null,
): AdvancedPanelState {
    val id = packageInput.trim()
    // A submit error (not installed) outranks the syntax hint: the syntax was fine.
    val hint = packageError ?: if (id.isNotEmpty() && !PackageId.isValid(id)) AdvancedPanel.SYNTAX_HINT else null
    return AdvancedPanelState(
        scanPackageEnabled = PackageId.isValid(id) && !running,
        packageHint = hint,
        scanAllEnabled = appCount > 0 && !running && !queueActive,
        scanAllSubtitle = when {
            running || queueActive -> "A scan is already running"
            appCount <= 0 -> "No Flutter apps to scan"
            else -> "$appCount app${if (appCount == 1) "" else "s"} · one at a time"
        },
    )
}

/** Android application id: dot-separated identifiers, no URL/path/wildcard syntax. */
object PackageId {
    const val MAX_LENGTH = 255
    private val regex = Regex("""^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$""")

    fun isValid(value: String): Boolean = value.length in 3..MAX_LENGTH && regex.matches(value)
}

/** External targets are only ever explicit http(s) URLs with a host. */
fun safeWebUrl(raw: String?): String? {
    val value = raw?.trim().orEmpty()
    if (value.isEmpty()) return null
    val uri = runCatching { URI(value) }.getOrNull() ?: return null
    if (uri.scheme?.lowercase() !in setOf("http", "https")) return null
    if (uri.host.isNullOrBlank()) return null
    return value
}

/** Tile/preview sizes; unknown (0/negative) renders the one placeholder, never a fake number. */
fun humanBytes(bytes: Long): String {
    if (bytes <= 0) return ReportMetadata.UNAVAILABLE
    val locale = Locale.US
    return when {
        bytes >= 1024L * 1024 * 1024 -> String.format(locale, "%.1f GB", bytes / (1024.0 * 1024 * 1024))
        bytes >= 1024L * 1024 -> String.format(locale, "%d MB", bytes / (1024L * 1024))
        bytes >= 1024 -> String.format(locale, "%d KB", bytes / 1024)
        else -> "$bytes B"
    }
}

/** Size plus splits. A split count of zero is absence, not a measurement: it is not printed. */
fun sizeAndSplits(bytes: Long, splitCount: Int): String =
    humanBytes(bytes) + if (splitCount > 0) " · $splitCount split(s)" else ""

/** One row of the severity summary. All five levels always render, in report order. */
data class SeveritySummaryRow(val label: String, val count: Int, val severity: Severity)

/**
 * Every severity level, including the ones at zero: a missing "Critical" row
 * would be indistinguishable from "critical was never checked". Low and Info
 * stay separate rows because the export and the stats keep them separate.
 */
fun severitySummary(stats: ReportStats): List<SeveritySummaryRow> = listOf(
    SeveritySummaryRow("Critical", stats.critical, Severity.CRITICAL),
    SeveritySummaryRow("High", stats.high, Severity.HIGH),
    SeveritySummaryRow("Medium", stats.medium, Severity.MEDIUM),
    SeveritySummaryRow("Low", stats.low, Severity.LOW),
    SeveritySummaryRow("Info", stats.info, Severity.INFO),
)

/**
 * What a grade letter means, in the words of the rule that produced it
 * (`gradeOf`): critical findings cap the grade at F, otherwise a weighted
 * severity score sets A–D. `F` is never rendered as a bare glyph.
 */
/**
 * Why a grade was awarded, in words.
 *
 * [hasCritical] is not inferable from the letter: `gradeOf` also returns `F` for a high weighted
 * score with no critical finding, so the legend must be told which case it is.
 */
fun gradeLegend(grade: Char, hasCritical: Boolean = false): String = when (grade.uppercaseChar()) {
    'A' -> "no critical findings, minimal weighted severity"
    'B' -> "no critical findings, low weighted severity"
    'C' -> "no critical findings, moderate weighted severity"
    'D' -> "no critical findings, high weighted severity"
    'F' -> if (hasCritical) {
        "critical findings present"
    } else {
        "no critical findings, weighted severity past the D threshold"
    }
    else -> ReportMetadata.UNAVAILABLE
}

/** One flattened route-tree row for a virtualized list. */
data class RouteRow(val node: RouteNode, val depth: Int)

/** Pre-order, depth-first, deterministic and bounded; never invents nodes/edges. */
fun flattenRoutes(nodes: List<RouteNode>, maxRows: Int = 200): List<RouteRow> {
    val out = ArrayList<RouteRow>(minOf(maxRows, 64))
    fun walk(node: RouteNode, depth: Int) {
        if (out.size >= maxRows) return
        out.add(RouteRow(node, depth))
        for (child in node.children) {
            if (out.size >= maxRows) return
            walk(child, depth + 1)
        }
    }
    for (node in nodes) {
        if (out.size >= maxRows) break
        walk(node, 0)
    }
    return out
}

/** Export dialog state. Safe by default: all sections, JSON, secrets redacted. */
data class ExportChoice(
    val json: Boolean = true,
    val sections: Set<ReportSection> = ReportExport.allSections,
    val sensitive: Boolean = false,
) {
    val extension: String get() = if (json) "json" else "md"
    val canExport: Boolean get() = sections.isNotEmpty()

    fun toggled(section: ReportSection): ExportChoice =
        copy(sections = if (section in sections) sections - section else sections + section)
}

/**
 * Export selection as plain strings, so rotating the device mid-selection keeps
 * the ticks and the sensitive opt-in instead of silently resetting them.
 */
fun ExportChoice.encode(): List<String> = listOf(
    json.toString(),
    sensitive.toString(),
    sections.joinToString(",") { it.name },
)

/**
 * Inverse of [encode]. An empty save falls back to the safe default; a save
 * whose section names are all unrecognised decodes to "nothing selected" so a
 * corrupt file can never quietly widen an export.
 */
fun exportChoiceOf(saved: List<String>): ExportChoice {
    if (saved.isEmpty()) return ExportChoice()
    val sections = saved.getOrNull(2).orEmpty()
        .split(",")
        .mapNotNull { name -> ReportSection.entries.firstOrNull { it.name == name } }
        .toSet()
    return ExportChoice(
        json = saved.getOrNull(0)?.toBooleanStrictOrNull() ?: true,
        sections = sections,
        sensitive = saved.getOrNull(1)?.toBooleanStrictOrNull() == true,
    )
}

/**
 * Tile metadata split into deliberate lines: version/code, then the SDK range
 * on its own line, then size (and splits only when present). The SDK line is
 * a unit, so a narrow tile can never break between "SDK" and the numbers, and
 * a long version name ellipsizes only its own line instead of eating the SDK.
 * An unrecovered value says "not available"; it is never a bare `?`.
 */
fun tileMetaLines(app: InstalledApp): List<String> {
    val system = if (app.isSystem) "system · " else ""
    val version = app.versionName?.let { "v$it (${app.versionCode})" } ?: ReportMetadata.UNAVAILABLE
    val sdk = if (app.minSdk != null && app.targetSdk != null) {
        "SDK ${app.minSdk}→${app.targetSdk}"
    } else {
        "SDK ${ReportMetadata.UNAVAILABLE}"
    }
    return listOf(
        "$system" + version,
        sdk,
        sizeAndSplits(app.sizeBytes, app.splitCount),
    )
}

/** Dependency list filtering; blank query keeps the recovered order. */
fun filterDependencies(deps: List<String>, query: String): List<String> =
    if (query.isBlank()) deps else deps.filter { it.contains(query, true) }

/** Visible page size for the dependency list; "Show more" grows it explicitly. */
const val DEPENDENCY_PAGE = 60

fun dependencyPage(filtered: List<String>, limit: Int): List<String> =
    if (limit <= 0) emptyList() else filtered.take(limit)
