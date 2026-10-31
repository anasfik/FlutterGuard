package com.flutterguard.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.flutterguard.app.scan.ApkSource
import com.flutterguard.app.scan.displayName
import com.flutterguard.app.scan.ArtifactEntry
import com.flutterguard.app.scan.DeepLink
import com.flutterguard.app.scan.Evidence
import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.InstalledApp
import com.flutterguard.app.scan.PubPackage
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportExport
import com.flutterguard.app.scan.ReportFiles
import com.flutterguard.app.scan.ReportSection
import com.flutterguard.app.scan.RouteTree
import com.flutterguard.app.scan.ScanLog
import com.flutterguard.app.scan.StoredReport
import com.flutterguard.app.scan.ScanLogEntry
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.fileScan
import com.flutterguard.app.scan.packageName
import com.flutterguard.app.scan.ScanStartPolicy
import com.flutterguard.app.scan.ScanStore
import com.flutterguard.app.settings.Settings
import com.flutterguard.app.scan.TextPreview
import com.flutterguard.app.scan.secretValues
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The Details tabs, in order. Also the default route section. */
internal val DetailsSections = listOf("Overview", "Findings", "Explore")

/**
 * Details = progressive research workspace over one last-good report.
 * A failed rescan keeps the previous report visible; evidence is masked and
 * reveal state is scoped to this package visit and never saved.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun DetailsScreen(
    app: InstalledApp?,
    packageName: String,
    /** True for a picked/shared APK, whose report has its own on-disk namespace. */
    fileScan: Boolean,
    phase: ScanPhase,
    lastSuccess: ScanPhase.Done?,
    section: String,
    onSection: (String) -> Unit,
    onBack: () -> Unit,
    onSeeAll: (SeeAllTarget, String) -> Unit,
    onRescan: () -> Unit,
    onCancel: () -> Unit,
) {
    val mine = phase.packageName == packageName && phase.fileScan == fileScan
    // Same package, same namespace: a file scan's report and diff must never be
    // rendered as the installed app's (and the reverse).
    val done = (phase as? ScanPhase.Done)?.takeIf { mine && it.report.meta.fileScan == fileScan }
    val retained = lastSuccess?.takeIf {
        it.job.packageName == packageName && it.report.meta.fileScan == fileScan
    }

    // A1: a finished report is read back from disk, so navigation and process
    // death do not lose it. The live job and this process's last success are
    // still the fast path (DetailPhase picks the order).
    val stored = rememberStoredReport(packageName, fileScan)
    val storedReport = (stored as? StoredReport.Loaded)?.report
    val storedFailure = (stored as? StoredReport.Unreadable)?.message

    val report = DetailPhase.report(phase, lastSuccess, packageName, storedReport, fileScan)
    val settings by Settings.state.collectAsState()
    // A prompt only: nothing scans in the background. Off by default, so an
    // untouched install behaves exactly as before.
    val updatePrompt = if (report != null && app != null && settings.rescanPrompt &&
        !report.meta.fileScan && report.meta.versionCode != app.versionCode
    ) {
        "The installed app is ${app.versionName ?: "?"} (${app.versionCode}); this report was taken from " +
            "${report.meta.versionName ?: "?"} (${report.meta.versionCode}). Findings may describe the older build."
    } else null
    val diff = done?.diff ?: retained?.diff.orEmpty()
    val failure = (phase as? ScanPhase.Failed)?.takeIf { mine }
    val cancelled = (phase as? ScanPhase.Cancelled)?.takeIf { mine }
    var exportOpen by rememberSaveable { mutableStateOf(false) }

    val busyElsewhere = phase is ScanPhase.Running && phase.packageName != packageName
    LaunchedEffect(packageName, fileScan, busyElsewhere, report != null, stored != null) {
        // Opening this workspace starts a scan once, only when there is nothing
        // to show, nothing else is running and the scan-all queue does not own
        // the single execution slot. A file route is never auto-started: its
        // rescan re-opens the document picker, which must only ever be a
        // deliberate tap.
        val queueActive = ScanQueueRunner.state.value.active
        if (!fileScan && app != null && stored != null &&
            ScanStartPolicy.shouldAutoStart(
                ScanStore.state.value.phase,
                packageName,
                queueActive = queueActive,
                hasReport = report != null,
                fileScan = fileScan,
            )
        ) {
            onRescan()
        }
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = onBack, modifier = Modifier.size(48.dp)) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back to app list")
                        }
                    },
                    title = {
                        Column {
                            Text(
                                app?.label ?: packageName,
                                style = MaterialTheme.typography.titleMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                packageName,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    },
                    actions = {
                        if (report != null) {
                            IconButton(onClick = { exportOpen = true }, modifier = Modifier.size(48.dp)) {
                                Icon(Icons.Default.Share, contentDescription = "Export report")
                            }
                        }
                        if (phase !is ScanPhase.Running) {
                            IconButton(onClick = onRescan, modifier = Modifier.size(48.dp)) {
                                Icon(Icons.Default.Refresh, contentDescription = "Scan")
                            }
                        }
                    },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            // A2: a scan of another package is a banner, never a blank page.
            when (DetailPhase.pane(phase, packageName, hasReport = report != null, fileScan = fileScan)) {
                DetailPane.PROGRESS -> ScanProgressPane(phase as ScanPhase.Running, onCancel)
                DetailPane.OTHER_SCAN -> OtherScanPane((phase as ScanPhase.Running).job.packageName, onCancel)
                DetailPane.FAILURE -> FailurePane(
                    title = when {
                        failure?.interrupted == true -> "Scan interrupted"
                        failure != null -> "Could not audit this app"
                        else -> "Scan cancelled"
                    },
                    message = failure?.message
                        ?: storedFailure?.let { "Stored report could not be read: $it" }
                        ?: "You cancelled this scan. Any previous report was left untouched.",
                    retained = null,
                    onRetry = onRescan,
                )
                DetailPane.NOT_STARTED -> NotStartedPane(packageName, onRescan)
                DetailPane.REPORT -> ReportWorkspace(
                    report = report!!,
                    diff = diff,
                    historyNote = done?.historyNote ?: retained?.historyNote,
                    section = section,
                    onSection = onSection,
                    onSeeAll = onSeeAll,
                    failureMessage = failure?.message ?: cancelled?.let { "Cancelled — showing the last successful report." },
                    storedNote = storedFailure,
                    runningElsewhere = DetailPhase.runningElsewhere(
                        phase, packageName, hasReport = true, fileScan = fileScan,
                    ),
                    updatePrompt = updatePrompt,
                    onRescan = onRescan,
                )
            }
        }
    }

    if (exportOpen && report != null) {
        ExportDialog(report = report, onDismiss = { exportOpen = false })
    }
}

@Composable
private fun ReportWorkspace(
    report: Report,
    diff: List<String>,
    historyNote: String?,
    section: String,
    onSection: (String) -> Unit,
    onSeeAll: (SeeAllTarget, String) -> Unit,
    failureMessage: String?,
    storedNote: String?,
    runningElsewhere: String?,
    updatePrompt: String?,
    onRescan: () -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        ChipRow(Modifier.padding(horizontal = Gutter, vertical = Space.s)) {
            DetailsSections.forEach { name ->
                WorkbenchChip(selected = section == name, onClick = { onSection(name) }, label = name)
            }
        }
        if (runningElsewhere != null) {
            Banner(
                "Another app is being scanned",
                "$runningElsewhere is running. This report stays readable; scan again when it finishes.",
            )
        }
        if (report.meta.fileScan) {
            Banner(
                "File scan",
                "This report was produced from an APK you picked or shared. The package name comes from its " +
                    "manifest, not from an installed app; findings, exports and history work the same way. " +
                    "Open the live APK browser only for installed apps.",
            )
        }
        if (updatePrompt != null) {
            Banner("App updated since this report", updatePrompt)
            Row(Modifier.padding(horizontal = Gutter)) { TextAction("Re-scan now", onRescan) }
        }
        if (storedNote != null) {
            Banner("Stored report unreadable", "$storedNote It was left untouched; scan to write a new one.", error = true)
        }
        if (failureMessage != null) {
            Banner("Latest scan did not finish", "$failureMessage The report below is the last successful one and was not overwritten.", error = true)
        }
        if (historyNote != null) {
            Banner("History not updated", historyNote)
        }
        // One saved list position per section, not one per composition: a tab
        // flip keeps the scroll offset it left, and Back from a See-all list
        // restores it from the route's saved state.
        val overviewList = rememberSaveable("overview", saver = LazyListState.Saver) { LazyListState() }
        val findingsList = rememberSaveable("findings", saver = LazyListState.Saver) { LazyListState() }
        val exploreList = rememberSaveable("explore", saver = LazyListState.Saver) { LazyListState() }
        when (section) {
            "Findings" -> FindingsSection(report, findingsList)
            "Explore" -> ExploreSection(report, onSeeAll, exploreList)
            else -> OverviewSection(report, diff, onSeeAll, overviewList)
        }
    }
}

// ------------------------------------------------------------------ overview

@Composable
private fun OverviewSection(
    report: Report,
    diff: List<String>,
    onSeeAll: (SeeAllTarget, String) -> Unit,
    listState: LazyListState,
) {
    val packageName = report.meta.packageName
    val log = rememberScanLog(packageName, report.generatedAt, report.meta.fileScan)
    val settings by Settings.state.collectAsState()

    val permissionWindow = preview(report.permissions)
    val linkWindow = preview(report.deepLinks)

    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = Gutter, end = Gutter, top = Space.l, bottom = Space.xxl),
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        item { GradeCard(report) }
        if (diff.isNotEmpty()) item { DiffCard(diff) }
        item {
            SectionCard("APK artifact") {
                InfoLine("Version", apkVersion(report))
                InfoLine("SDK", sdkRange(report))
                InfoLine("Size / splits", sizeAndSplits(report.meta.sizeBytes, report.meta.splitCount))
                InfoLine("ABIs", report.meta.abis.joinToString().ifEmpty { "none" })
                InfoLine("Installer", report.meta.installer ?: ReportMetadata.UNAVAILABLE, mono = false)
                // A fingerprint is evidence: shown in full and copyable, never clipped to 24 chars.
                if (report.meta.baseSha256.isNotEmpty()) {
                    InfoLine("base.apk SHA-256", report.meta.baseSha256, copyable = true)
                }
                report.meta.nativeLibs.take(6).forEach { lib ->
                    InfoLine(lib.name, humanBytes(lib.sizeBytes))
                }
            }
        }
        item { ExtractionMetadataCard(report) }
        item {
            SectionCard("Framework evidence") {
                if (report.framework.isFlutter) {
                    InfoLine("Flutter", "yes — ${report.framework.buildMode ?: ReportMetadata.UNAVAILABLE}")
                    InfoLine("Dart", report.framework.dartVersion ?: ReportMetadata.UNAVAILABLE)
                    InfoLine("Obfuscated", report.framework.obfuscated?.toString() ?: ReportMetadata.UNAVAILABLE)
                    report.framework.kernelBlobBytes?.let { InfoLine("kernel_blob.bin", "${humanBytes(it)} — readable Dart") }
                    report.framework.snapshotBytes?.takeIf { it > 0 }?.let { InfoLine("JIT snapshots", humanBytes(it)) }
                    if (report.framework.engineDebug) InfoLine("Engine", "debug build")
                    if (report.framework.dartDeps.isNotEmpty()) {
                        InfoLine("Dart deps", "${report.framework.dartDeps.size} recovered (see Explore)")
                    }
                    report.framework.engineVersion?.let { InfoLine("Engine", it.take(80)) }
                } else {
                    InfoLine("Flutter", "no", mono = false)
                    if (report.framework.otherFrameworks.isNotEmpty()) {
                        InfoLine("Detected", report.framework.otherFrameworks.joinToString(), mono = false)
                    }
                }
            }
        }
        item {
            SectionCard("Signing") {
                InfoLine("Schemes", report.signing.schemes.joinToString(" / ").ifEmpty { "none" })
                InfoLine("Signer", report.signing.signerSubject ?: ReportMetadata.UNAVAILABLE)
                val fingerprint = report.signing.sha256Fingerprint
                if (fingerprint != null) {
                    // Full value + copy: a signer certificate is compared, not glanced at.
                    InfoLine("SHA-256", fingerprint, copyable = true)
                } else {
                    InfoLine("SHA-256", ReportMetadata.UNAVAILABLE)
                }
                if (report.signing.debugCert) InfoLine("DEBUG CERT", "signed with the Android debug certificate")
                InfoLine("Valid until", report.signing.validTo ?: ReportMetadata.UNAVAILABLE)
                report.signing.notes.forEach { note ->
                    Text(note, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        item {
            SectionCard("Permissions (${report.permissions.size})") {
                permissionWindow.visible.forEach { p ->
                    Text(
                        "${p.name.substringAfterLast('.')} [${p.protection}]",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                    if (p.description.isNotBlank()) {
                        Text(p.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                SectionFooter(
                    countLabel = permissionWindow.countLabel("permissions"),
                    onSeeAll = if (permissionWindow.isCapped) {
                        { onSeeAll(SeeAllTarget.PERMISSIONS, "") }
                    } else null,
                )
            }
        }
        if (report.deepLinks.isNotEmpty()) {
            item {
                SectionCard("Deep links (${report.deepLinks.size})") {
                    linkWindow.visible.forEach { DeepLinkLine(it) }
                    SectionFooter(
                        countLabel = linkWindow.countLabel("links"),
                        onSeeAll = if (linkWindow.isCapped) {
                            { onSeeAll(SeeAllTarget.DEEP_LINKS, "") }
                        } else null,
                    )
                }
            }
        }
        item {
            ScanLogCard(
                log = log,
                historyEnabled = settings.keepHistory,
                onSeeAll = if (log.size > SCAN_LOG_PREVIEW) {
                    { onSeeAll(SeeAllTarget.SCAN_LOG, "") }
                } else null,
            )
        }
    }
}

/** Visible scan-log entries inline; the See-all route lists the retained history. */
private const val SCAN_LOG_PREVIEW = 2

/**
 * Decompile/check metadata read straight from the report: engine, build mode,
 * part counts, timings and the Flutter check that justified deep analysis.
 * Values that were not recovered read "not available" — never a guess.
 */
@Composable
private fun ExtractionMetadataCard(report: Report) {
    SectionCard("Extraction & check metadata") {
        ReportMetadata.rows(report).forEach { row ->
            InfoLine(row.label, row.value)
        }
    }
}

/** Versioned scan log retained in the existing `.hist` file; opening it never rescans. */
@Composable
private fun ScanLogCard(log: List<ScanLogEntry>, historyEnabled: Boolean, onSeeAll: (() -> Unit)?) {
    SectionCard("Versioned scan log (${log.size})") {
        if (!historyEnabled) {
            Text(
                "Scan history is turned off in Settings. New scans write a report but no version log, so update-to-update changes cannot be compared.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SectionCard
        }
        if (log.isEmpty()) {
            Text(
                "No retained scan log for this app yet. Each finished scan appends one stamped entry.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SectionCard
        }
        val newestFirst = log.indices.reversed().take(SCAN_LOG_PREVIEW)
        newestFirst.forEach { index ->
            val entry = log[index]
            Column(Modifier.padding(vertical = 4.dp)) {
                Text(
                    "v${entry.versionName} (${entry.versionCode}) · grade ${entry.grade ?: ReportMetadata.UNAVAILABLE}",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    if (entry.stampedAtMs > 0) formatTimestamp(entry.stampedAtMs) else ReportMetadata.UNAVAILABLE,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val diff = ScanLog.diffForPreviousVersion(log, index)
                if (diff.isNotEmpty()) {
                    Text("vs previous v${entry.versionName}", style = MaterialTheme.typography.labelSmall)
                    diff.take(6).forEach { line ->
                        Text(
                            line,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = themeDiffColor(line),
                        )
                    }
                    if (diff.size > 6) Text("… ${diff.size - 6} more", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
        SectionFooter(
            countLabel = if (onSeeAll != null) "Showing $SCAN_LOG_PREVIEW of ${log.size} scans" else "${log.size} scans",
            onSeeAll = onSeeAll,
        )
        Text(
            "History is read from disk; opening it does not start a scan.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun themeDiffColor(line: String): Color = when (line.firstOrNull()) {
    '+' -> MaterialTheme.colorScheme.error
    '-' -> MaterialTheme.colorScheme.primary
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}

/** Reads the retained log on IO; refreshing the report or package reloads it. */
@Composable
internal fun rememberScanLog(
    packageName: String,
    generatedAt: Long,
    /** True for a picked/shared APK: its log is not the installed app's log. */
    fileScan: Boolean = false,
): List<ScanLogEntry> {
    val context = LocalContext.current
    var entries by remember(packageName, fileScan) { mutableStateOf<List<ScanLogEntry>>(emptyList()) }
    LaunchedEffect(packageName, fileScan, generatedAt) {
        entries = withContext(Dispatchers.IO) {
            runCatching {
                val file = ReportFiles.historyFile(ReportFiles.appDir(context), packageName, fileScan)
                ScanLog.decode(if (file.isFile) file.readText() else null)
            }.getOrDefault(emptyList())
        }
    }
    return entries
}

@Composable
private fun GradeCard(report: Report) {
    val grade = report.grade
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(Space.l)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Neutral, not the accent: an F is the worst outcome on this
                // screen and must never be the most affirmative colour on it.
                Surface(
                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.semantics { contentDescription = "Grade $grade" },
                ) {
                    Text(
                        grade.toString(),
                        style = MaterialTheme.typography.displaySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(horizontal = Space.l, vertical = Space.s),
                    )
                }
                Spacer(Modifier.width(Space.l))
                Column(verticalArrangement = Arrangement.spacedBy(Space.xs)) {
                    severitySummary(report.stats).forEach { row ->
                        StatLine(row.label, row.count, row.severity)
                    }
                    Text(
                        "Grade $grade — ${gradeLegend(grade, report.stats.critical > 0)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        "${report.stats.stringsScanned} strings · ${report.stats.durationMs / 1000}s",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/** Version as the package manager reported it, or the one "unknown" placeholder. */
private fun apkVersion(report: Report): String =
    report.meta.versionName?.let { "$it (${report.meta.versionCode})" } ?: ReportMetadata.UNAVAILABLE

/** Both SDK numbers or nothing: a half range is not a measurement. */
private fun sdkRange(report: Report): String {
    val min = report.meta.minSdk
    val target = report.meta.targetSdk
    return if (min != null && target != null) "min $min → target $target" else ReportMetadata.UNAVAILABLE
}

/** Always drawn, zero included: "Critical 0" is a result, a missing row is not. */
@Composable
private fun StatLine(label: String, count: Int, severity: com.flutterguard.app.scan.Severity) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        SeverityDot(severity)
        Spacer(Modifier.width(Space.s))
        Text("$label  $count", style = MaterialTheme.typography.titleSmall)
    }
}

@Composable
private fun DiffCard(diff: List<String>) {
    SectionCard("Changes since last scan") {
        diff.forEach { line ->
            Text(
                line,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = themeDiffColor(line),
            )
        }
    }
}

@Composable
private fun DeepLinkLine(link: DeepLink) {
    Text(
        "${link.scheme}://${link.host ?: "*"} → ${link.component}${if (link.autoVerify) " (autoVerify)" else ""}",
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace,
    )
}

// ------------------------------------------------------------------ findings

@Composable
private fun FindingsSection(report: Report, listState: LazyListState) {
    val secrets = report.secretValues()
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = Gutter, end = Gutter, top = Space.l, bottom = Space.xxl),
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        item {
            Text(
                "Deterministic static matches with provenance. A match is evidence, not confirmed exploitability.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (report.findings.isEmpty()) {
            item { EmptyState("No findings", "The rules found nothing matching in the readable artifacts.") }
        } else {
            items(report.findings.sortedBy { it.severity }) { finding ->
                FindingCard(finding, report.meta.packageName, secrets)
            }
        }
    }
}

@Composable
private fun FindingCard(finding: Finding, packageName: String, secrets: List<String>) {
    var expanded by remember(packageName, finding.id) { mutableStateOf(false) }
    var revealed by remember(packageName, finding.id) { mutableStateOf(setOf<Int>()) }
    Card(
        Modifier.fillMaxWidth().clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(Space.l)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityDot(finding.severity)
                Spacer(Modifier.width(Space.s))
                Text(finding.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                Icon(
                    if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = if (expanded) "Collapse finding" else "Expand finding",
                )
            }
            // Severity is a label first: the word, in a scheme-derived pair, so
            // CRITICAL (filled) and HIGH (outlined) differ by more than a dot hue.
            val style = severityStyle(finding.severity)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.s)) {
                Surface(
                    color = style.container,
                    contentColor = style.content,
                    shape = MaterialTheme.shapes.extraSmall,
                    border = style.stroke?.let { BorderStroke(1.dp, it) },
                ) {
                    Text(
                        finding.severity.name,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = Space.s, vertical = Space.xs),
                    )
                }
                Text(
                    "pattern ${finding.id}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                Text(finding.detail, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                finding.evidence.take(3).forEachIndexed { index, evidence ->
                    EvidenceRow(
                        evidence = evidence,
                        revealed = index in revealed,
                        hasValue = evidence.value != null && evidence.value != evidence.snippet,
                        onToggleReveal = {
                            revealed = if (index in revealed) revealed - index else revealed + index
                        },
                    )
                }
                if (finding.remediation.isNotBlank()) {
                    Spacer(Modifier.height(Space.s))
                    Row(verticalAlignment = Alignment.Top) {
                        Icon(Icons.Default.Info, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(Space.s))
                        Text(finding.remediation, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                if (finding.masvs.isNotEmpty()) {
                    Text(
                        finding.masvs.joinToString(" "),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = Space.xs),
                    )
                }
            }
        }
    }
}

@Composable
private fun EvidenceRow(
    evidence: Evidence,
    revealed: Boolean,
    hasValue: Boolean,
    onToggleReveal: () -> Unit,
) {
    val context = LocalContext.current
    val settings by Settings.state.collectAsState()
    val revealAllowed = settings.canRevealSecrets
    // B2: a revealed value must not be screen-capturable while visible.
    SecureScreen(active = revealed && hasValue && revealAllowed)
    Column(Modifier.padding(top = Space.s)) {
        Text(
            "${evidence.source}@${evidence.offset}",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            evidence.snippet,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
        )
        if (hasValue) {
            if (revealed && revealAllowed) {
                Banner(
                    "Revealed for this visit only",
                    "Full matches stay in memory, are never logged, and reset when you change packages.",
                    error = true,
                )
                SelectionContainer {
                    Text(
                        evidence.value.orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(Space.s)) {
                    TextAction("Copy", onClick = {
                        evidence.value?.let { copyText(context, it, "Copied", sensitive = true) }
                    })
                    TextAction("Hide value", onToggleReveal)
                }
            } else {
                if (revealAllowed) {
                    TextAction("Reveal value", onToggleReveal)
                } else {
                    Text(
                        "Reveal is turned off in Settings → Secrets and exports.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else if (evidence.snippet.contains("chars hidden")) {
            // A report loaded from disk has no raw value: it only lived in the
            // scanning process. Say so instead of leaving a dead masked row.
            Text(
                "Rescan this app to reveal values from this report.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ------------------------------------------------------------------ explore

/**
 * Explore groups recovered strings by what they really are. Every long section
 * renders a bounded preview plus an explicit count and a See-all route; the
 * lists themselves are never rendered wholesale inside this scroll.
 *
 * See-all is a route of its own ([Destination.Section]), so the filter that was
 * active here travels with it and the routed list describes the same set.
 */
@Composable
private fun ExploreSection(
    report: Report,
    onSeeAll: (SeeAllTarget, String) -> Unit,
    listState: LazyListState,
) {
    val context = LocalContext.current
    val secrets = remember(report) { report.secretValues() }
    val groups = remember(report.routes, report.dartSources) {
        RecoveredPaths.split(report.routes, report.dartSources)
    }
    val routeRows = remember(groups.routes) { flattenRoutes(RouteTree.build(groups.routes), maxRows = 200) }
    var query by rememberSaveable(report.meta.packageName) { mutableStateOf("") }
    var depQuery by rememberSaveable(report.meta.packageName) { mutableStateOf("") }
    var previewEntry by remember(report.meta.packageName) { mutableStateOf<ArtifactEntry?>(null) }

    // A file scan has no installed app to read: resolving the package name through
    // PackageManager would show a *different* artifact than the report describes.
    val artifacts = rememberArtifactSource(report.meta.packageName, enabled = !report.meta.fileScan)
    val source = artifacts.source
    val entries = artifacts.entries

    val hosts = remember(report.hosts) { report.hosts.filter { it.classification != "unclassified" } }
    val endpoints = remember(hosts) { Endpoints.rows(hosts) }
    val deps = report.framework.dartDeps
    val filteredDeps = remember(deps, depQuery) { filterDependencies(deps, depQuery) }
    val filteredArtifacts = remember(entries, query, secrets) {
        val list = entries.orEmpty()
        if (query.isBlank()) list else list.filter { it.displayName(secrets).contains(query, true) }
    }

    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = Gutter, end = Gutter, top = Space.l, bottom = Space.xxl),
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        // ---- endpoints
        item {
            ExploreHeader(
                "Endpoints (${endpoints.size})",
                "Candidate hosts recovered from strings. Open uses exactly the URL shown; unverified strings never open.",
            )
        }
        val hostWindow = preview(endpoints)
        if (endpoints.isEmpty()) {
            item { Text("No host candidates recovered.", style = MaterialTheme.typography.bodySmall) }
        } else {
            items(hostWindow.visible, key = { "host-" + it.host.host }) { endpoint ->
                EndpointRowView(endpoint) { endpoint.url?.let { openWebLink(context, it) } }
            }
            item {
                SectionFooter(hostWindow.countLabel("hosts"), if (hostWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.HOSTS, "") }
                } else null)
            }
        }

        // ---- candidate routes (build paths are split out below)
        item { ExploreHeader("Candidate routes (${groups.routes.size})", "Prefix hierarchy from recovered route strings only. This is not a navigation graph.") }
        val routeWindow = preview(routeRows)
        if (routeRows.isEmpty()) {
            item { Text("No route candidates recovered.", style = MaterialTheme.typography.bodySmall) }
        } else {
            items(routeWindow.visible, key = { "route-" + it.node.path }) { row -> RouteRowView(row) }
            item {
                SectionFooter(routeWindow.countLabel("routes"), if (routeWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.ROUTES, "") }
                } else null)
            }
        }

        // ---- Dart source paths
        item {
            ExploreHeader(
                "Dart source paths (${groups.dartSources.size})",
                "Paths recovered from a debug/JIT kernel. They are not readable files and not a substitute for the artifact browser.",
            )
        }
        val dartWindow = preview(groups.dartSources)
        if (groups.dartSources.isEmpty()) {
            item { Text("No Dart source paths recovered (release builds usually omit them).", style = MaterialTheme.typography.bodySmall) }
        } else {
            items(dartWindow.visible, key = { "dart-" + it }) { path ->
                CompactPathRow(path) { copyText(context, path, "Copied") }
            }
            item {
                SectionFooter(dartWindow.countLabel("paths"), if (dartWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.DART_SOURCES, "") }
                } else null)
            }
        }

        // ---- embedded build paths (Cargo/CI/Flutter SDK strings, never routes)
        item {
            ExploreHeader(
                "Embedded build paths (${groups.buildPaths.size})",
                "Absolute build-machine paths recovered from native/build strings. Not routes and not Dart source; they describe where the app was built.",
            )
        }
        val buildWindow = preview(groups.buildPaths)
        if (groups.buildPaths.isEmpty()) {
            item { Text("No embedded build paths recovered.", style = MaterialTheme.typography.bodySmall) }
        } else {
            items(buildWindow.visible, key = { "build-" + it }) { path ->
                CompactPathRow(path) { copyText(context, path, "Copied") }
            }
            item {
                SectionFooter(buildWindow.countLabel("paths"), if (buildWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.BUILD_PATHS, "") }
                } else null)
            }
        }

        // ---- unclassified path-shaped strings
        item {
            ExploreHeader(
                "Unclassified paths (${groups.unclassified.size})",
                "Path-shaped strings that are neither routes nor a known build root. Never treated as navigation evidence.",
            )
        }
        val unclassifiedWindow = preview(groups.unclassified)
        if (groups.unclassified.isEmpty()) {
            item { Text("No unclassified path-shaped strings.", style = MaterialTheme.typography.bodySmall) }
        } else {
            items(unclassifiedWindow.visible, key = { "unclassified-" + it }) { path ->
                CompactPathRow(path) { copyText(context, path, "Copied") }
            }
            item {
                SectionFooter(unclassifiedWindow.countLabel("paths"), if (unclassifiedWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.UNCLASSIFIED_PATHS, "") }
                } else null)
            }
        }

        // ---- dependencies
        item { ExploreHeader("Dependencies (${deps.size})", "Candidate pub.dev package names. Version and license stay unknown unless recovered.") }
        item {
            OutlinedTextField(
                value = depQuery,
                onValueChange = { depQuery = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Filter dependencies") },
            )
        }
        if (deps.isEmpty()) {
            item { Text("No Dart package names recovered.", style = MaterialTheme.typography.bodySmall) }
        } else if (filteredDeps.isEmpty()) {
            item {
                EmptyState(
                    title = "No dependency matches",
                    detail = "No recovered package name contains \"$depQuery\".",
                    actionLabel = "Clear filter",
                    onAction = { depQuery = "" },
                )
            }
        } else {
            val depWindow = preview(filteredDeps)
            items(depWindow.visible, key = { "dep-" + it }) { dep ->
                val info = PubPackage.describe(dep, provenance = "recovered string")
                DependencyRow(name = info.name, url = info.url, version = info.version, license = info.license) {
                    info.url?.let { openWebLink(context, it) }
                }
            }
            item {
                SectionFooter(depWindow.countLabel("dependencies"), if (depWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.DEPENDENCIES, depQuery) }
                } else null)
            }
        }

        // ---- platform channels
        item { ExploreHeader("Platform channels (${report.channels.size})", "Names recovered from the artifact; kind is a heuristic label.") }
        val channelWindow = preview(report.channels)
        if (report.channels.isEmpty()) {
            item { Text("No platform channel names recovered.", style = MaterialTheme.typography.bodySmall) }
        } else {
            items(channelWindow.visible, key = { "chan-" + it.name }) { channel ->
                Row(Modifier.fillMaxWidth().padding(vertical = Space.xs)) {
                    Text(channel.name, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
                    Text(channel.kind, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            item {
                SectionFooter(channelWindow.countLabel("channels"), if (channelWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.CHANNELS, "") }
                } else null)
            }
        }

        // ---- third-party SDK markers
        item { ExploreHeader("Third-party services (${report.thirdParty.size})", "SDK markers found in strings.") }
        val markerWindow = preview(report.thirdParty)
        if (report.thirdParty.isEmpty()) {
            item { Text("No third-party SDK markers recovered.", style = MaterialTheme.typography.bodySmall) }
        } else {
            items(markerWindow.visible, key = { "third-" + it.service }) { hit ->
                Text("${hit.service}: ${hit.evidence.joinToString(", ")}", style = MaterialTheme.typography.bodySmall)
            }
            item {
                SectionFooter(markerWindow.countLabel("services"), if (markerWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.THIRD_PARTY, "") }
                } else null)
            }
        }

        // ---- artifact browser
        // No fabricated zero while the parts are still opening.
        val artifactCount = entries?.size?.toString() ?: ReportMetadata.UNAVAILABLE
        item { ExploreHeader("APK artifacts ($artifactCount)", "Part-aware typed entries. Names are masked; open only by explicit tap.") }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Filter artifacts") },
            )
        }
        when {
            artifacts.error != null -> item { Banner("Artifacts unavailable", artifacts.error!!, error = true) }
            entries == null -> item {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.m)) {
                    CircularProgressIndicator(Modifier.size(24.dp))
                    Text("Opening APK parts…", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        val artifactWindow = preview(filteredArtifacts)
        items(artifactWindow.visible, key = { "art-${it.partIndex}-${it.name}" }) { entry ->
            ArtifactRow(entry = entry, secrets = secrets) { previewEntry = entry }
        }
        if (filteredArtifacts.isNotEmpty()) {
            item {
                SectionFooter(artifactWindow.countLabel("entries"), if (artifactWindow.isCapped) {
                    { onSeeAll(SeeAllTarget.ARTIFACTS, query) }
                } else null)
            }
        } else if (entries?.isNotEmpty() == true) {
            item {
                EmptyState(
                    title = "No artifacts match",
                    detail = "No APK entry name contains \"$query\".",
                    actionLabel = "Clear filter",
                    onAction = { query = "" },
                )
            }
        } else if (entries != null && artifacts.error == null) {
            item {
                EmptyState(
                    title = "No entries",
                    detail = "The APK parts opened but listed no entries.",
                )
            }
        }
    }

    previewEntry?.let { entry ->
        ArtifactPreviewDialog(
            entry = entry,
            source = source,
            secrets = secrets,
            onDismiss = { previewEntry = null },
        )
    }
}

/** One-line recovered path with an explicit copy action (device defect 1). */
@Composable
private fun CompactPathRow(raw: String, onCopy: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            RecoveredPaths.compact(raw),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        TextAction("Copy", onCopy)
    }
}

@Composable
private fun ExploreHeader(title: String, detail: String) {
    Column(Modifier.padding(top = Space.s)) {
        Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
        Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun EndpointRowView(endpoint: EndpointRow, onOpen: () -> Unit) {
    val host = endpoint.host
    Row(Modifier.fillMaxWidth().padding(vertical = Space.xs), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(
                endpoint.displayUrl,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                if (endpoint.verified) {
                    (if (host.appOwned) "app-owned" else host.classification) + " · opens the URL shown"
                } else {
                    "unverified host string · not openable"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            host.samples.firstOrNull()?.takeIf { it != endpoint.displayUrl }?.let { sample ->
                Text(
                    sample,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (endpoint.url != null) {
            TextAction("Open", onOpen, contentDescription = "Open ${host.host}")
        } else {
            Text(
                "no link",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = Space.s),
            )
        }
    }
}

/**
 * Depth is carried by indent alone. The old chevrons implied "expands" and
 * "navigates" on rows that do neither, so they are gone; the indent is capped
 * so a deep path keeps a readable column.
 */
private const val ROUTE_INDENT_DP = 16
private const val MAX_ROUTE_INDENT = 2

@Composable
private fun RouteRowView(row: RouteRow) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(
                start = (minOf(row.depth, MAX_ROUTE_INDENT) * ROUTE_INDENT_DP).dp,
                top = Space.xs,
                bottom = Space.xs,
            ),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            row.node.path,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(Space.s))
        Text(
            if (row.node.terminal) "recovered" else "prefix",
            style = MaterialTheme.typography.labelSmall,
            color = if (row.node.terminal) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun DependencyRow(
    name: String,
    url: String?,
    version: String?,
    license: String?,
    onOpen: () -> Unit,
) {
    Row(Modifier.fillMaxWidth().padding(vertical = Space.xs), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(
                name,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "version ${version ?: ReportMetadata.UNAVAILABLE} · license ${license ?: ReportMetadata.UNAVAILABLE}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (url != null) TextAction("Open", onOpen, contentDescription = "Open $name on pub.dev")
        else Text("not a pub.dev name", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ArtifactRow(entry: ArtifactEntry, secrets: List<String>, onOpen: () -> Unit) {
    // B4: one action for the whole row, ≥48dp tall (measured 56dp on device). The
    // nested 48dp IconButton was a second, 24dp-looking affordance for the same
    // action; the chevron is now a hint, not a separate target.
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClickLabel = "Open", onClick = onOpen)
            .defaultMinSize(minHeight = 48.dp)
            .padding(vertical = Space.xs),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                entry.displayName(secrets),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "${entry.category} · part ${entry.partRole} (#${entry.partIndex}) · ${humanBytes(entry.uncompressedBytes)}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Icon(
            Icons.Default.KeyboardArrowRight,
            contentDescription = null,
            modifier = Modifier.size(24.dp),
        )
    }
}

@Composable
internal fun ArtifactPreviewDialog(
    entry: ArtifactEntry,
    source: ApkSource?,
    secrets: List<String>,
    onDismiss: () -> Unit,
) {
    var preview by remember(entry, source) { mutableStateOf<TextPreview?>(null) }
    var loading by remember(entry, source) { mutableStateOf(true) }
    var error by remember(entry, source) { mutableStateOf<String?>(null) }
    var raw by remember(entry, source) { mutableStateOf(false) }
    var confirmRaw by remember(entry, source) { mutableStateOf(false) }

    LaunchedEffect(entry, source) {
        val src = source
        if (src == null) {
            error = "APK parts are not open."
            loading = false
            return@LaunchedEffect
        }
        val result = withContext(Dispatchers.IO) {
            runCatching { src.preview(entry.partIndex, entry.name) }
        }
        result.onSuccess { p ->
            if (p == null) error = "Entry not found in the selected APK part."
            else preview = p
        }.onFailure { error = it.message ?: "Preview failed." }
        loading = false
    }

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        // B1: FLAG_SECURE is per window, so raw text must secure the dialog's own
        // window (this composition), not the Activity window behind it. Cleared on
        // dismiss/dispose by the reference-counted release.
        SecureScreen(active = raw && preview?.text != null)
        Surface(
            modifier = Modifier.fillMaxWidth(0.95f).heightIn(max = 600.dp),
            shape = MaterialTheme.shapes.medium,
            tonalElevation = 3.dp,
        ) {
            Column(Modifier.padding(Space.l)) {
                Text(
                    entry.displayName(secrets),
                    style = MaterialTheme.typography.titleSmall,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "${entry.category} · part ${entry.partRole} (#${entry.partIndex})",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                when {
                    loading -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CircularProgressIndicator(Modifier.size(24.dp))
                        Text("Reading bounded preview…", style = MaterialTheme.typography.bodySmall)
                    }
                    error != null -> Text(error!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    preview?.binary == true -> Text("Binary entry — no text preview is available.", style = MaterialTheme.typography.bodySmall)
                    preview?.text == null -> Text("This entry is empty.", style = MaterialTheme.typography.bodySmall)
                    else -> {
                        val masked = Evidence.scrub(preview!!.text!!, secrets)
                        Text(
                            if (raw) "Raw preview (explicit)" else "Masked preview of known detected secrets",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (raw) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                        )
                        if (preview!!.truncated) {
                            Text(
                                "Truncated: showing ${preview!!.bytesRead} of ${entry.uncompressedBytes} bytes.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Column(
                            Modifier.weight(1f, fill = false).heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
                        ) {
                            Text(
                                if (raw) preview!!.text!! else masked,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                        if (!raw) {
                            Text(
                                "Masking only covers secrets detected by this scan; other sensitive text may remain.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(Space.s))
                Row(horizontalArrangement = Arrangement.spacedBy(Space.s), verticalAlignment = Alignment.CenterVertically) {
                    TextAction("Close", onDismiss)
                    if (!loading && error == null && preview?.binary != true && preview?.text != null) {
                        if (raw) {
                            TextAction("Hide raw text", onClick = { raw = false })
                        } else {
                            TextAction("Reveal raw text", onClick = { confirmRaw = true })
                        }
                    }
                }
            }
        }
    }

    if (confirmRaw && preview?.text != null) {
        AlertDialog(
            onDismissRequest = { confirmRaw = false },
            title = { Text("Reveal raw text?") },
            text = {
                Text(
                    "Raw artifact content can contain secrets that this scan did not detect. It stays in memory and is hidden when you close this preview. Do not screenshot or share it.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    raw = true
                    confirmRaw = false
                }) { Text("Reveal raw text") }
            },
            dismissButton = { TextButton(onClick = { confirmRaw = false }) { Text("Cancel") } },
        )
    }
}

// ------------------------------------------------------------------ panes

@Composable
private fun NotStartedPane(packageName: String, onStart: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(start = Gutter, end = Gutter, top = Space.xl)) {
        Text("No report loaded", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(Space.s))
        Text(packageName, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(Space.s))
        Text(
            "Run a static audit of this app. Only one scan runs at a time; the report appears here when it finishes.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(Space.l))
        ActionButton("Scan", Icons.Default.PlayArrow, onStart)
    }
}

@Composable
private fun ScanProgressPane(phase: ScanPhase.Running, onCancel: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(start = Gutter, end = Gutter, top = Space.xl)) {
        Text("Scanning ${phase.job.packageName}", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(Space.l))
        ScanStepper(stage = phase.stage, pct = phase.pct)
        Spacer(Modifier.height(Space.s))
        Text(
            "Current stage: ${phase.stage}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(Space.l))
        if (phase.cancelRequested) Text("Cancelling…")
        else ActionButton("Cancel scan", Icons.Default.Close, onCancel)
        Spacer(Modifier.height(Space.s))
        Text(
            "You can leave this screen; the scan keeps running in the notification.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun OtherScanPane(packageName: String, onCancel: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(start = Gutter, end = Gutter, top = Space.xl)) {
        Text("Another scan is running", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(Space.s))
        Text(packageName, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        Spacer(Modifier.height(Space.s))
        Text(
            "Only one scan runs at a time. Wait for it to finish or cancel it, then scan this app.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(Space.l))
        ActionButton("Cancel scan", Icons.Default.Close, onCancel)
    }
}

@Composable
private fun FailurePane(title: String, message: String, retained: Report?, onRetry: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(start = Gutter, end = Gutter, top = 24.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error)
            Spacer(Modifier.width(8.dp))
            Text(title, style = MaterialTheme.typography.titleMedium)
        }
        Spacer(Modifier.height(8.dp))
        Text(message, style = MaterialTheme.typography.bodyMedium)
        if (retained != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                "The last successful report is still available: ${retained.meta.packageName} · ${formatTimestamp(retained.generatedAt)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(Space.l))
        ActionButton("Retry", Icons.Default.Refresh, onRetry)
    }
}

// ------------------------------------------------------------------ export

/** Rotation keeps the ticks and the sensitive opt-in; the export itself is transient. */
private val ExportChoiceSaver: Saver<ExportChoice, Any> =
    listSaver(save = { it.encode() }, restore = { exportChoiceOf(it) })

@Composable
private fun ExportDialog(report: Report, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settings by Settings.state.collectAsState()
    // The setting is the ceiling; the dialog's own switch is the per-export opt-in.
    val sensitiveAllowed = settings.sensitiveExport
    var choice by rememberSaveable(stateSaver = ExportChoiceSaver) { mutableStateOf(ExportChoice()) }
    var confirmSensitive by remember { mutableStateOf(false) }
    var exporting by remember { mutableStateOf(false) }
    var exportJob by remember { mutableStateOf<Job?>(null) }

    AlertDialog(
        // Back (and a tap outside) closes this dialog first — it never leaves the
        // screen — and a running export is cancelled rather than left orphaned.
        onDismissRequest = {
            exportJob?.cancel()
            onDismiss()
        },
        properties = DialogProperties(dismissOnBackPress = true),
        title = { Text("Export report") },
        text = {
            Column(
                Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(Space.s),
            ) {
                Text("Format", style = MaterialTheme.typography.titleSmall)
                ChipRow {
                    WorkbenchChip(selected = choice.json, onClick = { choice = choice.copy(json = true) }, label = "JSON")
                    WorkbenchChip(selected = !choice.json, onClick = { choice = choice.copy(json = false) }, label = "Markdown")
                }
                Text("Sections", style = MaterialTheme.typography.titleSmall)
                ReportSection.entries.forEach { section ->
                    // One labeled toggle node per section: the row owns the tap,
                    // the checkbox is decorative.
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .toggleable(
                                value = section in choice.sections,
                                role = Role.Checkbox,
                                onValueChange = { choice = choice.toggled(section) },
                            )
                            .defaultMinSize(minHeight = 48.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(
                            checked = section in choice.sections,
                            onCheckedChange = null,
                        )
                        Text(section.name.lowercase().replaceFirstChar { it.uppercase() })
                    }
                }
                Row(Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Sensitive export", style = MaterialTheme.typography.titleSmall)
                        Text(
                            if (sensitiveAllowed) {
                                "Off: evidence values stay redacted. On: raw retained values are written to the file."
                            } else {
                                "Disabled: \"Include sensitive values in exports\" is off in Settings, so this export is always redacted."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = choice.sensitive && sensitiveAllowed,
                        enabled = sensitiveAllowed,
                        onCheckedChange = { on ->
                            if (sensitiveAllowed) {
                                if (on) confirmSensitive = true else choice = choice.copy(sensitive = false)
                            }
                        },
                        modifier = Modifier.semantics { contentDescription = "Sensitive export" },
                    )
                }
                Text(
                    "Limits: artifacts are a bounded subset (max 256); selected sections with no data are omitted; history snapshots never include values.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = choice.canExport && !exporting,
                onClick = {
                    exporting = true
                    val sections = choice.sections
                    val ext = choice.extension
                    val sensitive = settings.exportSensitive(choice.sensitive)
                    exportJob = scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            runCatching { ReportExport.writeFile(context, report, ext, sections, sensitive) }
                        }
                        result.onSuccess { file -> shareReportFile(context, file, ext) }
                            .onFailure {
                                android.widget.Toast.makeText(
                                    context,
                                    "Export failed: ${it.message ?: ReportMetadata.UNAVAILABLE}",
                                    android.widget.Toast.LENGTH_LONG,
                                ).show()
                            }
                        exporting = false
                        onDismiss()
                    }
                },
            ) { Text(if (exporting) "Exporting…" else "Export") }
        },
        // Cancel stays reachable while exporting: it cancels the write too.
        dismissButton = {
            TextButton(onClick = {
                exportJob?.cancel()
                onDismiss()
            }) { Text("Cancel") }
        },
    )

    if (confirmSensitive) {
        AlertDialog(
            onDismissRequest = { confirmSensitive = false },
            title = { Text("Enable sensitive export?") },
            text = {
                Text(
                    "This writes raw secret values retained in memory into a shareable file. It is off by default for a reason: only enable it when you explicitly need the raw evidence and control where the file goes.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    choice = choice.copy(sensitive = true)
                    confirmSensitive = false
                }) { Text("I understand") }
            },
            dismissButton = { TextButton(onClick = { confirmSensitive = false }) { Text("Cancel") } },
        )
    }
}
