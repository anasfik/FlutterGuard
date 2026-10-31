package com.flutterguard.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.flutterguard.app.scan.ApkSource
import com.flutterguard.app.scan.ArtifactEntry
import com.flutterguard.app.scan.HostInfo
import com.flutterguard.app.scan.PubPackage
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportFiles
import com.flutterguard.app.scan.ScanLog
import com.flutterguard.app.scan.ScanLogEntry
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.StoredReport
import com.flutterguard.app.scan.displayName
import com.flutterguard.app.scan.secretValues
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Inline preview size for every long section. */
const val PREVIEW_ROWS = 8

/** Hard bound of one See-all route: virtualized, but never unbounded. */
const val SEE_ALL_MAX = 500

/** The stored report of one package, read on IO; null until the read returns. */
@Composable
internal fun rememberStoredReport(packageName: String, fileScan: Boolean = false): StoredReport? {
    val context = LocalContext.current
    var stored by remember(packageName, fileScan) { mutableStateOf<StoredReport?>(null) }
    LaunchedEffect(packageName, fileScan) {
        stored = withContext(Dispatchers.IO) {
            ReportFiles.load(ReportFiles.appDir(context), packageName, fileScan)
        }
    }
    return stored
}

/** APK parts of one app, as opened by [rememberArtifactSource]. */
internal data class ArtifactParts(
    val source: ApkSource? = null,
    val entries: List<ArtifactEntry>? = null,
    val error: String? = null,
)

/**
 * Opens this app's APK parts on IO and closes them when the caller leaves.
 * Explore and the artifact See-all route are never composed at the same time
 * (only the top route renders), so each opens its own source.
 */
@Composable
internal fun rememberArtifactSource(packageName: String, enabled: Boolean = true): ArtifactParts {
    val context = LocalContext.current
    var parts by remember(packageName) { mutableStateOf(ArtifactParts()) }
    LaunchedEffect(packageName, enabled) {
        if (!enabled) return@LaunchedEffect
        val result = withContext(Dispatchers.IO) {
            runCatching {
                val info = context.packageManager.getApplicationInfo(packageName, 0)
                val source = ApkSource.forApplication(info)
                source to source.artifactEntries()
            }
        }
        parts = result.fold(
            onSuccess = { (source, entries) -> ArtifactParts(source = source, entries = entries) },
            onFailure = { ArtifactParts(error = it.message ?: "Could not open the APK parts.") },
        )
    }
    DisposableEffect(packageName) {
        onDispose {
            parts.source?.close()
            parts = ArtifactParts()
        }
    }
    return parts
}

/**
 * A See-all list as its own route. Its report is rebuilt from this process's
 * last success or from disk, and its filter travels in the destination, so:
 * Back pops one route, the footer and the routed list describe the same set,
 * and opening a section never starts, stops or steals a scan.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SectionRoute(
    destination: Destination.Section,
    phase: ScanPhase,
    lastSuccess: ScanPhase.Done?,
    onBack: () -> Unit,
) {
    val packageName = destination.packageName
    val stored = rememberStoredReport(packageName, destination.fileScan)
    val report = DetailPhase.report(
        phase,
        lastSuccess,
        packageName,
        (stored as? StoredReport.Loaded)?.report,
        destination.fileScan,
    )

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = onBack, modifier = Modifier.size(48.dp)) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back to the app's details")
                        }
                    },
                    title = {
                        Text(
                            destination.target.title,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        },
    ) { pad ->
        if (report == null) {
            Column(Modifier.padding(pad).fillMaxSize()) {
                if (stored == null) {
                    // First frame after the push: the file read is on IO, so say
                    // "reading", never "no report" before knowing.
                    Row(
                        Modifier.fillMaxWidth().padding(Gutter),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator(Modifier.size(24.dp))
                        Text("Reading the stored report…", style = MaterialTheme.typography.bodySmall)
                    }
                } else {
                    // The report disappeared between opening the route and
                    // rendering it: say so and keep Back working.
                    EmptyState(
                        title = "No report loaded",
                        detail = if (stored is StoredReport.Unreadable) {
                            "The stored report could not be read: ${stored.message}"
                        } else {
                            "$packageName has no readable report any more. Open the app to scan it again."
                        },
                        actionLabel = "Back to details",
                        onAction = onBack,
                    )
                }
            }
            return@Scaffold
        }

        val secrets = remember(report) { report.secretValues() }
        val groups = remember(report.routes, report.dartSources) {
            RecoveredPaths.split(report.routes, report.dartSources)
        }
        val log = rememberScanLog(packageName, report.generatedAt, report.meta.fileScan)
        val hosts = remember(report.hosts) { report.hosts.filter { it.classification != "unclassified" } }
        val parts = rememberArtifactSource(
            packageName,
            enabled = destination.target == SeeAllTarget.ARTIFACTS,
        )
        var previewEntry by remember(packageName) { mutableStateOf<ArtifactEntry?>(null) }

        // Same filter the footer counted with, carried in the destination.
        val filteredArtifacts = remember(parts.entries, destination.filter, secrets) {
            val list = parts.entries.orEmpty()
            if (destination.filter.isBlank()) list
            else list.filter { it.displayName(secrets).contains(destination.filter, true) }
        }
        val deps = remember(report.framework.dartDeps, destination.filter) {
            filterDependencies(report.framework.dartDeps, destination.filter)
        }
        val rows = remember(destination.target, report, groups, filteredArtifacts, secrets, log, hosts, deps) {
            SeeAllRows.of(
                target = destination.target,
                report = report,
                groups = groups,
                artifacts = filteredArtifacts,
                secrets = secrets,
                log = log,
                hosts = hosts,
                deps = deps,
            )
        }

        Column(Modifier.padding(pad).fillMaxSize()) {
            parts.error?.let { Banner("Artifacts unavailable", it, error = true) }
            SectionListScreen(
                target = destination.target,
                rows = rows,
                modifier = Modifier.weight(1f),
                onOpenArtifact = { entry -> previewEntry = entry },
            )
        }

        previewEntry?.let { entry ->
            ArtifactPreviewDialog(
                entry = entry,
                source = parts.source,
                secrets = secrets,
                onDismiss = { previewEntry = null },
            )
        }
    }
}

/**
 * One bounded inline preview of a long section plus the exact count that makes
 * the bound explicit: `Showing 8 of 238 routes`.
 */
data class SectionWindow<T>(val visible: List<T>, val total: Int) {
    val hidden: Int get() = (total - visible.size).coerceAtLeast(0)
    val isCapped: Boolean get() = hidden > 0

    fun countLabel(noun: String): String =
        if (isCapped) "Showing ${visible.size} of $total $noun" else "$total $noun"
}

fun <T> preview(items: List<T>, limit: Int = PREVIEW_ROWS): SectionWindow<T> =
    SectionWindow(if (limit <= 0) emptyList() else items.take(limit), items.size)

fun <T> seeAllPage(items: List<T>, limit: Int = SEE_ALL_MAX): SectionWindow<T> =
    SectionWindow(if (limit <= 0) emptyList() else items.take(limit), items.size)

/** Dedicated list route behind every long section. */
enum class SeeAllTarget(val title: String, val noun: String, val searchable: Boolean) {
    HOSTS("Endpoints", "hosts", true),
    ROUTES("Candidate routes", "routes", true),
    DART_SOURCES("Dart source paths", "paths", true),
    BUILD_PATHS("Embedded build paths", "paths", true),
    UNCLASSIFIED_PATHS("Unclassified paths", "paths", true),
    DEPENDENCIES("Dependencies", "dependencies", true),
    CHANNELS("Platform channels", "channels", true),
    THIRD_PARTY("Third-party services", "services", false),
    ARTIFACTS("APK artifacts", "entries", true),
    PERMISSIONS("Permissions", "permissions", false),
    DEEP_LINKS("Deep links", "links", false),
    SCAN_LOG("Scan log", "scans", false),
}

/**
 * One generic, display-safe row. Paths and artifact names are already compacted
 * or masked before they reach this model, so nothing raw can leak from a list.
 */
data class SeeAllRowData(
    val title: String,
    val meta: String? = null,
    val detail: String? = null,
    val copy: Boolean = false,
    val link: String? = null,
    val artifact: ArtifactEntry? = null,
)

object SeeAllRows {

    /**
     * Builds the routed list. [hosts] and [deps] are the *filtered* lists the
     * caller previewed, so the See-all header always describes the same set as
     * the footer that opened it.
     *
     * ponytail: this proves the helper honours its arguments, not that
     * `DetailsScreen` passes `filteredDeps`/`filteredArtifacts`; a composable
     * call site is not JVM-testable here. Add an instrumentation test if a
     * regression ever slips through that wiring.
     */
    fun of(
        target: SeeAllTarget,
        report: Report,
        groups: RecoveredPathGroups,
        artifacts: List<ArtifactEntry>?,
        secrets: List<String>,
        log: List<ScanLogEntry> = emptyList(),
        hosts: List<HostInfo>? = null,
        deps: List<String>? = null,
    ): List<SeeAllRowData> = when (target) {
        SeeAllTarget.HOSTS -> Endpoints.rows(hosts ?: report.hosts.filter { it.classification != "unclassified" })
            .map { endpoint ->
                SeeAllRowData(
                    title = endpoint.displayUrl,
                    meta = buildString {
                        append(if (endpoint.verified) "verified host" else "unverified host string")
                        if (endpoint.host.appOwned && endpoint.verified) append(" · app-owned")
                        endpoint.host.samples.firstOrNull()?.let { append(" · $it") }
                    },
                    link = endpoint.url?.let { safeWebUrl(it) },
                )
            }
        SeeAllTarget.ROUTES -> groups.routes.map { SeeAllRowData(title = it, meta = "recovered string", copy = true) }
        SeeAllTarget.DART_SOURCES -> groups.dartSources.map { SeeAllRowData(title = RecoveredPaths.compact(it), copy = true) }
        SeeAllTarget.BUILD_PATHS -> groups.buildPaths.map { SeeAllRowData(title = RecoveredPaths.compact(it), copy = true) }
        SeeAllTarget.UNCLASSIFIED_PATHS -> groups.unclassified.map {
            SeeAllRowData(title = RecoveredPaths.compact(it), meta = "path-shaped, not a route", copy = true)
        }
        SeeAllTarget.DEPENDENCIES -> (deps ?: report.framework.dartDeps).map { dep ->
            val info = PubPackage.describe(dep, provenance = "recovered string")
            SeeAllRowData(
                title = info.name,
                meta = "version ${info.version ?: ReportMetadata.UNAVAILABLE} · license ${info.license ?: ReportMetadata.UNAVAILABLE}",
                link = info.url,
            )
        }
        SeeAllTarget.CHANNELS -> report.channels.map { SeeAllRowData(title = it.name, meta = it.kind) }
        SeeAllTarget.THIRD_PARTY -> report.thirdParty.map {
            SeeAllRowData(title = it.service, meta = it.evidence.joinToString(", "))
        }
        SeeAllTarget.ARTIFACTS -> artifacts.orEmpty().map { entry ->
            SeeAllRowData(
                title = entry.displayName(secrets),
                meta = "${entry.category} · part ${entry.partRole} (#${entry.partIndex}) · ${humanBytes(entry.uncompressedBytes)}",
                artifact = entry,
            )
        }
        SeeAllTarget.PERMISSIONS -> report.permissions.map {
            SeeAllRowData(title = it.name, meta = it.protection, detail = it.description.ifBlank { null })
        }
        SeeAllTarget.DEEP_LINKS -> report.deepLinks.map {
            SeeAllRowData(
                title = "${it.scheme}://${it.host ?: "*"} → ${it.component}",
                meta = if (it.autoVerify) "autoVerify" else "no autoVerify",
            )
        }
        SeeAllTarget.SCAN_LOG -> log.mapIndexed { index, entry ->
            SeeAllRowData(
                title = "v${entry.versionName} (${entry.versionCode}) · grade ${entry.grade ?: ReportMetadata.UNAVAILABLE}",
                meta = if (entry.stampedAtMs > 0) formatTimestamp(entry.stampedAtMs) else ReportMetadata.UNAVAILABLE,
                detail = ScanLog.diffForPreviousVersion(log, index).joinToString("\n").ifBlank { null },
            )
        }.asReversed()
    }
}

fun filterSeeAllRows(rows: List<SeeAllRowData>, query: String): List<SeeAllRowData> =
    if (query.isBlank()) rows else rows.filter { row ->
        row.title.contains(query, true) ||
            row.meta?.contains(query, true) == true ||
            row.detail?.contains(query, true) == true
    }

/** "Showing 8 of 238 routes" + the explicit See-all route for a long section. */
@Composable
fun SectionFooter(countLabel: String, onSeeAll: (() -> Unit)? = null) {
    Row(
        Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            countLabel,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        if (onSeeAll != null) {
            TextButton(onClick = onSeeAll, modifier = Modifier.defaultMinSize(minHeight = 48.dp)) {
                Text("See all")
            }
        }
    }
}

/**
 * Bounded, virtualized list body of a See-all route. Back belongs to the route
 * host (`SectionRoute`), which is the single navigation handler.
 */
@Composable
internal fun SectionListScreen(
    target: SeeAllTarget,
    rows: List<SeeAllRowData>,
    modifier: Modifier = Modifier,
    onOpenArtifact: (ArtifactEntry) -> Unit = {},
) {
    val context = LocalContext.current
    var query by rememberSaveable(target.name) { mutableStateOf("") }
    val filtered = remember(rows, query) { filterSeeAllRows(rows, query) }
    val page = remember(filtered) { seeAllPage(filtered) }

    Column(modifier.fillMaxSize()) {
        if (target.searchable && rows.size > PREVIEW_ROWS) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth().padding(horizontal = Gutter, vertical = 8.dp),
                singleLine = true,
                label = { Text("Filter ${target.noun}") },
            )
        }
        if (filtered.isEmpty()) {
            EmptyState(
                title = if (rows.isEmpty()) "Nothing recovered" else "No matches",
                detail = if (rows.isEmpty()) {
                    "This section is empty for this report."
                } else {
                    "No ${target.noun} contain \"$query\"."
                },
                actionLabel = if (query.isBlank()) null else "Clear filter",
                onAction = if (query.isBlank()) null else ({ query = "" }),
            )
        }
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                start = Gutter, end = Gutter, top = Space.s, bottom = Space.xxl,
            ),
            verticalArrangement = Arrangement.spacedBy(Space.xs),
        ) {
            items(page.visible.size) { index ->
                val row = page.visible[index]
                SeeAllRowView(
                    row = row,
                    onCopy = { copyText(context, row.title, "Copied") },
                    onLink = { openWebLink(context, row.link) },
                    onOpen = { row.artifact?.let(onOpenArtifact) },
                )            }
            if (page.isCapped || query.isNotBlank()) {
                item {
                    SectionFooter(
                        countLabel = if (page.isCapped) page.countLabel(target.noun)
                        else "${filtered.size} ${target.noun}",
                    )
                }
            }
        }
    }
}

@Composable
private fun SeeAllRowView(
    row: SeeAllRowData,
    onCopy: () -> Unit,
    onLink: () -> Unit,
    onOpen: () -> Unit,
) {
    Column(
        Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp).padding(vertical = 4.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                row.title,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = if (row.copy) 1 else 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            when {
                row.artifact != null -> TextButton(
                    onClick = onOpen,
                    modifier = Modifier.defaultMinSize(minHeight = 48.dp),
                ) { Text("Open") }
                row.link?.let { safeWebUrl(it) } != null -> TextButton(
                    onClick = onLink,
                    modifier = Modifier.defaultMinSize(minHeight = 48.dp),
                ) { Text("Open") }
                row.copy -> TextButton(
                    onClick = onCopy,
                    modifier = Modifier.defaultMinSize(minHeight = 48.dp),
                ) { Text("Copy") }
            }
        }
        row.meta?.let {
            Text(
                it,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        row.detail?.let {
            Spacer(Modifier.height(Space.xs))
            Text(
                it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 6,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
