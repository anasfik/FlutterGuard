package com.flutterguard.app.ui

import android.animation.ValueAnimator
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.flutterguard.app.scan.InstalledApp
import com.flutterguard.app.scan.InventoryState
import com.flutterguard.app.scan.ScanPhase

/**
 * Home = cached inventory + explicit refresh. The list is a single LazyColumn
 * so controls, active scan, banners and rows scroll as one truthful surface;
 * loading/empty/error all render inside it (never a blank page) and inventory
 * progress is a line of text, not a card.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HomeScreen(
    state: InventoryState,
    phase: ScanPhase,
    interrupted: List<String>,
    search: SearchUi,
    onSearch: (SearchUi) -> Unit,
    advanced: Boolean,
    onAdvanced: (Boolean) -> Unit,
    filter: AppFilter,
    onFilter: (AppFilter) -> Unit,
    packageInput: String,
    onPackageInput: (String) -> Unit,
    packageError: String?,
    listState: LazyListState,
    onRefresh: () -> Unit,
    onPick: (InstalledApp) -> Unit,
    onOpenRunning: (String) -> Unit,
    onCancelScan: () -> Unit,
    onScanPackage: (String) -> Unit,
    notificationsAllowed: Boolean,
    queue: ScanQueueState,
    onOpenQueue: () -> Unit,
    onScanAll: (List<QueueApp>) -> Unit,
    inventoryAllowed: Boolean,
    scanAllAllowed: Boolean,
    onOpenSettings: () -> Unit,
    onPickFile: () -> Unit,
    onRequestInventory: () -> Unit,
) {
    var confirmScanAll by remember { mutableStateOf(false) }
    val query = search.query
    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    // Title only: one line, so the bar stays the compact single-row
                    // variant. No subtitle anywhere else stands in for it.
                    title = {
                        Text(
                            "FlutterGuard",
                            style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.semantics { heading() },
                        )
                    },
                    actions = {
                        IconButton(onClick = onOpenSettings, modifier = Modifier.size(48.dp)) {
                            Icon(Icons.Default.Settings, contentDescription = "Settings")
                        }
                        if (inventoryAllowed) {
                            IconButton(onClick = onRefresh, enabled = !state.loading, modifier = Modifier.size(48.dp)) {
                                Icon(Icons.Default.Refresh, contentDescription = "Refresh installed apps")
                            }
                        }
                    },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        },
    ) { pad ->
        val running = phase as? ScanPhase.Running
        val flutterCount = state.apps.count { it.isFlutter }
        val scanAllCount = state.apps.count { it.isFlutter && !it.isSystem }
        val normalFallback = !advanced && state.apps.isNotEmpty() && flutterCount == 0
        val effective = when {
            advanced -> filter
            normalFallback -> AppFilter(query, flutterOnly = false, hideSystem = true)
            else -> AppFilter(query, flutterOnly = true, hideSystem = true)
        }
        val filtered = filterApps(state.apps, effective)

        Box(Modifier.padding(pad).fillMaxSize()) {
            LazyColumn(
                state = listState,
                // The list stops one FAB + gutter above the bottom edge, so the
                // search FAB floats on empty background instead of over a row.
                modifier = Modifier.fillMaxSize().padding(bottom = FabClearance),
                contentPadding = PaddingValues(start = Gutter, end = Gutter, top = 8.dp, bottom = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (running != null) {
                    item {
                        ActiveScanCard(
                            phase = running,
                            onReopen = { onOpenRunning(running.job.packageName) },
                            onCancel = onCancelScan,
                        )
                    }
                }

                if (queue.items.isNotEmpty()) {
                    item {
                        QueueEntryRow(queue = queue, onClick = onOpenQueue)
                    }
                }

                if (inventoryAllowed) {
                    item {
                        ChipRow {
                            WorkbenchChip(selected = !advanced, onClick = { onAdvanced(false) }, label = "Normal")
                            WorkbenchChip(selected = advanced, onClick = { onAdvanced(true) }, label = "Advanced")
                        }
                    }

                    if (advanced) {
                        item {
                            ToolsPanel(
                                appCount = scanAllCount,
                                packageInput = packageInput,
                                onPackageInput = onPackageInput,
                                packageError = packageError,
                                running = running != null,
                                queueActive = queue.active,
                                filter = filter,
                                onFilter = onFilter,
                                onScanPackage = onScanPackage,
                                onScanAll = { confirmScanAll = true },
                                scanAllAllowed = scanAllAllowed,
                                onPickFile = onPickFile,
                            )
                        }
                    }
                }

                if (interrupted.isNotEmpty()) {
                    item {
                        Banner(
                            "An earlier scan was interrupted",
                            "${interrupted.joinToString()} did not finish. Its previous report was left untouched; open the app to scan again.",
                        )
                    }
                }

                state.error?.let { error ->
                    item {
                        Banner(
                            "Discovering apps failed",
                            "$error The list below is the previous result, not an empty device.",
                            error = true,
                        )
                    }
                }

                when {
                    !inventoryAllowed -> {
                        item {
                            // The main screen keeps its shape: app scanning is the
                            // product, and asking for it is the primary action here.
                            // One file at a time is the fallback, not the offer.
                            Column(
                                Modifier.fillMaxWidth().padding(Gutter),
                                verticalArrangement = Arrangement.spacedBy(Space.s),
                            ) {
                                Text(
                                    "App scanning is off",
                                    style = MaterialTheme.typography.titleMedium,
                                    modifier = Modifier.semantics { heading() },
                                )
                                Text(
                                    "FlutterGuard cannot see which apps are installed until you allow it. Android grants broad package visibility when the app is installed, so there is no system prompt — this is FlutterGuard asking.",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(Space.xs))
                                Button(
                                    onClick = onRequestInventory,
                                    modifier = Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp),
                                ) { Text("Enable app scanning") }
                                TextAction("Scan a single APK instead", onPickFile)
                                Text(
                                    "A single-file scan works without that access and is labelled as a file scan.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                    !state.hasData && state.loading -> {
                        item { LoadingRow("Enumerating installed apps…") }
                        items(4) { SkeletonRow() }
                    }
                    !state.hasData && state.error != null -> {
                        item {
                            EmptyState(
                                title = "Could not read installed apps",
                                detail = "Refresh may succeed after the package manager is ready.",
                                actionLabel = "Retry",
                                onAction = onRefresh,
                            )
                        }
                    }
                    !state.hasData -> item { LoadingRow("Reading cached inventory…") }
                    else -> {
                        item {
                            Text(
                                when {
                                    // A refresh with a cached list has no card any more:
                                    // one inline word is the whole progress state.
                                    normalFallback -> "No Flutter apps detected — showing all user apps."
                                    else -> "${filtered.size} shown · $flutterCount Flutter of ${state.apps.size} installed"
                                } + if (state.loading) " · refreshing…" else "",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        if (filtered.isEmpty()) {
                            item {
                                EmptyState(
                                    title = "No matches",
                                    detail = "No installed app matches the current search and filters.",
                                    actionLabel = "Clear search and filters",
                                    onAction = {
                                        onSearch(search.cleared())
                                        onFilter(AppFilter(query = "", flutterOnly = false, hideSystem = false))
                                    },
                                )
                            }
                        } else {
                            items(filtered, key = { it.packageName }) { app ->
                                AppRow(app) { onPick(app) }
                            }
                        }
                    }
                }
            }
            HomeSearchBar(
                search = search,
                onSearch = onSearch,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(start = Gutter, end = Gutter, bottom = Space.l),
            )
        }
    }

    val scanAllTargets = state.apps.filter { it.isFlutter && !it.isSystem }
    if (confirmScanAll && scanAllAllowed) {
        AlertDialog(
            onDismissRequest = { confirmScanAll = false },
            title = { Text("Scan ${scanAllTargets.size} Flutter apps?") },
            text = {
                Text(
                    "The queue runs ${scanAllTargets.size} full static scans one at a time through the single scan owner. " +
                        "Each scan can take minutes on kernel-heavy apps and keeps the CPU busy, so expect battery use. " +
                        "Every finished app writes its report and history entry. " +
                        "You can cancel the queue at any time: the current scan stops at its next checkpoint and no queued app starts. " +
                        if (notificationsAllowed) {
                            "Per-app results and a queue summary are posted as notifications."
                        } else {
                            "Notifications are turned off for FlutterGuard, so per-app results stay inside the app; nothing is announced while it is in the background."
                        },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmScanAll = false
                    onScanAll(scanAllTargets.map { QueueApp(it.packageName, it.label) })
                }) { Text("Start queue") }
            },
            dismissButton = { TextButton(onClick = { confirmScanAll = false }) { Text("Cancel") } },
        )
    }
}

/** Strong ease-out: fast start, calm settle. Transform/alpha only, 220 ms. */
private val SearchEasing = CubicBezierEasing(0.05f, 0.7f, 0.1f, 1f)

/**
 * One FAB (56 dp) plus the 16 dp gutter the FAB floats on, reserved out of the
 * list viewport: rows are clipped above the FAB instead of being drawn under it.
 */
private val FabClearance = 56.dp + Gutter

/**
 * Search as one control in two states: a collapsed FAB in the bottom-end corner
 * that expands into the field from that same corner. Nothing animates but
 * `alpha`/`scale`, so the list is never re-laid-out mid-animation.
 *
 * The field is only composed while it is open (or fading), so a collapsed
 * search leaves no EditText behind for TalkBack or focus traversal. Collapsing
 * keeps the query on purpose: an open filter stays a filter. The X clears it.
 */
@Composable
private fun HomeSearchBar(
    search: SearchUi,
    onSearch: (SearchUi) -> Unit,
    modifier: Modifier = Modifier,
) {
    val focusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current
    val progress = remember { Animatable(if (search.expanded) 1f else 0f) }
    // Keeps both states composed for the duration of the transition, then drops
    // the one that is gone — two recompositions per open/close, not one per frame.
    var animating by remember { mutableStateOf(false) }

    LaunchedEffect(search.expanded) {
        val target = if (search.expanded) 1f else 0f
        if (!search.expanded) {
            // The close affordance (or Back) collapses immediately: focus and
            // keyboard go now, only the pill fading is animated.
            focusManager.clearFocus()
            keyboard?.hide()
        }
        if (progress.value != target) {
            animating = true
            if (ValueAnimator.areAnimatorsEnabled()) {
                progress.animateTo(target, tween(SEARCH_DURATION_MS, easing = SearchEasing))
            } else {
                // Reduced motion: toggle instantly, same end states.
                progress.snapTo(target)
            }
            animating = false
        }
        // Focus arrives in the frame the field finishes expanding, so the
        // keyboard never fights the animation.
        if (search.expanded) focusRequester.requestFocus()
    }

    Box(modifier, contentAlignment = Alignment.CenterEnd) {
        if (!search.expanded || animating) {
            BadgedBox(badge = { if (search.filtering) Badge() }) {
                FloatingActionButton(
                    onClick = { onSearch(search.expand()) },
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.graphicsLayer {
                        val p = progress.value
                        alpha = 1f - p
                        scaleX = 1f - 0.2f * p
                        scaleY = 1f - 0.2f * p
                        transformOrigin = TransformOrigin(1f, 1f)
                    },
                ) {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = if (search.filtering) {
                            // A collapsed query is still filtering: say so, the badge alone is silent.
                            "Search installed apps, filtered by ${search.query}"
                        } else {
                            "Search installed apps"
                        },
                    )
                }
            }
        }
        if (search.expanded || animating) {
            Row(
                Modifier.fillMaxWidth().graphicsLayer {
                    val p = progress.value
                    alpha = p
                    val scale = 0.85f + 0.15f * p
                    scaleX = scale
                    scaleY = scale
                    transformOrigin = TransformOrigin(1f, 1f)
                },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = search.query,
                    onValueChange = { onSearch(search.typed(it)) },
                    modifier = Modifier.weight(1f).focusRequester(focusRequester),
                    singleLine = true,
                    shape = MaterialTheme.shapes.extraLarge,
                    placeholder = { Text("Search name or package") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    trailingIcon = {
                        if (search.query.isNotEmpty()) {
                            IconButton(onClick = { onSearch(search.cleared()) }, modifier = Modifier.size(48.dp)) {
                                Icon(Icons.Default.Close, contentDescription = "Clear search")
                            }
                        }
                    },
                )
                Spacer(Modifier.width(8.dp))
                IconButton(
                    onClick = { onSearch(search.collapse()) },
                    modifier = Modifier
                        .size(48.dp)
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh, MaterialTheme.shapes.extraSmall),
                ) {
                    Icon(Icons.Default.Close, contentDescription = "Close search")
                }
            }
        }
    }
}

@Composable
private fun ActiveScanCard(phase: ScanPhase.Running, onReopen: () -> Unit, onCancel: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(Space.l), verticalArrangement = Arrangement.spacedBy(Space.s)) {
            Text("Scan in progress", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            Text(phase.job.packageName, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
            LinearProgressIndicator(progress = { phase.pct / 100f }, modifier = Modifier.fillMaxWidth())
            Text(
                "${phase.stage} (${phase.pct}%)${if (phase.cancelRequested) " · cancelling…" else ""}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(Space.s)) {
                Button(onClick = onReopen, modifier = Modifier.defaultMinSize(minHeight = 48.dp)) { Text("Open") }
                if (!phase.cancelRequested) {
                    TextAction("Cancel scan", onCancel)
                }
            }
            Text(
                "You can leave this screen or navigate away; the scan keeps running.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * Home's only queue surface: one row that opens the Queue route. It appears
 * while a queue is active or while its result is still undismissed, and it
 * never repeats the queue's per-app detail — that lives on the route.
 */
@Composable
private fun QueueEntryRow(queue: ScanQueueState, onClick: () -> Unit) {
    val shape = MaterialTheme.shapes.medium
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            .clickable(onClickLabel = "Open scan queue", onClick = onClick),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        shape = shape,
    ) {
        Row(
            Modifier.padding(horizontal = Space.l, vertical = Space.s).defaultMinSize(minHeight = 48.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "Scan queue",
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    queueEntrySubtitle(queue),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (queue.active) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(8.dp))
            Icon(
                Icons.Default.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AppRow(app: InstalledApp, onClick: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        shape = MaterialTheme.shapes.medium,
    ) {
        Row(
            Modifier.padding(horizontal = Space.l, vertical = Space.s).defaultMinSize(minHeight = 72.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            app.icon?.let {
                Image(it.asImageBitmap(), contentDescription = null, modifier = Modifier.size(40.dp))
            } ?: Box(Modifier.size(40.dp).background(MaterialTheme.colorScheme.surfaceContainerHighest, CircleShape))
            Spacer(Modifier.width(Space.m))
            Column(Modifier.weight(1f)) {
                Text(app.label, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                // One deliberate line per metadata fact: version, SDK range, size.
                // The version may ellipsize; the SDK range never shares its line,
                // so it cannot be pushed out by a long version name.
                tileMetaLines(app).forEach { line ->
                    Text(
                        line,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            if (app.isFlutter) {
                // Badge, not a control: the chip radius, never a pill.
                Surface(color = MaterialTheme.colorScheme.primaryContainer, shape = MaterialTheme.shapes.extraSmall) {
                    Text(
                        "FLUTTER",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(horizontal = Space.s, vertical = Space.xs),
                    )
                }
                Spacer(Modifier.width(Space.xs))
            }
            Icon(Icons.Default.KeyboardArrowRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Only values the package manager actually reports. */

@Composable
private fun LoadingRow(label: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = Space.l),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.m),
    ) {
        CircularProgressIndicator(Modifier.size(40.dp), color = MaterialTheme.colorScheme.primary)
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
    }
}

@Composable
private fun SkeletonRow() {
    Surface(
        modifier = Modifier.fillMaxWidth().height(64.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = MaterialTheme.shapes.medium,
    ) {}
}
