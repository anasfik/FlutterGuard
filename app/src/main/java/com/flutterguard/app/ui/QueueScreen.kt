package com.flutterguard.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.flutterguard.app.scan.ScanPhase

/**
 * One queue row, as the screen renders it: label, package, one state label and
 * whether the row goes anywhere. Pure and unit-tested; the queue's own
 * sequencing stays in [ScanQueueMachine].
 *
 * ponytail: a FAILED row carries its reason here (`failed · timed out`) and
 * opens the app's Details like a finished row. Details shows the last stored
 * report or its own no-report/failure pane, because the scan phase is global
 * and may already belong to the next app. Pass the note through
 * `Destination.Details` if a failure ever needs to be rendered inside Details.
 */
enum class QueueRowAction { NONE, OPEN_DETAILS }

data class QueueRowState(
    val title: String,
    val subtitle: String,
    val stateLabel: String,
    val action: QueueRowAction,
    val active: Boolean = false,
    val failed: Boolean = false,
) {
    val opensDetails: Boolean get() = action == QueueRowAction.OPEN_DETAILS
}

/**
 * One state word per intent, shared with the stepper and the Home card:
 * `queued` `running` `done` `failed` `cancelled`. A live stage and percentage
 * decorate `running` only, and only when the phase is this row's own app.
 */
fun queueStateWord(state: QueueItemState, live: ScanPhase.Running?): String = when (state) {
    QueueItemState.PENDING -> "queued"
    QueueItemState.STARTING -> "running"
    QueueItemState.RUNNING -> if (live == null) "running" else "running · ${live.stage} ${live.pct}%"
    QueueItemState.DONE -> "done"
    QueueItemState.FAILED -> "failed"
    QueueItemState.CANCELLED -> "cancelled"
}

fun queueRowState(item: QueueItem, phase: ScanPhase = ScanPhase.Idle): QueueRowState {
    // Only this app's own running scan may contribute a stage and percent.
    val live = (phase as? ScanPhase.Running)?.takeIf { it.job.packageName == item.packageName }
    val word = queueStateWord(item.state, live)
    // The reason belongs to the row's own state word, never to a second label.
    val label = if (item.state == QueueItemState.FAILED && !item.note.isNullOrBlank()) {
        "$word · ${item.note}"
    } else {
        word
    }
    return QueueRowState(
        title = item.label.ifBlank { item.packageName },
        subtitle = item.packageName,
        stateLabel = label,
        action = if (item.state == QueueItemState.DONE || item.state == QueueItemState.FAILED) {
            QueueRowAction.OPEN_DETAILS
        } else {
            QueueRowAction.NONE
        },
        active = item.state == QueueItemState.RUNNING || item.state == QueueItemState.STARTING,
        failed = item.state == QueueItemState.FAILED,
    )
}

/** Determinate progress: every terminal item counts, cancelled ones too. */
fun queueProgress(queue: ScanQueueState): Float =
    if (queue.total == 0) 0f else queue.finished.toFloat() / queue.total

/** Home's single queue entry row: `running · 3 of 11 scanned · 2 queued`. */
fun queueEntrySubtitle(queue: ScanQueueState): String {
    val state = when {
        queue.active -> "running"
        queue.cancelRequested || queue.cancelled > 0 -> "cancelled"
        else -> "done"
    }
    return "$state · " + queueSummaryText(queue.done, queue.failures, queue.cancelled, queue.total, queue.remaining)
}

/**
 * The scan-all queue as its own route. It presents `ScanQueueRunner.state` and
 * nothing else: it never starts, stops or reorders a scan, and the only scan
 * call is the user's own "Cancel queue" (confirmed, same consequence text as
 * before). Back pops the route, so a Details opened from a row returns here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun QueueRoute(
    queue: ScanQueueState,
    phase: ScanPhase,
    notificationsAllowed: Boolean,
    onBack: () -> Unit,
    onOpenApp: (String) -> Unit,
    onCancelQueue: () -> Unit,
    onDismiss: () -> Unit,
) {
    var confirmCancel by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = onBack, modifier = Modifier.size(48.dp)) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back to apps")
                        }
                    },
                    title = {
                        Text(
                            if (queue.active) "Scan queue" else "Scan-all result",
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
        Column(Modifier.padding(pad).fillMaxSize()) {
            if (queue.items.isEmpty()) {
                EmptyState(
                    title = "No scan queue",
                    detail = "This queue was dismissed or the process restarted. Start one from Advanced → Scan all Flutter apps.",
                    actionLabel = "Back to apps",
                    onAction = onBack,
                )
                return@Scaffold
            }

            Column(
                Modifier.padding(horizontal = Gutter).padding(top = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    queueSummaryText(queue.done, queue.failures, queue.cancelled, queue.total, queue.remaining),
                    style = MaterialTheme.typography.titleSmall,
                )
                // Honest and determinate: terminal items over total. No live
                // region here, and none on the rows, so the scanning percent
                // never re-announces on every progress tick.
                LinearProgressIndicator(progress = { queueProgress(queue) }, modifier = Modifier.fillMaxWidth())
            }

            LazyColumn(
                Modifier.weight(1f),
                contentPadding = PaddingValues(start = Gutter, end = Gutter, top = 8.dp, bottom = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(queue.items, key = { it.packageName }) { item ->
                    val row = queueRowState(item, phase)
                    QueueRowView(row, if (row.opensDetails) ({ onOpenApp(item.packageName) }) else null)
                }
            }

            QueueActions(
                queue = queue,
                notificationsAllowed = notificationsAllowed,
                onCancel = { confirmCancel = true },
                onDismiss = onDismiss,
            )
        }
    }

    // B3: cancel-all stops a running scan, so it is confirmed and the
    // consequence (stop at the next checkpoint, nothing else starts) is stated.
    if (confirmCancel) {
        AlertDialog(
            onDismissRequest = { confirmCancel = false },
            title = { Text("Cancel the scan-all queue?") },
            text = {
                Text(
                    "The scan running now stops at its next checkpoint, so its report is not written. " +
                        "No queued app starts. Reports already written stay.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmCancel = false
                    onCancelQueue()
                }) { Text("Cancel queue") }
            },
            dismissButton = {
                TextButton(onClick = { confirmCancel = false }) { Text("Keep scanning") }
            },
        )
    }
}

/**
 * The one filled primary button in this screen: cancel while the queue runs,
 * dismiss once it is terminal. Nothing else competes with it.
 */
@Composable
private fun QueueActions(
    queue: ScanQueueState,
    notificationsAllowed: Boolean,
    onCancel: () -> Unit,
    onDismiss: () -> Unit,
) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = Gutter, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (queue.active) {
            Text(
                if (notificationsAllowed) {
                    "The queue keeps running if you leave this screen; completion is posted as a notification."
                } else {
                    "The queue keeps running if you leave this screen. Notifications are off, so completion is only visible when you reopen the app."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = onCancel,
                enabled = !queue.cancelRequested,
                modifier = Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp),
            ) { Text(if (queue.cancelRequested) "Cancelling…" else "Cancel queue") }
        } else {
            Button(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp),
            ) { Text("Dismiss") }
        }
    }
}

/** One merged node: title, package and the state in its description. */
@Composable
private fun QueueRowView(row: QueueRowState, onOpen: (() -> Unit)?) {
    val shape = MaterialTheme.shapes.medium
    val modifier = Modifier
        .fillMaxWidth()
        .semantics(mergeDescendants = true) { stateDescription = row.stateLabel }
        .then(
            if (onOpen == null) {
                Modifier
            } else {
                Modifier.clip(shape).clickable(onClickLabel = "Open details", onClick = onOpen)
            },
        )
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        shape = shape,
    ) { QueueRowContent(row) }
}

@Composable
private fun QueueRowContent(row: QueueRowState) {
    Row(
        Modifier.padding(horizontal = Space.l, vertical = Space.s).defaultMinSize(minHeight = 48.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                row.title,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                row.subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(8.dp))
        Text(
            row.stateLabel,
            style = MaterialTheme.typography.labelSmall,
            color = when {
                row.failed -> MaterialTheme.colorScheme.error
                row.active -> MaterialTheme.colorScheme.primary
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            },
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.End,
            modifier = Modifier.widthIn(max = 150.dp),
        )
        // A chevron only where there is a destination.
        if (row.opensDetails) {
            Spacer(Modifier.width(4.dp))
            Icon(
                Icons.Default.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
