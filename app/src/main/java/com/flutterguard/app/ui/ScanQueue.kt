package com.flutterguard.app.ui

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.flutterguard.app.MainActivity
import com.flutterguard.app.ScanService
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.jobId
import com.flutterguard.app.scan.ScanStore
import com.flutterguard.app.scan.packageName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** One app in the scan-all queue. */
data class QueueApp(val packageName: String, val label: String)

enum class QueueItemState { PENDING, STARTING, RUNNING, DONE, FAILED, CANCELLED }

data class QueueItem(
    val packageName: String,
    val label: String,
    val state: QueueItemState = QueueItemState.PENDING,
    /** Why the item ended the way it did (timeout, start refused, real failure). */
    val note: String? = null,
)

/**
 * Scan-all queue state. Pure and immutable: [ScanQueueMachine] owns every
 * transition so sequencing and cancellation are unit-testable without Android.
 */
data class ScanQueueState(
    val items: List<QueueItem> = emptyList(),
    val active: Boolean = false,
    val cancelRequested: Boolean = false,
) {
    val total: Int get() = items.size
    val finished: Int get() = items.count { it.state in TERMINAL }
    val failures: Int get() = items.count { it.state == QueueItemState.FAILED }
    val done: Int get() = items.count { it.state == QueueItemState.DONE }
    val cancelled: Int get() = items.count { it.state == QueueItemState.CANCELLED }
    val remaining: Int get() = items.count { it.state == QueueItemState.PENDING }

    fun item(packageName: String): QueueItem? = items.firstOrNull { it.packageName == packageName }

    /** The one app that may be starting or scanning. Never more than one. */
    fun current(): QueueItem? =
        items.firstOrNull { it.state == QueueItemState.STARTING || it.state == QueueItemState.RUNNING }

    companion object {
        val TERMINAL = setOf(QueueItemState.DONE, QueueItemState.FAILED, QueueItemState.CANCELLED)
    }
}

object ScanQueueMachine {

    /** Deduplicating start; refuses an empty list and a queue that is already active. */
    fun begin(apps: List<QueueApp>, current: ScanQueueState = ScanQueueState()): ScanQueueState {
        if (current.active || apps.isEmpty()) return current
        val deduped = LinkedHashMap<String, QueueItem>()
        for (app in apps) {
            if (app.packageName.isBlank()) continue
            deduped[app.packageName] = QueueItem(app.packageName, app.label.ifBlank { app.packageName })
        }
        if (deduped.isEmpty()) return current
        return ScanQueueState(items = deduped.values.toList(), active = true)
    }

    /** Next app to start, or null while one is starting/running or after cancel-all. */
    fun nextPending(state: ScanQueueState): QueueItem? {
        if (!state.active || state.cancelRequested) return null
        if (state.current() != null) return null
        return state.items.firstOrNull { it.state == QueueItemState.PENDING }
    }

    fun onStarted(state: ScanQueueState, packageName: String): ScanQueueState {
        if (state.cancelRequested) return state
        return state.copy(
            items = state.items.map {
                if (it.packageName == packageName && it.state == QueueItemState.PENDING) {
                    it.copy(state = QueueItemState.STARTING)
                } else {
                    it
                }
            },
        )
    }

    fun onRunning(state: ScanQueueState, packageName: String): ScanQueueState =
        state.copy(
            items = state.items.map {
                if (it.packageName == packageName && it.state == QueueItemState.STARTING) {
                    it.copy(state = QueueItemState.RUNNING)
                } else {
                    it
                }
            },
        )

    fun onTerminal(
        state: ScanQueueState,
        packageName: String,
        result: QueueItemState,
        note: String? = null,
    ): ScanQueueState {
        val target = state.item(packageName) ?: return state
        if (result !in ScanQueueState.TERMINAL || target.state in ScanQueueState.TERMINAL) return state
        val items = state.items.map {
            if (it.packageName == packageName) it.copy(state = result, note = note) else it
        }
        val stillPending = items.any { it.state == QueueItemState.PENDING }
        val stillCurrent = items.any {
            it.state == QueueItemState.STARTING || it.state == QueueItemState.RUNNING
        }
        return state.copy(
            items = items,
            active = !state.cancelRequested && (stillPending || stillCurrent),
        )
    }

    /** Cancel-all: the running app is cancelled by the caller; nothing else may start. */
    fun onCancelAll(state: ScanQueueState): ScanQueueState {
        if (state.items.isEmpty()) return state
        val items = state.items.map {
            if (it.state == QueueItemState.PENDING) it.copy(state = QueueItemState.CANCELLED) else it
        }
        val stillCurrent = items.any {
            it.state == QueueItemState.STARTING || it.state == QueueItemState.RUNNING
        }
        return state.copy(items = items, cancelRequested = true, active = stillCurrent)
    }
}

/**
 * B2: "terminal" is not "scanned". A cancelled app has no report, so a queue of
 * 11 with 10 cancellations must never read "11 of 11 finished". One wording
 * function feeds both the Home card and the completion notification.
 */
fun queueSummaryText(
    done: Int,
    failed: Int,
    cancelled: Int,
    total: Int,
    pending: Int = 0,
): String = buildString {
    append("$done of $total scanned")
    if (failed > 0) append(" · $failed failed")
    if (cancelled > 0) append(" · $cancelled cancelled")
    if (pending > 0) append(" · $pending queued")
}

/**
 * The two queue waits, pure so they can be tested against real [ScanPhase]
 * values. Both are gated on the job the queue actually started: `ScanState`
 * keeps its last phase after a scan, so a stale `Done`/`Failed`/`Cancelled` of
 * the same package must never complete a new queue item.
 */
object ScanQueueWaits {

    /** How long a start may take to appear in the store before the item is failed. */
    const val START_TIMEOUT_MS = 10_000L

    /**
     * Upper bound for one app. Exceeding it marks the item FAILED ("timed out")
     * instead of waiting forever on a stalled scanner.
     */
    const val APP_TIMEOUT_MS = 20 * 60_000L

    /**
     * Ready to start the next app: both scan slots are free, or the queue was
     * cancelled. Without the cancel term a stalled scanner body would suspend the
     * queue forever, with Cancel queue already gone from the UI.
     */
    fun idleOrCancelled(running: Boolean, executing: Boolean, cancelRequested: Boolean): Boolean =
        cancelRequested || (!running && !executing)

    /** Job id of the running phase that counts as "this queue item started". */
    fun startedJobId(phase: ScanPhase, packageName: String, baselineJobId: Long): Long? =
        (phase as? ScanPhase.Running)
            ?.job
            // An installed-app queue item must not adopt a picked-APK job that
            // happens to run for the same package name.
            ?.takeIf { it.packageName == packageName && it.id > baselineJobId && !it.fileScan }
            ?.id

    /** Terminal phase belonging to [startedJobId] only. */
    fun isTerminal(phase: ScanPhase, packageName: String, startedJobId: Long): Boolean =
        result(phase, packageName, startedJobId) != null

    fun result(phase: ScanPhase, packageName: String, startedJobId: Long): QueueItemState? = when (phase) {
        is ScanPhase.Done -> if (phase.job.packageName == packageName && phase.job.id == startedJobId &&
            !phase.job.fileScan
        ) QueueItemState.DONE else null
        is ScanPhase.Failed -> if (phase.job.packageName == packageName && phase.job.id == startedJobId &&
            !phase.job.fileScan
        ) QueueItemState.FAILED else null
        is ScanPhase.Cancelled -> if (phase.job.packageName == packageName && phase.job.id == startedJobId) QueueItemState.CANCELLED else null
        else -> null
    }
}

/** Pure start gate: one queue, no running scan, no scanner body winding down. */
object ScanQueueGate {
    fun canBegin(
        running: Boolean,
        executing: Boolean,
        queueRunning: Boolean,
        apps: List<QueueApp>,
    ): Boolean = !running && !executing && !queueRunning && apps.any { it.packageName.isNotBlank() }
}

/**
 * Drives the queue through the single scan owner ([ScanService]). It never
 * scans by itself: it starts one app, waits for the observable terminal state
 * of that job, then starts the next. The scan body always belongs to the service.
 *
 * ponytail: the orchestration below runs on a real service + notifications and
 * is not unit-tested; only its pure predicates, gate and summary text are.
 * Instrument it if a sequencing bug ever survives review.
 */
// Holds only the application context (passed in as `appContext`), which lives as
// long as the process, so the static-field leak warning does not apply.
@SuppressLint("StaticFieldLeak")
object ScanQueueRunner {

    private const val CHANNEL_ID = "scan_queue"
    private const val NOTIF_ID = 1002
    private const val START_TIMEOUT_MS = 10_000L

    private val _state = MutableStateFlow(ScanQueueState())
    val state: StateFlow<ScanQueueState> = _state.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var job: Job? = null
    private var context: Context? = null

    /** False when empty, already running, or a scan is already in flight (no double start). */
    fun start(appContext: Context, apps: List<QueueApp>): Boolean {
        val canBegin = ScanQueueGate.canBegin(
            running = ScanStore.state.value.running != null,
            executing = ScanStore.isExecuting(),
            queueRunning = job?.isActive == true,
            apps = apps,
        )
        if (!canBegin) return false
        val begun = ScanQueueMachine.begin(apps, _state.value)
        if (!begun.active) return false
        context = appContext.applicationContext
        _state.value = begun
        job = scope.launch { run(begun.items.size) }
        return true
    }

    fun cancelAll(appContext: Context) {
        _state.update { ScanQueueMachine.onCancelAll(it) }
        if (ScanStore.state.value.running != null) ScanService.cancel(appContext)
    }

    fun dismiss() {
        if (job?.isActive == true) return
        _state.value = ScanQueueState()
    }

    /** Test hook. */
    fun reset() {
        job?.cancel()
        job = null
        context = null
        _state.value = ScanQueueState()
    }

    private suspend fun run(count: Int) {
        while (true) {
            val next = ScanQueueMachine.nextPending(_state.value) ?: break
            val pkg = next.packageName
            // The store refuses overlap while an abandoned scanner body winds down;
            // both the UI slot and the execution slot are observable. Bounded and
            // cancellable: a permanently busy store must fail the item, not wedge
            // the queue (a wedged queue hides its own Cancel action).
            val idle = withTimeoutOrNull(ScanQueueWaits.APP_TIMEOUT_MS) {
                combine(ScanStore.state, ScanStore.executing, _state) { s, e, q ->
                    ScanQueueWaits.idleOrCancelled(s.running != null, e != null, q.cancelRequested)
                }.first { it }
            }
            if (idle == null) {
                _state.update {
                    ScanQueueMachine.onTerminal(it, pkg, QueueItemState.FAILED, "scan store still busy")
                }
                break
            }
            // A cancel that landed while we waited must not start anything.
            if (_state.value.cancelRequested) break

            val baseline = ScanStore.state.value.phase.jobId ?: 0L
            _state.value = ScanQueueMachine.onStarted(_state.value, pkg)
            if (_state.value.cancelRequested) break

            val jobId = awaitStart(pkg, baseline)
            if (jobId == null) {
                _state.update { ScanQueueMachine.onTerminal(it, pkg, QueueItemState.FAILED, "could not start the scan") }
                continue
            }
            _state.update { ScanQueueMachine.onRunning(it, pkg) }
            // Cancel-all can land between "start sent" and "running": cancel it too.
            if (_state.value.cancelRequested) context?.let { ScanService.cancel(it) }

            val terminal = withTimeoutOrNull(ScanQueueWaits.APP_TIMEOUT_MS) {
                ScanStore.state.first { ScanQueueWaits.isTerminal(it.phase, pkg, jobId) }
            }
            if (terminal == null) {
                _state.update {
                    ScanQueueMachine.onTerminal(it, pkg, QueueItemState.FAILED, "timed out")
                }
                continue
            }
            val result = ScanQueueWaits.result(terminal.phase, pkg, jobId) ?: QueueItemState.FAILED
            _state.update { ScanQueueMachine.onTerminal(it, pkg, result) }
        }
        // Items left behind by a busy-store timeout will never start: report them
        // as cancelled, not "queued", so the summary cannot promise work.
        if (_state.value.items.any { it.state == QueueItemState.PENDING }) {
            _state.value = ScanQueueMachine.onCancelAll(_state.value)
        }
        val finalState = _state.value
        context?.let { notifyFinished(it, finalState, count) }
    }

    /** Starts one app and returns the job id that belongs to this start, or null. */
    private suspend fun awaitStart(packageName: String, baselineJobId: Long): Long? {
        val ctx = context ?: return null
        if (ScanService.start(ctx, packageName)) {
            startedJobId(packageName, baselineJobId)?.let { return it }
        }
        delay(1_200)
        if (ScanService.start(ctx, packageName)) {
            startedJobId(packageName, baselineJobId)?.let { return it }
        }
        return null
    }

    /**
     * Waits for the first phase that belongs to a job newer than the baseline.
     * Uses the same predicate the tests pin, so removing it breaks production.
     */
    private suspend fun startedJobId(packageName: String, baselineJobId: Long): Long? =
        withTimeoutOrNull(ScanQueueWaits.START_TIMEOUT_MS) {
            var found: Long? = null
            ScanStore.state.first { s ->
                found = ScanQueueWaits.startedJobId(s.phase, packageName, baselineJobId)
                found != null
            }
            found
        }

    /** Background-safe completion; silently skipped when notifications are not permitted. */
    private fun notifyFinished(context: Context, state: ScanQueueState, requested: Int) {
        // The Settings toggle is the user's answer for the whole app, queue included.
        if (!com.flutterguard.app.settings.Settings.snapshot(context).notifications) return
        runCatching {
            val nm = context.getSystemService(NotificationManager::class.java)
            if (nm?.getNotificationChannel(CHANNEL_ID) == null) {
                nm?.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Scan-all queue", NotificationManager.IMPORTANCE_LOW)
                        .apply { setShowBadge(false) },
                )
            }
            val open = PendingIntent.getActivity(
                context,
                1,
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val cancelled = state.cancelled
            val text = queueSummaryText(state.done, state.failures, cancelled, requested, state.remaining)
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle(if (cancelled > 0) "Scan-all cancelled" else "Scan-all finished")
                .setContentText(text)
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            ScanNotifier.post(context, NOTIF_ID, notification)
        }
    }
}
