package com.flutterguard.app.scan

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Identity of one requested scan. Progress/completion messages carry it so stale ones can be dropped. */
data class ScanJob(
    val id: Long,
    val packageName: String,
    val startedAtMs: Long,
    /**
     * True when the job scans a picked/shared APK rather than the installed app.
     * Part of the job identity: progress, failure and cancellation of one
     * namespace must never surface under the other's name.
     */
    val fileScan: Boolean = false,
)

sealed interface ScanPhase {
    data object Idle : ScanPhase

    data class Running(
        val job: ScanJob,
        val stage: String = "Starting…",
        val pct: Int = 0,
        /** Set when the user asked to cancel; the scan stops at its next checkpoint. */
        val cancelRequested: Boolean = false,
    ) : ScanPhase

    data class Done(
        val job: ScanJob,
        val report: Report,
        /** Absolute path of the atomically written JSON report, null if storage failed. */
        val reportPath: String?,
        /** Non-null when the report was saved but its history snapshot was not. */
        val historyNote: String? = null,
        val diff: List<String> = emptyList(),
    ) : ScanPhase

    data class Failed(val job: ScanJob, val message: String, val interrupted: Boolean = false) : ScanPhase

    data class Cancelled(val job: ScanJob) : ScanPhase
}

/** Storage namespace this phase belongs to. */
val ScanPhase.fileScan: Boolean
    get() = when (this) {
        is ScanPhase.Running -> job.fileScan
        is ScanPhase.Done -> job.fileScan
        is ScanPhase.Failed -> job.fileScan
        is ScanPhase.Cancelled -> job.fileScan
        ScanPhase.Idle -> false
    }

/** Package this phase belongs to, or null for [ScanPhase.Idle]. */
val ScanPhase.packageName: String?
    get() = when (this) {
        is ScanPhase.Running -> job.packageName
        is ScanPhase.Done -> job.packageName
        is ScanPhase.Failed -> job.packageName
        is ScanPhase.Cancelled -> job.packageName
        ScanPhase.Idle -> null
    }

/**
 * Permanent abandonment gate for one job. Abandonment cannot be revoked: a later
 * job gets its own token, so a zombie scanner that only reaches its next
 * checkpoint after a timeout/retry still sees its own abandoned flag.
 */
class ScanToken(val jobId: Long) {
    private val abandoned = AtomicBoolean(false)

    val isAbandoned: Boolean get() = abandoned.get()

    /** Idempotent: timeout, service destroy and a late cancel all converge here. */
    fun abandon() {
        abandoned.set(true)
    }
}

/**
 * Whether the audit screen may start a scan by itself. Pure so the "busy
 * elsewhere", "already have a result" and "a queue owns the slot" rules are
 * regression-tested.
 */
object ScanStartPolicy {
    fun shouldAutoStart(
        phase: ScanPhase,
        packageName: String,
        queueActive: Boolean = false,
        hasReport: Boolean = false,
        fileScan: Boolean = false,
    ): Boolean = when {
        // The queue is the single mutator of the slot while it runs.
        queueActive -> false
        // A stored/in-memory report is already shown; a rescan is explicit.
        hasReport -> false
        phase is ScanPhase.Idle -> true
        // One scan at a time; the caller re-evaluates when the other scan ends.
        phase is ScanPhase.Running -> false
        // A finished scan of the other namespace says nothing about this one.
        else -> phase.packageName != packageName || phase.fileScan != fileScan
    }
}

/** Job id of any phase, or null for [ScanPhase.Idle]; used to gate "a newer job" waits. */
val ScanPhase.jobId: Long?
    get() = when (this) {
        is ScanPhase.Running -> job.id
        is ScanPhase.Done -> job.id
        is ScanPhase.Failed -> job.id
        is ScanPhase.Cancelled -> job.id
        ScanPhase.Idle -> null
    }

/**
 * Immutable scan state. Every transition is a pure function so the lifecycle
 * rules (one job, no stale progress, no stale completion) are unit-testable
 * without Android or coroutines.
 */
data class ScanState(
    val phase: ScanPhase = ScanPhase.Idle,
    /** Last successful scan of this process, kept so a failed retry can still point at a valid report. */
    val lastSuccess: ScanPhase.Done? = null,
) {
    val running: ScanPhase.Running? get() = phase as? ScanPhase.Running

    /** Returns the same state and false when another job is already running: duplicates are dropped. */
    fun start(job: ScanJob): Pair<ScanState, Boolean> =
        if (running != null) this to false else copy(phase = ScanPhase.Running(job)) to true

    fun progress(jobId: Long, stage: String, pct: Int): ScanState {
        val r = running ?: return this
        if (r.job.id != jobId) return this
        return copy(phase = r.copy(stage = stage, pct = pct.coerceIn(0, 100).coerceAtLeast(r.pct)))
    }

    fun requestCancel(jobId: Long): ScanState {
        val r = running ?: return this
        if (r.job.id != jobId || r.cancelRequested) return this
        return copy(phase = r.copy(cancelRequested = true))
    }

    /** A scan that finished before observing a cancel request is a genuine success. */
    fun succeeded(
        jobId: Long,
        report: Report,
        reportPath: String?,
        historyNote: String?,
        diff: List<String>,
    ): ScanState {
        val r = running ?: return this
        if (r.job.id != jobId) return this
        val done = ScanPhase.Done(r.job, report, reportPath, historyNote, diff)
        return copy(phase = done, lastSuccess = done)
    }

    fun failed(jobId: Long, message: String, interrupted: Boolean = false): ScanState {
        val r = running ?: return this
        if (r.job.id != jobId) return this
        return copy(phase = ScanPhase.Failed(r.job, message, interrupted))
    }

    fun cancelled(jobId: Long): ScanState {
        val r = running ?: return this
        if (r.job.id != jobId) return this
        return copy(phase = ScanPhase.Cancelled(r.job))
    }
}

/**
 * Process-scoped scan state, observed by the UI and written by [com.flutterguard.app.ScanService].
 * Holds no Activity or Context, so rotation and navigation cannot affect a running scan.
 */
object ScanStore {

    private val ids = AtomicLong(0)
    private val _state = MutableStateFlow(ScanState())

    /**
     * Job whose scanner body has not returned yet. A terminal state (timeout,
     * cancel, failure) frees the UI slot but not this one: the synchronous scan
     * must finish exiting before a second scanner may start. Observable, so the
     * scan-all queue can wait for the real slot instead of guessing.
     */
    private val _executing = MutableStateFlow<Long?>(null)
    val executing: StateFlow<Long?> = _executing.asStateFlow()
    val executingJob: Long? get() = _executing.value

    fun isExecuting(): Boolean = _executing.value != null

    val state: StateFlow<ScanState> = _state.asStateFlow()

    /**
     * One active job *execution* per process. Returns null when a scan is
     * running or when an abandoned scan body is still winding down.
     */
    @Synchronized
    fun start(
        packageName: String,
        now: Long = System.currentTimeMillis(),
        fileScan: Boolean = false,
    ): ScanJob? {
        if (_state.value.running != null || _executing.value != null) return null
        val job = ScanJob(ids.incrementAndGet(), packageName, now, fileScan)
        val (next, accepted) = _state.value.start(job)
        if (!accepted) return null
        _state.value = next
        _executing.value = job.id
        return job
    }

    /** Called once when a scanner body returns, successfully or not. Only its own slot is freed. */
    @Synchronized
    fun executionFinished(jobId: Long) {
        if (_executing.value == jobId) _executing.value = null
    }

    /**
     * Runs [block] as the owner of the execution slot of [jobId] and frees the
     * slot however that coroutine ends — including a launch that is cancelled
     * before the body ever runs. Releasing only inside the body (its `finally`)
     * leaks the claim on service destruction or abandonment in the start window,
     * which then refuses every later scan until process death. [executionFinished]
     * is id-guarded and idempotent, so an extra call is harmless.
     */
    fun launchExecution(scope: CoroutineScope, jobId: Long, block: suspend () -> Unit): Job? {
        val launched = runCatching { scope.launch { block() } }.getOrNull()
        if (launched == null) {
            executionFinished(jobId)
            return null
        }
        // Fires for normal completion and for a cancelled-before-start job alike.
        launched.invokeOnCompletion {
            // A body that never ran leaves the phase Running on top of the slot:
            // settle both, or the store looks busy forever. No-op once terminal.
            failed(jobId, "scan did not start")
            executionFinished(jobId)
        }
        return launched
    }

    fun progress(jobId: Long, stage: String, pct: Int) =
        _state.update { it.progress(jobId, stage, pct) }

    fun requestCancel(jobId: Long) = _state.update { it.requestCancel(jobId) }

    fun isCancelled(jobId: Long): Boolean =
        _state.value.running?.let { it.job.id == jobId && it.cancelRequested } == true

    fun succeeded(
        jobId: Long,
        report: Report,
        reportPath: String?,
        historyNote: String?,
        diff: List<String>,
    ) = _state.update { it.succeeded(jobId, report, reportPath, historyNote, diff) }

    fun failed(jobId: Long, message: String, interrupted: Boolean = false) =
        _state.update { it.failed(jobId, message, interrupted) }

    fun cancelled(jobId: Long) = _state.update { it.cancelled(jobId) }

    /** Test hook: returns the store to a fresh Idle state. */
    @Synchronized
    fun reset() {
        _executing.value = null
        _state.value = ScanState()
    }
}
