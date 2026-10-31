package com.flutterguard.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import com.flutterguard.app.scan.Discovery
import com.flutterguard.app.scan.History
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.ReportExport
import com.flutterguard.app.scan.ReportFiles
import com.flutterguard.app.scan.ScanCancelledException
import com.flutterguard.app.scan.ScanJob
import com.flutterguard.app.scan.ScanStore
import com.flutterguard.app.scan.ScanToken
import com.flutterguard.app.scan.Scanner
import com.flutterguard.app.ui.ScanNotifier
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob

/**
 * The single owner of scan execution. The UI and the scripted (`am start -e scan`)
 * entry both start a scan here; navigation and rotation never own or cancel the job.
 * The service is a `dataSync` foreground service (local file processing), reports
 * progress in a notification, and stops itself on completion, failure, cancel or
 * the Android 15 foreground time limit.
 */
class ScanService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var work: Job? = null
    private var activeId: Long = -1L

    /**
     * Abandonment gate of the job this service instance is running. Per job and
     * permanent, so a retry can never revive an old synchronous scanner.
     */
    private var activeToken: ScanToken? = null

    /**
     * The cache copy of a picked/shared APK. `execute` deletes it in `finally`,
     * but a launch cancelled before the body runs never reaches that, and
     * `onDestroy` is the only place left that can drop it.
     */
    private var activeFile: java.io.File? = null
    private var headless = false
    private var foregroundStarted = false
    private var lastNotificationKey: String? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val pkg = intent.getStringExtra(EXTRA_PACKAGE)
                val filePath = intent.getStringExtra(EXTRA_FILE)
                if (pkg.isNullOrBlank()) {
                    stopSelf(startId)
                } else if (filePath != null) {
                    startFileScan(pkg, java.io.File(filePath), intent.getBooleanExtra(EXTRA_HEADLESS, false))
                } else {
                    startScan(pkg, intent.getBooleanExtra(EXTRA_HEADLESS, false))
                }
            }
            ACTION_CANCEL -> requestCancel()
            else -> if (work?.isActive != true) stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    private fun startScan(packageName: String, headless: Boolean) {
        // The installed-app path is gated on explicit consent for the current
        // policy: the UI never enumerates before it agrees, and the service
        // refuses a start that bypassed the UI (scripted or stale intent).
        if (!com.flutterguard.app.settings.Settings.snapshot(this).inventoryAllowed()) {
            if (headless) Log.w(TAG, "FG_ERROR installed-app scan needs privacy consent: $packageName")
            refuseScan(packageName, "Installed-app scans are off until you agree to the privacy disclosure")
            return
        }
        startJob(packageName, headless, file = null)
    }

    /** A picked/shared APK: package identity is already decoded by [com.flutterguard.app.scan.FileImport]. */
    private fun startFileScan(packageName: String, file: java.io.File, headless: Boolean) {
        if (!file.isFile) {
            if (headless) Log.e(TAG, "FG_ERROR imported APK is gone: ${file.name}")
            refuseScan(packageName, "The imported APK is no longer available")
            return
        }
        startJob(packageName, headless, file)
    }

    private fun startJob(packageName: String, headless: Boolean, file: java.io.File?) {
        // The store refuses a second job while any scanner body is still running,
        // even one whose job already failed (timeout/cancel): no overlap, no hiding.
        val job = ScanStore.start(packageName, fileScan = file != null)
        if (job == null) {
            // No job will own this cache copy, so nothing else would ever delete it.
            file?.let { runCatching { it.delete() } }
            refuseScan(packageName, "a scan is already running or still stopping")
            return
        }
        if (file != null) activeFile = file
        val token = ScanToken(job.id)
        this.headless = headless
        activeId = job.id
        activeToken = token
        goForeground(token, packageName, "Starting…", 0)
        if (headless) Log.i(TAG, "FG_START $packageName")
        // The execution slot is freed by the launch itself, not by execute()'s
        // finally: a launch cancelled before the body runs must not brick scanning.
        work = ScanStore.launchExecution(scope, job.id) { execute(job, token, file) }
    }

    /**
     * A start answered with a startForegroundService request must call
     * startForeground, otherwise Android kills the process. A live scan keeps
     * ownership: its notification is re-announced under the same id and the
     * service is NOT stopped — stopSelf(startId) here would tear the running
     * scan down, because this refused start is the most recent one.
     */
    private fun refuseScan(packageName: String, why: String) {
        if (headless) Log.w(TAG, "FG_ERROR $why: $packageName")
        val running = ScanStore.state.value.running
        if (running != null || foregroundStarted) {
            val cancelling = running?.cancelRequested == true
            ensureChannel()
            ServiceCompat.startForeground(
                this,
                NOTIF_ID,
                buildNotification(
                    running?.job?.packageName ?: packageName,
                    if (cancelling) "Cancelling…" else running?.stage ?: "Scan running",
                    running?.pct ?: 0,
                    cancelling,
                ),
                foregroundType(),
            )
            foregroundStarted = true
            lastNotificationKey = null
            return
        }
        // Nothing live: satisfy the request, then stop.
        goForeground(null, packageName, why, 0)
        finishForeground()
    }

    private suspend fun execute(job: ScanJob, token: ScanToken, file: java.io.File?) {
        val packageName = job.packageName
        val dir = ReportFiles.appDir(this)
        val settings = com.flutterguard.app.settings.Settings.snapshot(this)
        var stage = "Reading package info"
        // True once a full report is on disk: an abandonment that lands after the
        // write must not leave an "interrupted" marker for a package that has one.
        var savedOk = false
        val onProgress: (String, Int) -> Unit = { step, pct ->
            if (!token.isAbandoned) {
                stage = step
                ScanStore.progress(job.id, step, pct)
                goForeground(token, packageName, step, pct)
                if (headless) Log.i(TAG, "FG_PROGRESS $pct% $step")
            }
        }
        val isCancelled: () -> Boolean = { token.isAbandoned || ScanStore.isCancelled(job.id) }
        // A picked/shared APK is stored in its own namespace: the installed app with
        // the same package name keeps its verdict, report and version log. Declared
        // outside the try so the finally block clears the same marker it set.
        val fileScan = file != null
        try {
            val previous: String?
            val report: Report
            if (file != null) {
                // File scan: the manifest identity was resolved before the service
                // started, so the report still records the package it declared.
                ReportFiles.markInflight(dir, packageName, fileScan)
                previous = if (settings.keepHistory) ReportFiles.previousHistory(dir, packageName, true) else null
                report = Scanner.scanFile(this, file, onProgress, isCancelled)
            } else {
                val app = try {
                    Discovery.load(this, packageName)
                } catch (t: Throwable) {
                    // Removed package or unreadable package manager entry: a visible failure, never a success.
                    fail(job, token, "Not installed or unreadable: ${t.message ?: t::class.java.simpleName}")
                    return
                }

                ReportFiles.markInflight(dir, packageName, fileScan)
                previous = if (settings.keepHistory) ReportFiles.previousHistory(dir, packageName) else null

                report = Scanner.scan(
                    context = this,
                    app = app,
                    onProgress = onProgress,
                    isCancelled = isCancelled,
                )
            }

            // An abandoned job (timeout/destroy) must not persist anything.
            if (token.isAbandoned) return
            val json = ReportExport.toJson(report)
            if (token.isAbandoned) return
            val saved = ReportFiles.save(
                dir, packageName, json, History.snapshot(report),
                writeHistory = settings.keepHistory,
                fileScan = fileScan,
            )
            savedOk = true
            if (token.isAbandoned) return
            val diff = previous?.let {
                runCatching { History.diff(it, History.snapshot(report)) }.getOrDefault(emptyList())
            } ?: emptyList()
            ScanStore.succeeded(job.id, report, saved.json.absolutePath, saved.historyNote, diff)
            if (headless) Log.i(TAG, "FG_REPORT ${saved.json.absolutePath}")
        } catch (c: ScanCancelledException) {
            if (!token.isAbandoned) {
                ScanStore.cancelled(job.id)
                if (headless) Log.w(TAG, "FG_ERROR cancelled")
            }
        } catch (c: CancellationException) {
            // Service stopped or timed out; onDestroy/onTimeout already recorded why.
            throw c
        } catch (t: Throwable) {
            if (!token.isAbandoned) fail(job, token, "${t.message ?: t::class.java.simpleName} (stage: $stage)")
        } finally {
            // Keep the marker of an abandoned scan: it is the interruption signal —
            // unless the report was already written, in which case it would be a lie.
            if (!token.isAbandoned || savedOk) ReportFiles.clearInflight(dir, packageName, fileScan)
            // The cache copy exists only for this job; an abandoned job also drops it.
            if (file != null) runCatching { file.delete() }
            if (activeFile === file) activeFile = null
            if (activeId == job.id && activeToken === token) {
                activeId = -1L
                activeToken = null
                finishForeground()
            }
        }
    }

    private fun fail(job: ScanJob, token: ScanToken, message: String) {
        if (token.isAbandoned) return
        ScanStore.failed(job.id, message)
        if (headless) Log.e(TAG, "FG_ERROR $message")
    }

    private fun requestCancel() {
        val id = activeId
        if (id < 0 || work?.isActive != true) {
            stopSelf()
            return
        }
        ScanStore.requestCancel(id)
        val running = ScanStore.state.value.running
        goForeground(activeToken, running?.job?.packageName ?: "scan", "Cancelling…", running?.pct ?: 0)
    }

    override fun onTimeout(startId: Int) {
        onForegroundTimeout()
    }

    /** Android 15 dataSync foreground time limit (6h in 24h). */
    override fun onTimeout(startId: Int, fgsType: Int) {
        onForegroundTimeout()
    }

    private fun onForegroundTimeout() {
        abandonActive("Foreground time limit reached — the scan was stopped. Retry to run it again.", interrupted = true)
        if (headless) Log.e(TAG, "FG_ERROR foreground time limit reached")
    }

    /**
     * Permanently abandons the running job: its token stays abandoned for the rest
     * of its life, so its late progress, notification, report write and marker
     * cleanup are all fenced off while a retry waits for the body to exit.
     */
    private fun abandonActive(reason: String, interrupted: Boolean) {
        val id = activeId
        val token = activeToken
        token?.abandon()
        work?.cancel()
        work = null
        if (id >= 0 && token != null) ScanStore.failed(id, reason, interrupted)
        activeId = -1L
        activeToken = null
        finishForeground()
    }

    override fun onDestroy() {
        val id = activeId
        // Abandon first: a synchronous scanner must not touch state or storage afterwards.
        activeToken?.abandon()
        if (id >= 0 && ScanStore.state.value.running?.job?.id == id) {
            // The service died mid-scan (not a completion): record an interruption, never a success.
            ScanStore.failed(id, "Scan interrupted — the app process or scan service was stopped.", interrupted = true)
            if (headless) Log.e(TAG, "FG_ERROR scan interrupted")
        }
        work?.cancel()
        work = null
        // A launch killed before its body ran never reached execute()'s cleanup.
        activeFile?.let { runCatching { it.delete() } }
        activeFile = null
        activeId = -1L
        activeToken = null
        super.onDestroy()
    }

    // ------------------------------------------------------------ notification

    private fun goForeground(token: ScanToken?, packageName: String, stage: String, pct: Int) {
        // An abandoned job may never resurrect the notification or foreground state.
        if (token != null && token.isAbandoned) return
        val cancelling = ScanStore.state.value.running?.cancelRequested == true
        val key = "$packageName|$stage|$pct|$cancelling"
        if (key == lastNotificationKey) return
        lastNotificationKey = key
        ensureChannel()
        val notification = buildNotification(packageName, if (cancelling) "Cancelling…" else stage, pct, cancelling)
        if (!foregroundStarted) {
            // Must happen within a few seconds of startForegroundService; the manifest
            // declares the dataSync type and its permissions.
            ServiceCompat.startForeground(this, NOTIF_ID, notification, foregroundType())
            foregroundStarted = true
        } else {
            ScanNotifier.post(this, NOTIF_ID, notification)
        }
    }

    private fun finishForeground() {
        lastNotificationKey = null
        foregroundStarted = false
        runCatching { ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE) }
        stopSelf()
    }

    private fun foregroundType(): Int =
        if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC else 0

    private fun ensureChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Artifact scans", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Progress of static artifact scans running in the background"
                setShowBadge(false)
            }
        )
    }

    private fun buildNotification(packageName: String, stage: String, pct: Int, cancelling: Boolean): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val cancel = PendingIntent.getService(
            this,
            1,
            Intent(this, ScanService::class.java).setAction(ACTION_CANCEL),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("Scanning $packageName")
            .setContentText(stage)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setProgress(100, pct.coerceIn(0, 100), false)
            .apply { if (!cancelling) addAction(0, "Cancel", cancel) }
            .build()
    }

    companion object {
        private const val TAG = "FlutterGuard"
        private const val CHANNEL_ID = "scan_progress"
        private const val NOTIF_ID = 1001

        const val ACTION_START = "com.flutterguard.app.action.START_SCAN"
        const val ACTION_CANCEL = "com.flutterguard.app.action.CANCEL_SCAN"
        const val EXTRA_PACKAGE = "package"
        const val EXTRA_HEADLESS = "headless"
        const val EXTRA_FILE = "apkFile"

        /** Returns false when the foreground service could not be started (e.g. background start restrictions). */
        fun start(context: Context, packageName: String, headless: Boolean = false): Boolean {
            val intent = Intent(context, ScanService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_PACKAGE, packageName)
                .putExtra(EXTRA_HEADLESS, headless)
            return try {
                context.startForegroundService(intent)
                true
            } catch (t: Throwable) {
                Log.e(TAG, if (headless) "FG_ERROR ${t.message}" else "Could not start scan service: ${t.message}")
                false
            }
        }

        /** Starts an audit of a picked/shared APK already copied into the app cache. */
        fun startFile(
            context: Context,
            packageName: String,
            file: java.io.File,
            headless: Boolean = false,
        ): Boolean {
            val intent = Intent(context, ScanService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_PACKAGE, packageName)
                .putExtra(EXTRA_FILE, file.absolutePath)
                .putExtra(EXTRA_HEADLESS, headless)
            return try {
                context.startForegroundService(intent)
                true
            } catch (t: Throwable) {
                Log.e(TAG, if (headless) "FG_ERROR ${t.message}" else "Could not start file scan: ${t.message}")
                false
            }
        }

        fun cancel(context: Context): Boolean = try {
            context.startService(Intent(context, ScanService::class.java).setAction(ACTION_CANCEL))
            true
        } catch (t: Throwable) {
            Log.e(TAG, "Could not cancel scan: ${t.message}")
            false
        }
    }
}
