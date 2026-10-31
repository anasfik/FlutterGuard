package com.flutterguard.app.ui

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.flutterguard.app.MainActivity
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.ScanStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

/**
 * A3: `ScanStore` is a plain `MutableStateFlow`, not Compose snapshot state, so
 * `snapshotFlow { ScanStore.state.value.phase }` reads nothing the snapshot
 * system can observe and may never re-emit for the exact case it exists for (a
 * scan ending while the user sits on Home). Collect the flow itself.
 */
fun scanPhaseFeed(): Flow<ScanPhase> = ScanStore.state.map { it.phase }.distinctUntilChanged()

/**
 * Terminal scan notification, so a scan that finishes (or fails) while the user
 * is elsewhere is not silent. The service removes its own progress notification
 * on finish; this is the one-shot result. Silently skipped — never promised —
 * when POST_NOTIFICATIONS is denied.
 */
object ScanNotifier {

    private const val CHANNEL_ID = "scan_results"
    private const val NOTIF_ID = 1003

    /**
     * The one place that posts a non-foreground notification.
     *
     * POST_NOTIFICATIONS is revocable at any time from API 33 on, and a missing
     * grant throws nothing but silently drops the notification — so every caller
     * has to ask first. Keeping the check here means no call site can forget it.
     */
    fun post(context: Context, id: Int, notification: Notification): Boolean {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return false
        return runCatching {
            NotificationManagerCompat.from(context).notify(id, notification)
        }.isSuccess
    }

    fun terminal(context: Context, phase: ScanPhase) {
        val manager = NotificationManagerCompat.from(context)
        if (!manager.areNotificationsEnabled()) return
        val (title, text) = when (phase) {
            is ScanPhase.Done -> "Scan finished" to buildString {
                append(phase.job.packageName)
                append(" · grade ").append(phase.report.grade)
                val findings = phase.report.findings.size
                append(" · ").append(findings).append(if (findings == 1) " finding" else " findings")
            }
            is ScanPhase.Failed -> "Scan failed" to "${phase.job.packageName} · ${phase.message.take(120)}"
            is ScanPhase.Cancelled -> "Scan cancelled" to phase.job.packageName
            else -> return
        }
        runCatching {
            val nm = context.getSystemService(NotificationManager::class.java)
            if (nm?.getNotificationChannel(CHANNEL_ID) == null) {
                nm?.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Scan results", NotificationManager.IMPORTANCE_DEFAULT)
                        .apply { setShowBadge(false) },
                )
            }
            val open = PendingIntent.getActivity(
                context,
                2,
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_more)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            post(context, NOTIF_ID, notification)
        }
    }
}
