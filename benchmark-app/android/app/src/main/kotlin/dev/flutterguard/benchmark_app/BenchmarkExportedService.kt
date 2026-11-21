package dev.flutterguard.benchmark_app

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Planted exported component: a service any app on the device can start.
 * It does no work and returns no binder.
 */
class BenchmarkExportedService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
}
