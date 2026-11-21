package dev.flutterguard.benchmark_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Planted exported component: a receiver any app on the device can trigger.
 */
class BenchmarkExportedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) = Unit
}
