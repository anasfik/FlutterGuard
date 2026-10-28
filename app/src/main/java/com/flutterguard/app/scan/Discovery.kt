package com.flutterguard.app.scan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import java.io.File

data class InstalledApp(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val isFlutter: Boolean,
    val isSystem: Boolean,
    val icon: Bitmap?,
    val applicationInfo: ApplicationInfo,
)

/** Enumerates installed apps (requires QUERY_ALL_PACKAGES) and flags Flutter ones. */
object Discovery {

    fun loadApps(context: Context): List<InstalledApp> {
        val pm = context.packageManager
        val pkgs: List<android.content.pm.PackageInfo> = pm.getInstalledPackages(PackageManager.GET_META_DATA)
        val out = ArrayList<InstalledApp>(pkgs.size)
        for (pi in pkgs) {
            val ai = pi.applicationInfo ?: continue
            val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(pi.packageName)
            val versionCode = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()
            out.add(
                InstalledApp(
                    packageName = pi.packageName,
                    label = label,
                    versionName = pi.versionName,
                    versionCode = versionCode,
                    isFlutter = runCatching { detectFlutter(ai) }.getOrDefault(false),
                    isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    icon = runCatching { drawableToBitmap(pm.getApplicationIcon(ai)) }.getOrNull(),
                    applicationInfo = ai,
                )
            )
        }
        return out.sortedWith(compareByDescending<InstalledApp> { it.isFlutter }.thenBy { it.label.lowercase() })
    }

    /**
     * Flutter detection. The nativeLibraryDir fast path is unreliable: several
     * ROMs/SELinux policies deny stat() on other apps' extracted lib dirs, so
     * the authoritative check is the APK zip itself (base + splits).
     */
    private fun detectFlutter(ai: ApplicationInfo): Boolean {
        ai.nativeLibraryDir?.let { nd ->
            if (File(nd, "libapp.so").exists() || File(nd, "libflutter.so").exists()) return true
        }
        if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0) return false // zip scan too slow for all system apps
        val paths = LinkedHashSet<String>()
        ai.publicSourceDir?.let(paths::add)
        ai.sourceDir?.let(paths::add)
        ai.splitSourceDirs?.let(paths::addAll)
        for (p in paths) {
            val apk = File(p)
            if (!apk.canRead()) continue
            java.util.zip.ZipFile(apk).use { z ->
                if (z.getEntry("lib/arm64-v8a/libapp.so") != null ||
                    z.getEntry("lib/armeabi-v7a/libapp.so") != null ||
                    z.getEntry("lib/x86_64/libapp.so") != null ||
                    z.getEntry("lib/arm64-v8a/libflutter.so") != null ||
                    z.getEntry("lib/armeabi-v7a/libflutter.so") != null ||
                    z.getEntry("lib/x86_64/libflutter.so") != null ||
                    z.getEntry("assets/flutter_assets/AssetManifest.bin") != null ||
                    z.getEntry("assets/flutter_assets/AssetManifest.json") != null
                ) return true
            }
        }
        return false
    }

    private fun drawableToBitmap(d: Drawable): Bitmap? {
        if (d is BitmapDrawable && d.bitmap != null) return d.bitmap
        val size = 96
        val w = if (d.intrinsicWidth > 0) d.intrinsicWidth else size
        val h = if (d.intrinsicHeight > 0) d.intrinsicHeight else size
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        d.setBounds(0, 0, canvas.width, canvas.height)
        d.draw(canvas)
        return bmp
    }
}
