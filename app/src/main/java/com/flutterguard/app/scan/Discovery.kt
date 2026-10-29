package com.flutterguard.app.scan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import java.io.File

/**
 * One installed app as shown in the list. Deliberately platform-object free
 * (only the nullable icon bitmap) and stable enough to cache across navigation;
 * the scanner resolves its own [ApplicationInfo] by package name at scan time.
 */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val isFlutter: Boolean,
    val isSystem: Boolean,
    /** Base APK plus split APK sizes; 0 when unreadable. */
    val sizeBytes: Long,
    val splitCount: Int,
    val icon: Bitmap?,
)

/** Enumerates installed apps (requires QUERY_ALL_PACKAGES) and flags Flutter ones. */
object Discovery {

    /** Throws on package-manager failure: discovery errors must be surfaced, not shown as an empty list. */
    fun loadApps(context: Context): List<InstalledApp> {
        val pm = context.packageManager
        val pkgs: List<PackageInfo> = pm.getInstalledPackages(PackageManager.GET_META_DATA)
        val out = ArrayList<InstalledApp>(pkgs.size)
        for (pi in pkgs) toInstalledApp(pm, pi)?.let(out::add)
        return out.sortedWith(compareByDescending<InstalledApp> { it.isFlutter }.thenBy { it.label.lowercase() })
    }

    /** Resolves one package. Throws [PackageManager.NameNotFoundException] when it is gone. */
    fun load(context: Context, packageName: String): InstalledApp {
        val pm = context.packageManager
        val pi = pm.getPackageInfo(packageName, PackageManager.GET_META_DATA)
        return toInstalledApp(pm, pi) ?: error("no application info for $packageName")
    }

    private fun toInstalledApp(pm: PackageManager, pi: PackageInfo): InstalledApp? {
        val ai = pi.applicationInfo ?: return null
        val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(pi.packageName)
        val versionCode = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()
        return InstalledApp(
            packageName = pi.packageName,
            label = label,
            versionName = pi.versionName,
            versionCode = versionCode,
            minSdk = ai.minSdkVersion.takeIf { it > 0 },
            targetSdk = ai.targetSdkVersion.takeIf { it > 0 },
            isFlutter = runCatching { detectFlutter(ai) }.getOrDefault(false),
            isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            sizeBytes = totalApkBytes(ai.publicSourceDir ?: ai.sourceDir, ai.splitSourceDirs),
            splitCount = ai.splitSourceDirs?.size ?: 0,
            icon = runCatching { drawableToBitmap(pm.getApplicationIcon(ai)) }.getOrNull(),
        )
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

/** Base + split APK bytes on disk. Missing/unreadable parts contribute 0. */
fun totalApkBytes(basePath: String?, splitPaths: Array<out String>?): Long {
    var total = 0L
    basePath?.let { total += File(it).length() }
    splitPaths?.forEach { total += File(it).length() }
    return total
}
