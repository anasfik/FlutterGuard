package com.flutterguard.app.scan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * The only Android adapter in front of the shared scanner. Package-manager
 * lookup, API-level signing branches, installer metadata and permission
 * protection stay here; the engine never sees a Context.
 */
object AndroidScan {

    /**
     * Installed-app scan. [InstalledApp] is resolved again at scan time so a
     * package removed since discovery fails visibly here instead of scanning a
     * stale cached entry.
     */
    suspend fun scan(
        context: Context,
        app: InstalledApp,
        onProgress: (step: String, pct: Int) -> Unit,
        isCancelled: () -> Boolean = { false },
    ): Report {
        val pm = context.packageManager
        var flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or PackageManager.GET_PERMISSIONS
        if (Build.VERSION.SDK_INT >= 28) flags = flags or PackageManager.GET_SIGNING_CERTIFICATES
        val pi = pm.getPackageInfo(app.packageName, flags)
        val ai = pm.getApplicationInfo(app.packageName, 0)

        val target = ScanTarget(
            packageName = app.packageName,
            label = app.label,
            versionName = app.versionName,
            versionCode = app.versionCode,
            minSdk = app.minSdk,
            targetSdk = app.targetSdk,
            isSystem = app.isSystem,
        )
        return Scanner.scan(
            parts = partsFor(ai),
            target = target,
            install = installFacts(pm, app.packageName, pi, ai),
            onProgress = onProgress,
            isCancelled = isCancelled,
            permissionProtection = permissionProtection(pm),
        )
    }

    /** Picked/shared APK scan: same engine, platform permission metadata retained. */
    suspend fun scanFile(
        context: Context,
        file: File,
        onProgress: (step: String, pct: Int) -> Unit,
        isCancelled: () -> Boolean = { false },
    ): Report = Scanner.scanFile(
        file = file,
        onProgress = onProgress,
        isCancelled = isCancelled,
        permissionProtection = permissionProtection(context.packageManager),
    )

    /** Base APK plus splits, for the artifact browser. */
    fun source(ai: ApplicationInfo): ApkSource = ApkSource(partsFor(ai))

    private fun partsFor(ai: ApplicationInfo): List<ApkPart> {
        val parts = ArrayList<ApkPart>()
        val base = ai.publicSourceDir ?: ai.sourceDir
        if (base != null) parts.add(ApkPart(File(base), "base"))
        val splits = ai.splitSourceDirs
        if (splits != null) {
            for (s in splits) {
                val f = File(s)
                parts.add(ApkPart(f, f.name.removeSuffix(".apk")))
            }
        }
        return parts
    }

    private fun installFacts(
        pm: PackageManager,
        packageName: String,
        pi: PackageInfo,
        ai: ApplicationInfo,
    ): InstallFacts = InstallFacts(
        versionName = pi.versionName,
        versionCode = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong(),
        minSdk = ai.minSdkVersion.takeIf { it > 0 },
        targetSdk = ai.targetSdkVersion.takeIf { it > 0 },
        installer = runCatching {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(packageName).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(packageName)
        }.getOrNull(),
        firstInstallMs = pi.firstInstallTime,
        lastUpdateMs = pi.lastUpdateTime,
        // The original path required both a PackageInfo and a public base APK.
        signing = if (ai.publicSourceDir != null) signingFacts(pi) else null,
    )

    private fun signingFacts(pi: PackageInfo): SigningFacts {
        val certBytes: List<ByteArray> = if (Build.VERSION.SDK_INT >= 28) {
            val si = pi.signingInfo
            when {
                si == null -> emptyList()
                si.hasMultipleSigners() -> si.apkContentsSigners?.map { it.toByteArray() } ?: emptyList()
                else -> si.signingCertificateHistory?.map { it.toByteArray() } ?: emptyList()
            }
        } else {
            @Suppress("DEPRECATION")
            pi.signatures?.map { it.toByteArray() } ?: emptyList()
        }
        return SigningFacts(
            certBytes = certBytes,
            multipleSigners = Build.VERSION.SDK_INT >= 28 && pi.signingInfo?.hasMultipleSigners() == true,
            rotationHistory = Build.VERSION.SDK_INT >= 28 && pi.signingInfo?.hasPastSigningCertificates() == true,
        )
    }

    /**
     * The one platform lookup the manifest rules need. Reads the field rather
     * than `getProtection()`: the getter only exists from API 28 and minSdk is
     * 26, so Android 8.0/8.1 would throw NoSuchMethodError.
     */
    private fun permissionProtection(pm: PackageManager): (String) -> String = { name ->
        try {
            val pi = pm.getPermissionInfo(name, 0)
            @Suppress("DEPRECATION")
            val level = pi.protectionLevel
            when (level and 0xF) {
                2 -> if (level and 0x10 != 0) "signature|privileged" else "signature"
                3 -> "dangerous"
                4 -> "normal"
                else -> "protection=0x${level.toString(16)}"
            }
        } catch (_: Exception) {
            "custom/unknown"
        }
    }
}
