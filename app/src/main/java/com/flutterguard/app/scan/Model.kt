package com.flutterguard.app.scan

/** Severity of a finding. Ordered from worst to informational. */
enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

/** Where a string/secret came from, e.g. "lib/arm64-v8a/libapp.so" or "classes2.dex". */
data class Provenance(val source: String, val offset: Long = 0)

data class Evidence(val source: String, val offset: Long, val snippet: String) {
    companion object {
        /** Redact the middle of a secret so reports can be shared safely. */
        fun redact(s: String): String = when {
            s.length <= 12 -> s.take(4) + "…" + s.takeLast(2)
            else -> s.take(8) + "…" + s.takeLast(4)
        }
    }
}

data class Finding(
    val id: String,
    val title: String,
    val severity: Severity,
    val detail: String,
    val evidence: List<Evidence>,
    val remediation: String,
    val masvs: List<String> = emptyList(),
)

data class AppMeta(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val installer: String?,
    val firstInstallMs: Long,
    val lastUpdateMs: Long,
    val isSystem: Boolean,
    val sizeBytes: Long,
    val splitCount: Int,
    val abis: List<String>,
    val nativeLibs: List<NativeLib>,
    val baseSha256: String,
)

data class NativeLib(val name: String, val abi: String, val sizeBytes: Long, val sha256: String?, val versionMarkers: List<String>)

data class FrameworkInfo(
    val isFlutter: Boolean,
    val engineVersion: String? = null,
    val dartVersion: String? = null,
    val obfuscated: Boolean? = null,
    val buildMode: String? = null,
    val otherFrameworks: List<String> = emptyList(),
    val dartDeps: List<String> = emptyList(),
    /** Size of assets/flutter_assets/kernel_blob.bin when present (debug/JIT builds). */
    val kernelBlobBytes: Long? = null,
    /** Combined size of isolate/vm snapshot data when present. */
    val snapshotBytes: Long? = null,
    /** Engine ships debug-only bits (Khronos validation layer, no AOT app snapshot). */
    val engineDebug: Boolean = false,
    /** Flutter assets exist but no libapp.so: the Dart code is not AOT-compiled. */
    val libappMissing: Boolean = false,
)

data class SigningInfo(
    val signerSubject: String?,
    val signerIssuer: String?,
    val sha256Fingerprint: String?,
    val debugCert: Boolean,
    val multipleSigners: Boolean,
    val rotationHistory: Boolean,
    val validFrom: String?,
    val validTo: String?,
    val sigAlgorithm: String?,
    val schemes: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
)

data class HostInfo(
    val host: String,
    val classification: String,
    /** Up to three sample URLs seen for this host, query strings redacted. */
    val samples: List<String> = emptyList(),
    /** Host shares a token with the app package/label — likely the app's own backend. */
    val appOwned: Boolean = false,
)

data class ChannelInfo(val name: String, val origin: String, val kind: String)

data class ThirdPartyHit(val service: String, val evidence: List<String>)

data class ReportStats(
    val critical: Int, val high: Int, val medium: Int, val low: Int, val info: Int,
    val stringsScanned: Long, val durationMs: Long,
)

data class Report(
    val meta: AppMeta,
    val framework: FrameworkInfo,
    val signing: SigningInfo,
    val findings: List<Finding>,
    val hosts: List<HostInfo>,
    val channels: List<ChannelInfo>,
    val thirdParty: List<ThirdPartyHit>,
    val permissions: List<PermissionHit>,
    val deepLinks: List<DeepLink>,
    val stats: ReportStats,
    val grade: Char,
    /** API route paths recovered from the Dart kernel/libapp.so string layer. */
    val routes: List<String> = emptyList(),
    /** Dart source file paths recovered from a debug/JIT kernel. */
    val dartSources: List<String> = emptyList(),
    val generatedAt: Long = System.currentTimeMillis(),
) {
    val bySeverity: Map<Severity, List<Finding>> get() = findings.groupBy { it.severity }
}

data class PermissionHit(val name: String, val protection: String, val description: String)

data class DeepLink(val component: String, val scheme: String, val host: String?, val autoVerify: Boolean)

fun gradeOf(c: Int, h: Int, m: Int, l: Int): Char {
    if (c > 0) return 'F'
    val score = h * 25 + m * 8 + l * 2
    return when {
        score == 0 -> 'A'
        score <= 10 -> 'B'
        score <= 45 -> 'C'
        score <= 110 -> 'D'
        else -> 'F'
    }
}
