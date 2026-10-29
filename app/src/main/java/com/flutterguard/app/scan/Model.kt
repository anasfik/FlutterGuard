package com.flutterguard.app.scan

/** Severity of a finding. Ordered from worst to informational. */
enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

/** Where a string/secret came from, e.g. "lib/arm64-v8a/libapp.so" or "classes2.dex". */
data class Provenance(val source: String, val offset: Long = 0)

/**
 * One observed match.
 *
 * [snippet] is safe to show and share by construction: for sensitive rules it
 * never contains characters of the matched value (see [mask]). The complete
 * match is kept in [value] for explicit reveal/copy only — it is in-memory
 * state, never serialized into external reports, history or logs; after
 * process death a rescan recovers it.
 */
data class Evidence(val source: String, val offset: Long, val snippet: String, val value: String? = null) {
    companion object {
        /** Placeholder for a sensitive value: reveals length only, never characters. */
        fun mask(s: String): String = "[${s.length} chars hidden]"

        /**
         * Prepare one scrubber for repeated use (a report render has many fields
         * and one stable secret set). Equivalent to [scrub] per call, without
         * re-filtering/sorting the secrets for every field.
         *
         * ponytail: one prep per render, then O(fields × occurrences); the
         * alternation-regex variant is available if profiling shows this matters.
         */
        fun prepared(secrets: Collection<String>): (String) -> String {
            val distinct = secrets.filter { it.isNotEmpty() }.distinct()
            if (distinct.isEmpty()) return { it }
            val short = distinct.filter { it.length < 8 }
            val long = distinct.filter { it.length >= 8 }.sortedByDescending { it.length }
            return { text ->
                when {
                    text.isEmpty() -> text
                    // Fail closed: a value too short to replace precisely masks the
                    // whole field rather than leaving characters raw.
                    short.any { text.contains(it) } -> mask(text)
                    else -> long.fold(text) { acc, s -> acc.replace(s, mask(s)) }
                }
            }
        }

        /**
         * Replace every occurrence of each secret in [text] with its [mask].
         * Longest secrets are applied first so a short secret cannot break a
         * longer one. No count cap: every supplied value is processed.
         * Fail-closed for values too short to replace precisely (< 8 chars):
         * if one occurs, the whole text becomes its mask rather than leaking.
         */
        fun scrub(text: String, secrets: Collection<String>): String = prepared(secrets)(text)
    }
}

/** Role of a typed APK entry for the artifact browser. */
enum class ArtifactCategory {
    MANIFEST, DEX, NATIVE_LIB, KERNEL, CONFIG, KEY_MATERIAL, SIGNING, ASSET, RESOURCE, OTHER,
}

/**
 * Typed inventory row for one zip entry. Split APKs may repeat the same path,
 * so [partIndex]/[partRole] carry the provenance that a bare name cannot.
 * Sizes are as recorded in the zip central directory (-1 = unknown).
 */
data class ArtifactEntry(
    val partIndex: Int,
    val partRole: String,
    val name: String,
    val compressedBytes: Long,
    val uncompressedBytes: Long,
    val category: ArtifactCategory,
)

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
    /** Candidate route paths (API prefixes and named navigation) recovered as
     *  literal strings. Candidates only: no navigation relationship is claimed. */
    val routes: List<String> = emptyList(),
    /** Dart source file paths recovered from a debug/JIT kernel. */
    val dartSources: List<String> = emptyList(),
    /** Notable APK entries captured at scan time (bounded), with part provenance. */
    val artifacts: List<ArtifactEntry> = emptyList(),
    val generatedAt: Long = System.currentTimeMillis(),
) {
    val bySeverity: Map<Severity, List<Finding>> get() = findings.groupBy { it.severity }
}

/**
 * Display name for an artifact row: artifact names are identity (used to look
 * up the exact entry in the owning APK part), so [ArtifactEntry.name] stays raw.
 * Render this helper instead whenever a detected secret could be embedded in
 * the path. [secrets] is required on purpose: pass [Report.secretValues] so the
 * safe path cannot silently fall back to the raw name.
 */
fun ArtifactEntry.displayName(secrets: Collection<String>): String =
    Evidence.scrub(name, secrets)

/**
 * Every privately retained sensitive value (public identifiers, where snippet
 * equals value, are excluded). The public source for display-time scrubbing:
 * exporters, history and Task 3 UI all use this same set.
 */
fun Report.secretValues(): List<String> =
    findings.flatMap { f ->
        f.evidence.filter { it.value != null && it.snippet != it.value }.mapNotNull { it.value }
    }.distinct()

/**
 * Replace every detected secret in display-ready fields (finding details,
 * evidence sources and snippets, host names and samples, channels, third-party
 * evidence, permissions, deep links, routes, source paths) with its mask, so
 * neither reports, history nor the UI can leak a raw value outside the private
 * [Evidence.value] channel. Idempotent; safelisted public identifiers are not
 * in the secret set. Artifact names stay raw for lookup and must be rendered
 * through [displayName] with [secretValues].
 */
fun Report.scrubSecrets(secrets: Collection<String>): Report {
    if (secrets.isEmpty()) return this
    val scrub = Evidence.prepared(secrets)
    return copy(
        findings = findings.map { f ->
            f.copy(
                detail = scrub(f.detail),
                evidence = f.evidence.map { e -> e.copy(source = scrub(e.source), snippet = scrub(e.snippet)) },
            )
        },
        hosts = hosts.map { h ->
            h.copy(host = scrub(h.host), samples = h.samples.map { scrub(it) })
        },
        channels = channels.map { c ->
            c.copy(name = scrub(c.name), origin = scrub(c.origin))
        },
        thirdParty = thirdParty.map { t -> t.copy(evidence = t.evidence.map { scrub(it) }) },
        permissions = permissions.map { p -> p.copy(description = scrub(p.description)) },
        deepLinks = deepLinks.map { d ->
            d.copy(
                component = scrub(d.component),
                scheme = scrub(d.scheme),
                host = d.host?.let { scrub(it) },
            )
        },
        routes = routes.map { scrub(it) },
        dartSources = dartSources.map { scrub(it) },
    )
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
