package com.flutterguard.app.scan

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Selectable export sections; both JSON and Markdown honor the same set. */
enum class ReportSection {
    OVERVIEW, FINDINGS, ENDPOINTS, ROUTES, DEPENDENCIES, CHANNELS, ARTIFACTS, PERMISSIONS,
}

/**
 * Report serialization: canonical JSON (schema flutterguard/report/1) + Markdown.
 *
 * Defaults are safe: raw secret values never appear (details, URL samples,
 * host names, channels, third-party evidence, permissions, deep links, routes
 * and source paths are scrubbed against the privately retained evidence
 * values; evidence prints its masked snippet). A full value is only written
 * when the caller explicitly opts into `sensitive = true`.
 */
object ReportExport {

    val allSections: Set<ReportSection> = ReportSection.entries.toSet()

    /**
     * Field/value pairs for one evidence row. Default: source/offset/snippet
     * only (source scrubbed against [secrets]). Sensitive: adds the retained
     * value when present. [secrets] also scrubs the snippet (idempotent on
     * already-masked snippets).
     */
    fun evidenceFields(
        e: Evidence,
        sensitive: Boolean = false,
        secrets: Collection<String> = emptyList(),
    ): List<Pair<String, Any>> {
        val fields = ArrayList<Pair<String, Any>>(4)
        fields.add("source" to if (secrets.isEmpty()) e.source else Evidence.scrub(e.source, secrets))
        fields.add("offset" to e.offset)
        fields.add("snippet" to if (secrets.isEmpty()) e.snippet else Evidence.scrub(e.snippet, secrets))
        if (sensitive && e.value != null) fields.add("value" to e.value)
        return fields
    }

    /**
     * The exact tree [toJson] serializes. Exposed for regressions because
     * `org.json` is Android-stubbed in JVM tests; the serializer consumes this
     * same map, so section gating and redaction are tested for real here.
     */
    internal fun payload(
        r: Report,
        sections: Set<ReportSection> = allSections,
        sensitive: Boolean = false,
    ): Map<String, Any?> {
        val secrets = if (sensitive) emptyList() else r.secretValues()
        val safe = if (secrets.isEmpty()) r else r.scrubSecrets(secrets)
        val root = LinkedHashMap<String, Any?>()
        root["schema"] = "flutterguard/report/1"
        root["generatedAt"] = safe.generatedAt

        // The framework object is emitted for either section: an export that
        // selects only DEPENDENCIES must still carry dartDeps.
        if (ReportSection.OVERVIEW in sections || ReportSection.DEPENDENCIES in sections) {
            val fw = LinkedHashMap<String, Any?>()
            if (ReportSection.OVERVIEW in sections) {
                fw["isFlutter"] = safe.framework.isFlutter
                fw["dartVersion"] = safe.framework.dartVersion
                fw["engineVersion"] = safe.framework.engineVersion
                fw["obfuscated"] = safe.framework.obfuscated
                fw["buildMode"] = safe.framework.buildMode
                fw["otherFrameworks"] = safe.framework.otherFrameworks
                fw["kernelBlobBytes"] = safe.framework.kernelBlobBytes
                fw["snapshotBytes"] = safe.framework.snapshotBytes
                fw["engineDebug"] = safe.framework.engineDebug
                fw["libappMissing"] = safe.framework.libappMissing
            }
            if (ReportSection.DEPENDENCIES in sections) fw["dartDeps"] = safe.framework.dartDeps
            root["framework"] = fw
        }

        if (ReportSection.OVERVIEW in sections) {
            val meta = LinkedHashMap<String, Any?>()
            meta["packageName"] = safe.meta.packageName
            meta["label"] = safe.meta.label
            meta["versionName"] = safe.meta.versionName
            meta["versionCode"] = safe.meta.versionCode
            meta["minSdk"] = safe.meta.minSdk
            meta["targetSdk"] = safe.meta.targetSdk
            meta["installer"] = safe.meta.installer
            meta["isSystem"] = safe.meta.isSystem
            meta["sizeBytes"] = safe.meta.sizeBytes
            meta["splitCount"] = safe.meta.splitCount
            meta["abis"] = safe.meta.abis
            meta["baseApkSha256"] = safe.meta.baseSha256
            meta["fileScan"] = safe.meta.fileScan
            meta["nativeLibs"] = safe.meta.nativeLibs.map { l ->
                linkedMapOf(
                    "name" to l.name, "abi" to l.abi, "size" to l.sizeBytes,
                    "sha256Prefix" to l.sha256, "versionMarkers" to l.versionMarkers,
                )
            }
            root["meta"] = meta

            val sig = LinkedHashMap<String, Any?>()
            sig["signerSubject"] = safe.signing.signerSubject
            sig["sha256Fingerprint"] = safe.signing.sha256Fingerprint
            sig["debugCert"] = safe.signing.debugCert
            sig["schemes"] = safe.signing.schemes
            sig["rotationHistory"] = safe.signing.rotationHistory
            sig["validTo"] = safe.signing.validTo
            root["signing"] = sig
            root["stats"] = linkedMapOf(
                "critical" to safe.stats.critical, "high" to safe.stats.high, "medium" to safe.stats.medium,
                "low" to safe.stats.low, "info" to safe.stats.info,
                "stringsScanned" to safe.stats.stringsScanned, "durationMs" to safe.stats.durationMs,
            )
            root["grade"] = safe.grade.toString()
        }

        if (ReportSection.FINDINGS in sections) {
            root["findings"] = safe.findings.map { f ->
                linkedMapOf(
                    "id" to f.id, "title" to f.title, "severity" to f.severity.name,
                    "detail" to f.detail,
                    "evidence" to f.evidence.map { e ->
                        val m = LinkedHashMap<String, Any?>()
                        for ((k, v) in evidenceFields(e, sensitive, secrets)) m[k] = v
                        m
                    },
                    "remediation" to f.remediation, "masvs" to f.masvs,
                )
            }
            root["thirdParty"] = safe.thirdParty.map { linkedMapOf("service" to it.service, "evidence" to it.evidence) }
        }

        if (ReportSection.ENDPOINTS in sections) {
            root["hosts"] = safe.hosts.map { h ->
                linkedMapOf(
                    "host" to h.host, "class" to h.classification,
                    "appOwned" to h.appOwned, "samples" to h.samples,
                )
            }
            // Same section mapping as Markdown: deep links are endpoints.
            root["deepLinks"] = safe.deepLinks.map { d ->
                linkedMapOf(
                    "component" to d.component, "scheme" to d.scheme,
                    "host" to (d.host ?: ""), "autoVerify" to d.autoVerify,
                )
            }
        }
        if (ReportSection.ROUTES in sections) {
            root["routes"] = safe.routes
            root["dartSources"] = safe.dartSources
        }
        if (ReportSection.CHANNELS in sections) {
            root["channels"] = safe.channels.map {
                linkedMapOf("name" to it.name, "origin" to it.origin, "kind" to it.kind)
            }
        }
        if (ReportSection.ARTIFACTS in sections) {
            root["artifacts"] = safe.artifacts.map { a ->
                linkedMapOf(
                    "partIndex" to a.partIndex, "partRole" to a.partRole,
                    "name" to a.displayName(secrets), "compressedBytes" to a.compressedBytes,
                    "uncompressedBytes" to a.uncompressedBytes, "category" to a.category.name,
                )
            }
        }
        if (ReportSection.PERMISSIONS in sections) {
            root["permissions"] = safe.permissions.map {
                linkedMapOf("name" to it.name, "protection" to it.protection, "note" to it.description)
            }
        }
        return root
    }

    private fun toJsonValue(v: Any?): Any = when (v) {
        null -> JSONObject.NULL
        is Map<*, *> -> JSONObject().also { o -> for ((k, x) in v) o.put(k.toString(), toJsonValue(x)) }
        is List<*> -> JSONArray().also { a -> for (x in v) a.put(toJsonValue(x)) }
        else -> v
    }

    fun toJson(
        r: Report,
        sections: Set<ReportSection> = allSections,
        sensitive: Boolean = false,
    ): String = (toJsonValue(payload(r, sections, sensitive)) as JSONObject).toString(2)

    fun toMarkdown(
        r: Report,
        sections: Set<ReportSection> = allSections,
        sensitive: Boolean = false,
    ): String {
        val secrets = if (sensitive) emptyList() else r.secretValues()
        val safe = if (secrets.isEmpty()) r else r.scrubSecrets(secrets)
        return buildString {
            appendLine("# FlutterGuard report — ${safe.meta.label} (`${safe.meta.packageName}`)")
            appendLine()
            if (sensitive) {
                appendLine("> **SENSITIVE EXPORT** — contains raw secret values; share only with explicit intent.")
            } else {
                appendLine("_Sensitive values are redacted; enable the explicit sensitive export to reveal them._")
            }
            appendLine()

            if (ReportSection.OVERVIEW in sections) {
                appendLine("- Version: ${safe.meta.versionName ?: "?"} (${safe.meta.versionCode}) · SDK ${safe.meta.minSdk ?: "?"}→${safe.meta.targetSdk ?: "?"} · size ${safe.meta.sizeBytes / 1024 / 1024} MB · ${safe.meta.splitCount} split(s) · ABI ${safe.meta.abis.joinToString()}")
                if (safe.meta.fileScan) {
                    appendLine("- Source: **picked APK file** — package identity comes from the manifest, not an installed app.")
                }
                appendLine("- Framework: ${if (safe.framework.isFlutter) "Flutter ${safe.framework.dartVersion ?: ""} (${safe.framework.buildMode ?: "?"}, obfuscated=${safe.framework.obfuscated})" else safe.framework.otherFrameworks.joinToString().ifEmpty { "native" }}")
                appendLine("- Signing: ${safe.signing.schemes.joinToString("/").ifEmpty { "?" }}${if (safe.signing.debugCert) " · DEBUG CERT" else ""} · SHA-256 ${safe.signing.sha256Fingerprint?.take(16)}…")
                appendLine("- Grade: **${safe.grade}** — ${safe.stats.critical} critical, ${safe.stats.high} high, ${safe.stats.medium} medium, ${safe.stats.low} low, ${safe.stats.info} info (${safe.stats.stringsScanned} strings scanned in ${safe.stats.durationMs / 1000}s)")
                appendLine()
            }

            if (ReportSection.FINDINGS in sections) {
                appendLine("## Findings")
                for (f in safe.findings) {
                    appendLine()
                    appendLine("### [${f.severity}] ${f.title}  `${f.id}`")
                    appendLine(f.detail)
                    for (e in f.evidence.take(3)) {
                        appendLine("> `${e.source}@${e.offset}`: `${e.snippet}`")
                        if (sensitive && e.value != null) appendLine("> value: `${e.value}`")
                    }
                    appendLine("_Remediation: ${f.remediation}_ ${f.masvs.joinToString(" ") { "`$it`" }}")
                }
                appendLine()
                appendLine("## Third-party services (${safe.thirdParty.size})")
                safe.thirdParty.forEach { appendLine("- ${it.service}: ${it.evidence.joinToString()}") }
                appendLine()
            }

            if (ReportSection.ENDPOINTS in sections) {
                appendLine("## Endpoints (${safe.hosts.size})")
                safe.hosts.take(60).forEach {
                    appendLine("- `${it.host}` — ${it.classification}${if (it.appOwned) " · app-owned" else ""}")
                    it.samples.forEach { s -> appendLine("  - $s") }
                }
                if (safe.deepLinks.isNotEmpty()) {
                    appendLine()
                    appendLine("## Deep links")
                    safe.deepLinks.forEach { appendLine("- ${it.scheme}://${it.host ?: "*"} → ${it.component}${if (it.autoVerify) " (autoVerify)" else ""}") }
                }
                appendLine()
            }

            if (ReportSection.ROUTES in sections) {
                appendLine("## Candidate routes (${safe.routes.size})")
                if (safe.routes.isEmpty()) appendLine("_none recoverable_") else safe.routes.forEach { appendLine("- `$it`") }
                appendLine()
                if (safe.dartSources.isNotEmpty()) {
                    appendLine("## Dart source files (${safe.dartSources.size})")
                    safe.dartSources.forEach { appendLine("- `$it`") }
                    appendLine()
                }
            }

            if (ReportSection.DEPENDENCIES in sections) {
                appendLine("## Dart dependencies (${safe.framework.dartDeps.size})")
                if (safe.framework.dartDeps.isEmpty()) {
                    appendLine("_none recoverable_")
                } else {
                    safe.framework.dartDeps.forEach { dep ->
                        if (PubPackage.isValid(dep)) {
                            appendLine("- `$dep` — candidate pub.dev package name (version/license unknown)")
                        } else {
                            appendLine("- `$dep` — recovered name, not a valid pub.dev package (no link)")
                        }
                    }
                }
                appendLine()
            }

            if (ReportSection.CHANNELS in sections) {
                appendLine("## Platform channels (${safe.channels.size})")
                safe.channels.take(40).forEach { appendLine("- ${it.name} (${it.kind}, ${it.origin})") }
                appendLine()
            }

            if (ReportSection.ARTIFACTS in sections) {
                appendLine("## Artifacts (${safe.artifacts.size})")
                safe.artifacts.take(256).forEach {
                    appendLine(
                        "- ${it.displayName(secrets)} — ${it.category} · part ${it.partRole} (#${it.partIndex}) · " +
                            "${it.compressedBytes}/${it.uncompressedBytes} B",
                    )
                }
                appendLine()
            }

            if (ReportSection.PERMISSIONS in sections) {
                appendLine("## Permissions (${safe.permissions.size})")
                safe.permissions.forEach { appendLine("- ${it.name} [${it.protection}]${if (it.description.isNotBlank()) " — ${it.description}" else ""}") }
            }
        }
    }

    /** Explicit format dispatch: unknown extensions fail loudly, never fall through. */
    fun render(
        r: Report,
        ext: String,
        sections: Set<ReportSection> = allSections,
        sensitive: Boolean = false,
    ): String = when (ext.lowercase()) {
        "json" -> toJson(r, sections, sensitive)
        "md", "markdown" -> toMarkdown(r, sections, sensitive)
        else -> throw IllegalArgumentException("unsupported export format: $ext")
    }

    fun writeFile(
        context: android.content.Context,
        r: Report,
        ext: String,
        sections: Set<ReportSection> = allSections,
        sensitive: Boolean = false,
    ): File {
        val dir = File(context.cacheDir, "exports").apply { mkdirs() }
        val prefix = "${r.meta.packageName.replace('.', '_')}_report_"
        val f = File.createTempFile(prefix, ".$ext", dir)
        f.writeText(render(r, ext, sections, sensitive))
        return f
    }
}
