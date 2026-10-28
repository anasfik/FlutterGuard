package com.flutterguard.app.scan

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Report serialization: canonical JSON (schema flutterguard/report/1) + Markdown. */
object ReportExport {

    fun toJson(r: Report): String {
        val root = JSONObject()
        root.put("schema", "flutterguard/report/1")
        root.put("generatedAt", r.generatedAt)
        val meta = JSONObject()
            .put("packageName", r.meta.packageName)
            .put("label", r.meta.label)
            .put("versionName", r.meta.versionName ?: JSONObject.NULL)
            .put("versionCode", r.meta.versionCode)
            .put("minSdk", r.meta.minSdk ?: JSONObject.NULL)
            .put("targetSdk", r.meta.targetSdk ?: JSONObject.NULL)
            .put("installer", r.meta.installer ?: JSONObject.NULL)
            .put("isSystem", r.meta.isSystem)
            .put("sizeBytes", r.meta.sizeBytes)
            .put("splitCount", r.meta.splitCount)
            .put("abis", JSONArray(r.meta.abis))
            .put("baseApkSha256", r.meta.baseSha256)
        val libs = JSONArray()
        for (l in r.meta.nativeLibs) {
            libs.put(JSONObject().put("name", l.name).put("abi", l.abi).put("size", l.sizeBytes)
                .put("sha256Prefix", l.sha256).put("versionMarkers", JSONArray(l.versionMarkers)))
        }
        meta.put("nativeLibs", libs)
        root.put("meta", meta)

        val fw = JSONObject()
            .put("isFlutter", r.framework.isFlutter)
            .put("dartVersion", r.framework.dartVersion ?: JSONObject.NULL)
            .put("engineVersion", r.framework.engineVersion ?: JSONObject.NULL)
            .put("obfuscated", r.framework.obfuscated ?: JSONObject.NULL)
            .put("buildMode", r.framework.buildMode ?: JSONObject.NULL)
            .put("otherFrameworks", JSONArray(r.framework.otherFrameworks))
            .put("dartDeps", JSONArray(r.framework.dartDeps))
            .put("kernelBlobBytes", r.framework.kernelBlobBytes ?: JSONObject.NULL)
            .put("snapshotBytes", r.framework.snapshotBytes ?: JSONObject.NULL)
            .put("engineDebug", r.framework.engineDebug)
            .put("libappMissing", r.framework.libappMissing)
        root.put("framework", fw)

        val sig = JSONObject()
            .put("signerSubject", r.signing.signerSubject ?: JSONObject.NULL)
            .put("sha256Fingerprint", r.signing.sha256Fingerprint ?: JSONObject.NULL)
            .put("debugCert", r.signing.debugCert)
            .put("schemes", JSONArray(r.signing.schemes))
            .put("rotationHistory", r.signing.rotationHistory)
            .put("validTo", r.signing.validTo ?: JSONObject.NULL)
        root.put("signing", sig)

        val findings = JSONArray()
        for (f in r.findings) {
            val ev = JSONArray()
            for (e in f.evidence) ev.put(JSONObject().put("source", e.source).put("offset", e.offset).put("snippet", e.snippet))
            findings.put(
                JSONObject().put("id", f.id).put("title", f.title).put("severity", f.severity.name)
                    .put("detail", f.detail).put("evidence", ev)
                    .put("remediation", f.remediation).put("masvs", JSONArray(f.masvs)),
            )
        }
        root.put("findings", findings)

        root.put("hosts", JSONArray(r.hosts.map {
            JSONObject().put("host", it.host).put("class", it.classification)
                .put("appOwned", it.appOwned).put("samples", JSONArray(it.samples))
        }))
        root.put("channels", JSONArray(r.channels.map { JSONObject().put("name", it.name).put("origin", it.origin).put("kind", it.kind) }))
        root.put("thirdParty", JSONArray(r.thirdParty.map { JSONObject().put("service", it.service).put("evidence", JSONArray(it.evidence)) }))
        root.put("routes", JSONArray(r.routes))
        root.put("dartSources", JSONArray(r.dartSources))
        root.put("permissions", JSONArray(r.permissions.map {
            JSONObject().put("name", it.name).put("protection", it.protection).put("note", it.description)
        }))
        root.put("deepLinks", JSONArray(r.deepLinks.map {
            JSONObject().put("component", it.component).put("scheme", it.scheme).put("host", it.host ?: "").put("autoVerify", it.autoVerify)
        }))

        root.put("stats", JSONObject()
            .put("critical", r.stats.critical).put("high", r.stats.high).put("medium", r.stats.medium)
            .put("low", r.stats.low).put("info", r.stats.info)
            .put("stringsScanned", r.stats.stringsScanned).put("durationMs", r.stats.durationMs))
        root.put("grade", r.grade.toString())
        return root.toString(2)
    }

    fun toMarkdown(r: Report): String = buildString {
        appendLine("# FlutterGuard report — ${r.meta.label} (`${r.meta.packageName}`)")
        appendLine()
        appendLine("- Version: ${r.meta.versionName ?: "?"} (${r.meta.versionCode}) · SDK ${r.meta.minSdk ?: "?"}→${r.meta.targetSdk ?: "?"} · size ${r.meta.sizeBytes / 1024 / 1024} MB · ${r.meta.splitCount} split(s) · ABI ${r.meta.abis.joinToString()}")
        appendLine("- Framework: ${if (r.framework.isFlutter) "Flutter ${r.framework.dartVersion ?: ""} (${r.framework.buildMode ?: "?"}, obfuscated=${r.framework.obfuscated})" else r.framework.otherFrameworks.joinToString().ifEmpty { "native" }}")
        appendLine("- Signing: ${r.signing.schemes.joinToString("/").ifEmpty { "?" }}${if (r.signing.debugCert) " · DEBUG CERT" else ""} · SHA-256 ${r.signing.sha256Fingerprint?.take(16)}…")
        appendLine("- Grade: **${r.grade}** — ${r.stats.critical} critical, ${r.stats.high} high, ${r.stats.medium} medium, ${r.stats.low} low, ${r.stats.info} info (${r.stats.stringsScanned} strings scanned in ${r.stats.durationMs / 1000}s)")
        appendLine()
        appendLine("## Findings")
        for (f in r.findings) {
            appendLine()
            appendLine("### [${f.severity}] ${f.title}  `${f.id}`")
            appendLine(f.detail)
            for (e in f.evidence.take(3)) appendLine("> `${e.source}@${e.offset}`: `${e.snippet}`")
            appendLine("_Remediation: ${f.remediation}_ ${f.masvs.joinToString(" ") { "`$it`" }}")
        }
        appendLine()
        appendLine("## Endpoints (${r.hosts.size})")
        r.hosts.take(60).forEach {
            appendLine("- `${it.host}` — ${it.classification}${if (it.appOwned) " · app-owned" else ""}")
            it.samples.forEach { s -> appendLine("  - $s") }
        }
        appendLine()
        if (r.routes.isNotEmpty()) {
            appendLine("## API routes (${r.routes.size})")
            r.routes.forEach { appendLine("- `$it`") }
            appendLine()
        }
        if (r.dartSources.isNotEmpty()) {
            appendLine("## Dart source files (${r.dartSources.size})")
            r.dartSources.forEach { appendLine("- `$it`") }
            appendLine()
        }
        appendLine("## Dart dependencies (${r.framework.dartDeps.size})")
        appendLine(r.framework.dartDeps.joinToString(", ") { "`$it`" }.ifEmpty { "_none recoverable_" })
        appendLine()
        appendLine("## Platform channels (${r.channels.size})")
        r.channels.take(40).forEach { appendLine("- ${it.name} (${it.kind}, ${it.origin})") }
        appendLine()
        appendLine("## Third-party services (${r.thirdParty.size})")
        r.thirdParty.forEach { appendLine("- ${it.service}: ${it.evidence.joinToString()}") }
        appendLine()
        appendLine("## Permissions (${r.permissions.size})")
        r.permissions.forEach { appendLine("- ${it.name} [${it.protection}]${if (it.description.isNotBlank()) " — ${it.description}" else ""}") }
        if (r.deepLinks.isNotEmpty()) {
            appendLine()
            appendLine("## Deep links")
            r.deepLinks.forEach { appendLine("- ${it.scheme}://${it.host ?: "*"} → ${it.component}${if (it.autoVerify) " (autoVerify)" else ""}") }
        }
    }

    fun writeFile(context: android.content.Context, r: Report, ext: String): File {
        val dir = File(context.cacheDir, "exports").apply { mkdirs() }
        val name = "${r.meta.packageName.replace('.', '_')}_report.$ext"
        val f = File(dir, name)
        f.writeText(if (ext == "json") toJson(r) else toMarkdown(r))
        return f
    }
}
