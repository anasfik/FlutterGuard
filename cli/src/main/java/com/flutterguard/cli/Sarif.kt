package com.flutterguard.cli

import com.flutterguard.app.scan.Evidence
import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.FindingKind
import com.flutterguard.app.scan.Report
import com.flutterguard.app.scan.Severity
import com.flutterguard.app.scan.secretValues
import org.json.JSONArray
import org.json.JSONObject

/**
 * SARIF 2.1.0 projection of a scanned artifact.
 *
 * Honest scope: the location is the APK itself, so no `region`/line is ever
 * emitted. Messages and fingerprint sources come from display-ready report
 * fields (already scrubbed) and are scrubbed again here; evidence snippets and
 * retained values never enter the document, and fingerprints are built from
 * rule id plus evidence source only — never from a value or its hash.
 */
object Sarif {

    const val VERSION = "2.1.0"
    const val SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    const val FINGERPRINT_KEY = "flutterguardEvidence/v1"
    const val INFORMATION_URI = "https://flutterguard.dev/"

    private val rank = mapOf("error" to 0, "warning" to 1, "note" to 2)

    /** null = not reported (informational inventory is omitted by default). */
    fun level(f: Finding): String? = when (f.kind) {
        FindingKind.INFORMATIONAL -> null
        FindingKind.SUSPECTED -> "note"
        FindingKind.CONFIRMED -> when (f.severity) {
            Severity.CRITICAL, Severity.HIGH -> "error"
            Severity.MEDIUM, Severity.LOW -> "warning"
            Severity.INFO -> "note"
        }
    }

    fun document(report: Report, apkUri: String): String {
        val scrub = Evidence.prepared(report.secretValues())
        val reported = report.findings.filter { level(it) != null }
        val ruleIds = reported.map { it.id }.distinct()
        val index = ruleIds.withIndex().associate { (i, id) -> id to i }

        val rules = JSONArray()
        for (id in ruleIds) {
            val group = reported.filter { it.id == id }
            val level = group.mapNotNull { level(it) }.minByOrNull { rank.getValue(it) } ?: "note"
            rules.put(
                JSONObject()
                    .put("id", id)
                    .put("shortDescription", JSONObject().put("text", scrub(group.first().title)))
                    .put("help", JSONObject().put("text", scrub(group.first().remediation)))
                    .put("defaultConfiguration", JSONObject().put("level", level)),
            )
        }

        val results = JSONArray()
        for (f in reported) {
            val source = f.evidence.firstOrNull()?.source?.let(scrub) ?: ""
            results.put(
                JSONObject()
                    .put("ruleId", f.id)
                    .put("ruleIndex", index.getValue(f.id))
                    .put("level", level(f))
                    .put("message", JSONObject().put("text", scrub(f.detail).ifBlank { scrub(f.title) }))
                    .put("partialFingerprints", JSONObject().put(FINGERPRINT_KEY, "${f.id}|$source"))
                    .put(
                        "locations",
                        JSONArray().put(
                            JSONObject().put(
                                "physicalLocation",
                                JSONObject().put("artifactLocation", JSONObject().put("uri", apkUri)),
                            ),
                        ),
                    ),
            )
        }

        val driver = JSONObject()
            .put("name", "FlutterGuard")
            .put("informationUri", INFORMATION_URI)
            .put("rules", rules)
        val run = JSONObject()
            .put("tool", JSONObject().put("driver", driver))
            .put("results", results)
        return JSONObject()
            .put("version", VERSION)
            .put("\$schema", SCHEMA)
            .put("runs", JSONArray().put(run))
            .toString(2)
    }

    /** Structural gate before publication: parseable, required keys, resolvable rules. */
    fun validate(json: String) {
        val root = runCatching { JSONObject(json) }.getOrElse {
            throw IllegalArgumentException("SARIF is not valid JSON")
        }
        require(root.optString("version") == VERSION) { "SARIF version is not $VERSION" }
        require(root.optString("\$schema") == SCHEMA) { "SARIF \$schema missing" }
        val runs = root.optJSONArray("runs") ?: throw IllegalArgumentException("SARIF runs missing")
        require(runs.length() > 0) { "SARIF runs is empty" }
        val run = runs.getJSONObject(0)
        val driver = run.optJSONObject("tool")?.optJSONObject("driver")
            ?: throw IllegalArgumentException("SARIF tool.driver missing")
        require(driver.optString("name") == "FlutterGuard") { "SARIF driver name missing" }
        val rules = driver.optJSONArray("rules") ?: throw IllegalArgumentException("SARIF rules missing")
        val ids = (0 until rules.length()).map { rules.getJSONObject(it).getString("id") }.toSet()
        require(ids.size == rules.length()) { "SARIF rules repeat an id" }
        val results = run.optJSONArray("results") ?: throw IllegalArgumentException("SARIF results missing")
        for (i in 0 until results.length()) {
            val r = results.getJSONObject(i)
            require(r.getString("ruleId") in ids) { "SARIF result references an unknown rule" }
            require(r.getInt("ruleIndex") in 0 until rules.length()) { "SARIF result ruleIndex out of range" }
            require(r.optString("level") in setOf("error", "warning", "note", "none")) { "SARIF result level invalid" }
            require(r.optJSONObject("message")?.optString("text")?.isNotBlank() == true) { "SARIF result message missing" }
            val uri = r.optJSONArray("locations")
                ?.optJSONObject(0)
                ?.optJSONObject("physicalLocation")
                ?.optJSONObject("artifactLocation")
                ?.optString("uri")
            require(!uri.isNullOrBlank()) { "SARIF result artifact location missing" }
        }
    }
}
