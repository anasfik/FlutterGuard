package com.flutterguard.app.scan

/**
 * Version-diff audits: every scan writes a compact snapshot next to the JSON
 * report, and the next scan of the same package is compared against it. This is
 * the only signal a static artifact can give you that a human reviewer cannot
 * get from a single scan — what the update changed.
 */
object History {

    private const val HOSTS = "hosts:"
    private const val ROUTES = "routes:"
    private const val FINDINGS = "findings:"
    private const val DEPS = "deps:"
    private const val VERSION = "version:"

    /** Stable, line-oriented snapshot. Values are sorted so diffs stay quiet. */
    fun snapshot(r: Report): String = buildString {
        appendLine(VERSION + "${r.meta.versionName} (${r.meta.versionCode})")
        appendLine(HOSTS + r.hosts.map { it.host }.sorted().joinToString("|"))
        appendLine(ROUTES + r.routes.sorted().joinToString("|"))
        appendLine(FINDINGS + r.findings.map { "${it.severity}|${it.id}" }.distinct().sorted().joinToString("|"))
        appendLine(DEPS + r.framework.dartDeps.sorted().joinToString("|"))
    }

    /**
     * Human-readable delta between two snapshots. `+` appeared, `-` disappeared,
     * `~` changed in place (version only).
     */
    fun diff(old: String, new: String): List<String> {
        val a = parse(old)
        val b = parse(new)
        if (a.isEmpty() || b.isEmpty()) return emptyList()
        val out = ArrayList<String>()

        val vOld = a[VERSION]?.firstOrNull()
        val vNew = b[VERSION]?.firstOrNull()
        if (vOld != null && vNew != null && vOld != vNew) out += "~ version $vOld → $vNew"

        fun compare(key: String, label: String, limit: Int) {
            val before = a[key].orEmpty().toSet()
            val after = b[key].orEmpty().toSet()
            (after - before).sorted().take(limit).forEach { out += "+ $label $it" }
            (before - after).sorted().take(limit).forEach { out += "- $label $it" }
        }
        compare(HOSTS, "host", 12)
        compare(ROUTES, "route", 12)
        compare(FINDINGS, "finding", 12)
        compare(DEPS, "dep", 8)

        val added = (b[FINDINGS].orEmpty().toSet()) - (a[FINDINGS].orEmpty().toSet())
        val removed = (a[FINDINGS].orEmpty().toSet()) - (b[FINDINGS].orEmpty().toSet())
        if (out.size > 40) {
            val extra = out.size - 40
            out.subList(40, out.size).clear()
            out += "… $extra more (see JSON export)"
        }
        if (added.isEmpty() && removed.isEmpty() && out.none { it.startsWith("~") }) {
            out += "no change in hosts, routes, findings or dependencies"
        }
        return out
    }

    private fun parse(text: String): Map<String, List<String>> {
        val map = HashMap<String, List<String>>()
        for (line in text.lineSequence()) {
            val key = when {
                line.startsWith(VERSION) -> VERSION
                line.startsWith(HOSTS) -> HOSTS
                line.startsWith(ROUTES) -> ROUTES
                line.startsWith(FINDINGS) -> FINDINGS
                line.startsWith(DEPS) -> DEPS
                else -> continue
            }
            val body = line.removePrefix(key)
            map[key] = if (body.isBlank()) emptyList() else body.split('|')
        }
        return map
    }
}
