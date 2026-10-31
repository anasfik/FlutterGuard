package com.flutterguard.app.scan

/**
 * Version-diff audits: every scan writes a compact snapshot next to the JSON
 * report, and the next scan of the same package is compared against it. This is
 * the only signal a static artifact can give you that a human reviewer cannot
 * get from a single scan — what the update changed.
 */
object History {

    private const val STAMP = "stamp:"
    private const val HOSTS = "hosts:"
    private const val ROUTES = "routes:"
    private const val FINDINGS = "findings:"
    private const val DEPS = "deps:"
    private const val VERSION = "version:"

    /**
     * Stable, line-oriented snapshot. Values are sorted so diffs stay quiet.
     * The `stamp:` header carries the version/timestamp/grade of this scan for
     * the versioned log; [diff] ignores it and old snapshots without it still
     * parse.
     */
    fun snapshot(r: Report): String = buildString {
        appendLine(STAMP + "${r.generatedAt}|${r.meta.versionName ?: "?"}|${r.meta.versionCode}|${r.grade}")
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

        if (out.size > 40) {
            val extra = out.size - 39
            out.subList(39, out.size).clear()
            out += "… $extra more (see JSON export)"
        }
        if (out.isEmpty()) {
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
            val items = if (body.isBlank()) emptyList() else body.split('|')
            // Findings are stored as severity|id pairs, so the field separator
            // collides with the pair separator. Fold pairs back together; older
            // snapshots on disk were written that way and must still diff.
            map[key] = if (key == FINDINGS && items.size % 2 == 0) {
                items.chunked(2).map { it.joinToString("|") }
            } else {
                items
            }
        }
        return map
    }
}

/** One retained scan of an app, stamped with the version it was taken from. */
data class ScanLogEntry(
    val stampedAtMs: Long,
    val versionName: String,
    val versionCode: Long,
    val grade: Char?,
    val snapshot: String,
)

/**
 * Versioned per-app scan log stored inside the existing `.hist` file: blocks
 * separated by a marker, oldest first, bounded to [MAX_ENTRIES]. It is the same
 * atomic [ReportFiles] write, not a second persistence layer, and it is plain
 * text so an exported or pulled report stays readable by hand.
 */
object ScanLog {

    /** Retained scans per app; enough to see update-to-update deltas. */
    const val MAX_ENTRIES = 20

    private const val SEPARATOR = "\n#---\n"
    private const val BLOCK_MARKER = "#---"
    private const val STAMP = "stamp:"
    private const val VERSION = "version:"
    private val versionLine = Regex("""^version:(.*?)\s*\((\d+)\)\s*$""")

    /** Appends [snapshot] to the log text, deduplicating an identical re-append and keeping the newest entries. */
    fun append(existingText: String?, snapshot: String): String {
        val block = encodeBlock(snapshot.trim())
        if (block.isEmpty()) return existingText.orEmpty()
        val blocks = (splitBlocks(existingText) + block).distinct()
        return blocks.takeLast(MAX_ENTRIES).joinToString(SEPARATOR)
    }

    /** Oldest first; tolerates an empty file and the legacy single-snapshot format. */
    fun decode(text: String?): List<ScanLogEntry> =
        splitBlocks(text).mapNotNull { block ->
            val parsed = parse(block)
            parsed
        }

    /** Human diff against the previous entry of the same versionCode, empty when there is none. */
    fun diffForPreviousVersion(entries: List<ScanLogEntry>, index: Int): List<String> {
        val current = entries.getOrNull(index) ?: return emptyList()
        val previous = (index - 1 downTo 0)
            .map { entries[it] }
            .firstOrNull { it.versionCode == current.versionCode && it.versionName == current.versionName }
            ?: return emptyList()
        return History.diff(previous.snapshot, current.snapshot)
    }

    private fun splitBlocks(text: String?): List<String> =
        text.orEmpty().split(SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }

    /**
     * Artifact text is attacker-controlled and may contain the block marker.
     * Escape backslashes, then the marker, so one snapshot can never split.
     */
    private fun encodeBlock(text: String): String =
        text.replace("\\", "\\\\").replace(BLOCK_MARKER, "\\$BLOCK_MARKER")

    private fun decodeBlock(text: String): String =
        text.replace("\\$BLOCK_MARKER", BLOCK_MARKER).replace("\\\\", "\\")

    /**
     * Only the first line of a block may declare its stamp/version. Values are
     * raw snapshot text and may contain `\n` + `stamp:…`; scanned line by line
     * ("last one wins") such a value forged the timestamp, version and grade.
     */
    private fun parse(block: String): ScanLogEntry? {
        val header = block.lineSequence().firstOrNull()?.trim().orEmpty()
        var stampedAt = 0L
        var versionName: String? = null
        var versionCode = -1L
        var grade: Char? = null
        if (header.startsWith(STAMP)) {
            val parts = header.removePrefix(STAMP).split('|')
            stampedAt = parts.getOrNull(0)?.toLongOrNull() ?: 0L
            versionName = parts.getOrNull(1)?.takeIf { it.isNotBlank() && it != "?" }
            versionCode = parts.getOrNull(2)?.toLongOrNull() ?: -1L
            grade = parts.getOrNull(3)?.firstOrNull()
        } else if (header.startsWith(VERSION)) {
            // Legacy snapshot written before the log existed.
            val match = versionLine.find(header)
            if (match != null) {
                versionName = match.groupValues[1].trim().takeIf { it.isNotEmpty() && it != "null" }
                versionCode = match.groupValues[2].toLongOrNull() ?: -1L
            }
        }
        return ScanLogEntry(
            stampedAtMs = stampedAt,
            versionName = versionName ?: "?",
            versionCode = versionCode,
            grade = grade,
            snapshot = decodeBlock(block),
        )
    }
}
