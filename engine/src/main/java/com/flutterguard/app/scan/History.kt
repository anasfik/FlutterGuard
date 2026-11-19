package com.flutterguard.app.scan

/**
 * Version-diff audits: every scan writes a compact snapshot next to the JSON
 * report, and the next scan of the same package is compared against it. This is
 * the only signal a static artifact can give you that a human reviewer cannot
 * get from a single scan — what the update changed.
 *
 * The snapshot stays line-oriented plain text. New snapshots append a versioned
 * `cmp2:` block with the categories the original format lacked (permissions,
 * providers, native libraries, finding kind/provenance, network policy,
 * signing). Old snapshots keep parsing exactly as before and are never
 * rewritten; a category they did not record is UNAVAILABLE for a comparison,
 * never an empty set and never a removal.
 */
object History {

    private const val STAMP = "stamp:"
    private const val HOSTS = "hosts:"
    private const val ROUTES = "routes:"
    private const val FINDINGS = "findings:"
    private const val DEPS = "deps:"
    private const val VERSION = "version:"

    /** Extension marker, format version, recorded package and the categories written. */
    private const val CMP = "cmp2:"
    private const val CMP_VERSION = "1"
    private const val PKG_ATTR = "pkg="
    private const val CUT = "cut:"
    private const val PERM = "perm:"
    private const val PROVIDER = "provider:"
    private const val NATIVE = "native:"
    private const val FIND = "find:"
    private const val NET = "net:"
    private const val SIGN = "sign:"

    /**
     * Bounds on the extended block. A truncation is recorded explicitly (`cut:`)
     * so the category is treated as unavailable instead of silently incomplete.
     */
    private const val MAX_FINDINGS = 300
    private const val MAX_NETWORK = 120

    private val EXTENDED_CATEGORIES = listOf(
        DiffCategory.PERMISSIONS,
        DiffCategory.PROVIDERS,
        DiffCategory.NATIVE_LIBS,
        DiffCategory.FINDINGS,
        DiffCategory.NETWORK_POLICY,
        DiffCategory.SIGNING,
    )

    /**
     * Stable, line-oriented snapshot. Values are sorted and scrubbed against the
     * report's privately retained secrets, so a recovered value can never reach
     * the history log. The `stamp:` header carries version/timestamp/grade for
     * the versioned log; [diff] ignores it and old snapshots still parse.
     */
    fun snapshot(r: Report): String = buildString {
        val scrub = Evidence.prepared(r.secretValues())
        val findingFacts = r.findings.flatMap { finding ->
            val id = flat(finding.id)
            finding.evidence
                .map { flat(scrub(it.source.ifBlank { "artifact" })) }
                .ifEmpty { listOf("artifact") }
                .map { source -> FindingSnapshot(id, finding.severity, finding.kind, source) }
        }
        // Aggregate first: three identical matches are one fact with a count,
        // never a silently deduplicated row.
        val counts = LinkedHashMap<String, Pair<FindingSnapshot, Int>>()
        for (fact in findingFacts) {
            val key = fact.key()
            counts[key] = fact to ((counts[key]?.second ?: 0) + 1)
        }
        val ordered = counts.values.sortedWith(
            compareBy({ it.first.id }, { it.first.source }, { it.first.severity.ordinal }, { it.first.kind.ordinal }),
        )
        val network = ordered.filter { it.first.id.startsWith("NET-") }
        val keptFindings = ordered.filterNot { it.first.id.startsWith("NET-") }.take(MAX_FINDINGS)
        val keptNetwork = network.take(MAX_NETWORK)

        appendLine(STAMP + "${r.generatedAt}|${flat(r.meta.versionName ?: "?")}|${r.meta.versionCode}|${r.grade}")
        appendLine(VERSION + "${flat(r.meta.versionName ?: "null")} (${r.meta.versionCode})")
        appendLine(HOSTS + r.hosts.map { flat(scrub(it.host)) }.sorted().joinToString("|"))
        appendLine(ROUTES + r.routes.map { flat(scrub(it)) }.sorted().joinToString("|"))
        appendLine(FINDINGS + r.findings.map { "${it.severity}|${flat(it.id)}" }.distinct().sorted().joinToString("|"))
        appendLine(DEPS + r.framework.dartDeps.map { flat(scrub(it)) }.sorted().joinToString("|"))

        appendLine(
            CMP + (
                listOf(CMP_VERSION, "pkg=${flat(r.meta.packageName)}") + EXTENDED_CATEGORIES.map { it.name }
                ).joinToString("|"),
        )
        r.permissions.map { flat(scrub(it.name)) }.distinct().sorted().forEach { appendLine(PERM + it) }
        r.thirdParty.map { flat(scrub(it.service)) }.distinct().sorted().forEach { appendLine(PROVIDER + it) }
        r.meta.nativeLibs
            .groupBy { "${flat(it.abi)}/${flat(it.name)}" }
            .mapValues { (_, libs) -> libs.mapNotNull { it.sha256 }.minOrNull()?.let(::flat).orEmpty() }
            .toSortedMap()
            .forEach { (name, sha) -> appendLine(NATIVE + "$name=$sha") }
        keptFindings.forEach { (fact, times) -> appendLine(FIND + fact.encode(times)) }
        keptNetwork.forEach { (fact, times) -> appendLine(NET + fact.encode(times)) }
        r.signing.sha256Fingerprint?.let { appendLine(SIGN + flat(it)) }
        if (ordered.count { !it.first.id.startsWith("NET-") } > keptFindings.size) {
            appendLine(CUT + DiffCategory.FINDINGS.name)
        }
        if (network.size > keptNetwork.size) appendLine(CUT + DiffCategory.NETWORK_POLICY.name)
    }

    /**
     * Human-readable delta between two snapshots. `+` appeared, `-` disappeared,
     * `~` changed in place, `?` a category the older scan did not record.
     */
    fun diff(old: String, new: String): List<String> {
        val a = parseFacts(old) ?: return emptyList()
        val b = parseFacts(new) ?: return emptyList()
        // A storage-name collision (`com.a_b` vs `com.a.b`) can put another
        // app's scan in this log; never diff two subjects.
        val beforePackage = a.packageName
        val afterPackage = b.packageName
        if (beforePackage != null && afterPackage != null && beforePackage != afterPackage) {
            return listOf("not compared: these scans belong to different packages ($beforePackage vs $afterPackage)")
        }
        val sameFormat = (a.extended == null) == (b.extended == null)
        val oldFacts = factsOf(a)
        val newFacts = factsOf(b)
        val formatSkip = if (sameFormat) emptySet() else setOf(DiffCategory.FINDINGS, DiffCategory.NETWORK_POLICY)
        val skipped = oldFacts.unavailable + newFacts.unavailable + formatSkip

        val changes = ArrayList<ReportChange>()
        a.version?.let { before ->
            b.version?.let { after ->
                if (before != after) changes += ReportChange(DiffCategory.VERSION, DiffChange.CHANGED, "$before → $after")
            }
        }
        changes += DiffEngine.compare(oldFacts, newFacts, skipped)
        val sorted = changes.sortedWith(CHANGE_ORDER)

        // Per-category bounds keep the inline card readable; the global bound is
        // the same one the log always had. This list is a summary — the complete
        // change set comes from History.changeLines(comparison).
        val out = ArrayList<String>()
        sorted.firstOrNull { it.category == DiffCategory.VERSION }?.let { out += line(it) }
        val grouped = sorted.filter { it.category != DiffCategory.VERSION }.groupBy { it.category }
        for (category in DiffCategory.entries) {
            val limit = if (category == DiffCategory.DEPENDENCIES) 8 else 12
            grouped[category].orEmpty().take(limit).forEach { out += line(it) }
        }
        if (out.size > 40) {
            val extra = out.size - 39
            out.subList(39, out.size).clear()
            out += "… $extra more (see the complete comparison)"
        }
        // Two records from the original format have the same (smaller) category
        // set, so they stay quiet; anything extended is explicit about what the
        // pair could not answer.
        val notes = if (a.extended == null && b.extended == null) {
            emptyList()
        } else {
            notesFor(oldFacts.unavailable, newFacts.unavailable, formatSkip)
        }
        if (out.isEmpty()) {
            out += if (notes.isEmpty()) {
                "no change in hosts, routes, findings or dependencies"
            } else {
                "no comparison in the categories recorded by both scans"
            }
        }
        out += notes
        return out
    }

    /**
     * Diff a new snapshot against the newest scan recorded in [previousLog].
     *
     * The log keeps up to [ScanLog.MAX_ENTRIES] blocks; diffing the whole text
     * would accumulate the extended categories across every block and subtract
     * any older `cut:` globally, blaming today's scan for an old removal and
     * hiding a re-added value. An empty or unparseable log has no baseline.
     */
    fun diffAgainstLatestIn(previousLog: String, snapshot: String): List<String> {
        val latest = ScanLog.decode(previousLog).lastOrNull()?.snapshot ?: return emptyList()
        return diff(latest, snapshot)
    }

    /** One explicit `?` line per category that was skipped, worded for the side that lacks it. */
    private fun notesFor(
        oldMissing: Set<DiffCategory>,
        newMissing: Set<DiffCategory>,
        formatSkip: Set<DiffCategory>,
    ): List<String> {
        val notes = ArrayList<String>()
        for (category in DiffCategory.entries) {
            val note = when {
                category in formatSkip -> "? ${plural(category)} not comparable across snapshot formats"
                category in oldMissing && category in newMissing -> "? ${plural(category)} unavailable in both scans"
                category in oldMissing -> "? ${plural(category)} unavailable in the older snapshot"
                category in newMissing -> "? ${plural(category)} unavailable in the newer scan"
                else -> null
            }
            if (note != null) notes += note
        }
        return notes
    }

    private fun line(change: ReportChange): String {
        val prefix = when (change.change) {
            DiffChange.ADDED -> "+"
            DiffChange.REMOVED -> "-"
            DiffChange.CHANGED -> "~"
        }
        val detail = change.detail?.let { " — $it" }.orEmpty()
        val times = if (change.occurrences > 1) " ×${change.occurrences}" else ""
        return "$prefix ${change.category.label} ${change.identity}$detail$times"
    }

    private fun plural(category: DiffCategory): String = when (category) {
        DiffCategory.VERSION -> "version"
        DiffCategory.PERMISSIONS -> "permissions"
        DiffCategory.HOSTS -> "hosts"
        DiffCategory.ROUTES -> "routes"
        DiffCategory.PROVIDERS -> "providers"
        DiffCategory.DEPENDENCIES -> "dependencies"
        DiffCategory.NATIVE_LIBS -> "native libraries"
        DiffCategory.FINDINGS -> "findings"
        DiffCategory.NETWORK_POLICY -> "network policy findings"
        DiffCategory.SIGNING -> "signing certificate"
    }

    /**
     * Comparison of the retained scan at [index] with the newest earlier entry
     * of a genuinely different version, or null when there is no such entry
     * (first scan) or the log cannot be parsed. The newest scan of a version is
     * not its own baseline.
     */
    fun comparison(
        entries: List<ScanLogEntry>,
        index: Int,
        packageName: String,
        namespace: ScanNamespace,
    ): ReportComparison? {
        val previousIndex = previousDifferentIndex(entries, index) ?: return null
        return comparisonAt(entries, previousIndex, index, packageName, namespace)
    }

    /**
     * Unbounded comparison of the retained scan at [index] with the immediately
     * previous retained scan, whatever its version: the complete set behind the
     * inline "changes since last scan" card and its See-all route.
     */
    fun comparisonForPreviousScan(
        entries: List<ScanLogEntry>,
        index: Int,
        packageName: String,
        namespace: ScanNamespace,
    ): ReportComparison? {
        if (index <= 0) return null
        return comparisonAt(entries, index - 1, index, packageName, namespace)
    }

    /** Every change of a comparison as display lines, with no category or line bound. */
    fun changeLines(comparison: ReportComparison): List<String> =
        if (comparison.rejected) {
            listOfNotNull(comparison.rejectedReason?.let { "? $it" })
        } else {
            comparison.changes.map { line(it) }
        }

    private fun comparisonAt(
        entries: List<ScanLogEntry>,
        previousIndex: Int,
        index: Int,
        packageName: String,
        namespace: ScanNamespace,
    ): ReportComparison? {
        val previous = entries.getOrNull(previousIndex) ?: return null
        val current = entries.getOrNull(index) ?: return null
        val a = parseFacts(previous.snapshot) ?: return null
        val b = parseFacts(current.snapshot) ?: return null
        val beforeVersion = ReportIdentity(
            packageName = a.packageName ?: packageName,
            versionName = previous.versionName.takeIf { it != "?" },
            versionCode = previous.versionCode,
            namespace = namespace,
        )
        val afterVersion = ReportIdentity(
            packageName = b.packageName ?: packageName,
            versionName = current.versionName.takeIf { it != "?" },
            versionCode = current.versionCode,
            namespace = namespace,
        )
        // The history file is keyed by a lossy storage name, so a collision can
        // put another app's block in this log. Never compare two subjects.
        if (beforeVersion.packageName != packageName || afterVersion.packageName != packageName) {
            val foreign = beforeVersion.packageName.takeIf { it != packageName }
                ?: afterVersion.packageName.takeIf { it != packageName }
                ?: afterVersion.packageName
            return ReportComparison(
                status = ComparisonStatus.PACKAGE_MISMATCH,
                before = beforeVersion.copy(packageName = packageName),
                after = afterVersion.copy(packageName = if (foreign == packageName) beforeVersion.packageName else foreign),
            )
        }
        val sameFormat = (a.extended == null) == (b.extended == null)
        val oldFacts = factsOf(a)
        val newFacts = factsOf(b)
        val formatSkip = if (sameFormat) emptySet() else setOf(DiffCategory.FINDINGS, DiffCategory.NETWORK_POLICY)
        val unavailable = oldFacts.unavailable + newFacts.unavailable + formatSkip

        val changes = ArrayList<ReportChange>()
        if (beforeVersion.versionLabel != afterVersion.versionLabel) {
            changes += ReportChange(
                DiffCategory.VERSION,
                DiffChange.CHANGED,
                "${beforeVersion.versionLabel} → ${afterVersion.versionLabel}",
            )
        }
        changes += DiffEngine.compare(oldFacts, newFacts, unavailable)
        return ReportComparison(
            status = ComparisonStatus.COMPARED,
            before = beforeVersion,
            after = afterVersion,
            changes = changes.sortedWith(CHANGE_ORDER),
            unavailable = unavailable,
            coalesced = changes.sumOf { (it.occurrences - 1).coerceAtLeast(0) },
        )
    }

    /** Index of the newest earlier entry whose version is genuinely different, if any. */
    internal fun previousDifferentIndex(entries: List<ScanLogEntry>, index: Int): Int? {
        val current = entries.getOrNull(index) ?: return null
        for (i in index - 1 downTo 0) {
            val entry = entries[i]
            if (entry.versionCode != current.versionCode || entry.versionName != current.versionName) return i
        }
        return null
    }

    // --------------------------------------------------------------- snapshot

    private data class FindingSnapshot(
        val id: String,
        val severity: Severity,
        val kind: FindingKind,
        val source: String,
    ) {
        /** Identity of the fact; duplicates differ only by occurrence count. */
        fun key(): String = "$severity|$kind|$id|$source"

        /** `severity|kind|count|id|source`; the count sits before the free-text source. */
        fun encode(occurrences: Int): String = "$severity|$kind|$occurrences|$id|$source"
    }

    private class Extended(
        val available: Set<DiffCategory>,
        val permissions: List<String>,
        val providers: List<String>,
        val native: Map<String, DiffFact>,
        val findings: Map<String, DiffFact>,
        val network: Map<String, DiffFact>,
        val signing: String?,
    )

    private class Snapshot(
        val version: String?,
        val hosts: List<String>,
        val routes: List<String>,
        val legacyFindings: List<String>,
        val deps: List<String>,
        val extended: Extended?,
        /** Package recorded in the extension, when the snapshot has one. */
        val packageName: String?,
    )

    /** A value never gets to start a new snapshot line of its own. */
    private fun flat(value: String): String = value.replace('\r', ' ').replace('\n', ' ')

    /**
     * Parses a snapshot. Legacy keys keep their old "last line wins" behaviour;
     * the `cmp2:` block is additive and its absence means "not recorded".
     */
    private fun parseFacts(text: String): Snapshot? {
        var version: String? = null
        var hosts = emptyList<String>()
        var routes = emptyList<String>()
        var legacyFindings = emptyList<String>()
        var deps = emptyList<String>()
        var recognized = false
        var hasExtension = false
        var recordedPackage: String? = null
        val available = HashSet<DiffCategory>()
        val cut = HashSet<DiffCategory>()
        val permissions = ArrayList<String>()
        val providers = ArrayList<String>()
        val native = HashMap<String, DiffFact>()
        val findings = HashMap<String, DiffFact>()
        val network = HashMap<String, DiffFact>()
        var signing: String? = null

        for (raw in text.lineSequence()) {
            val line = raw.trim()
            when {
                line.startsWith(STAMP) -> Unit
                line.startsWith(VERSION) -> {
                    version = line.removePrefix(VERSION).trim()
                    recognized = true
                }
                line.startsWith(HOSTS) -> {
                    hosts = columns(line.removePrefix(HOSTS))
                    recognized = true
                }
                line.startsWith(ROUTES) -> {
                    routes = columns(line.removePrefix(ROUTES))
                    recognized = true
                }
                line.startsWith(FINDINGS) -> {
                    legacyFindings = findingColumns(line.removePrefix(FINDINGS))
                    recognized = true
                }
                line.startsWith(DEPS) -> {
                    deps = columns(line.removePrefix(DEPS))
                    recognized = true
                }
                line.startsWith(CMP) -> {
                    hasExtension = true
                    line.removePrefix(CMP).split('|').drop(1).forEach { token ->
                        if (token.startsWith(PKG_ATTR)) {
                            recordedPackage = token.removePrefix(PKG_ATTR).trim().ifBlank { null }
                        } else {
                            DiffCategory.entries.firstOrNull { it.name == token }?.let { available += it }
                        }
                    }
                    recognized = true
                }
                line.startsWith(CUT) -> {
                    DiffCategory.entries.firstOrNull { it.name == line.removePrefix(CUT).trim() }?.let { cut += it }
                    recognized = true
                }
                line.startsWith(PERM) -> {
                    permissions += line.removePrefix(PERM)
                    recognized = true
                }
                line.startsWith(PROVIDER) -> {
                    providers += line.removePrefix(PROVIDER)
                    recognized = true
                }
                line.startsWith(NATIVE) -> {
                    val body = line.removePrefix(NATIVE)
                    val separator = body.indexOf('=')
                    if (separator > 0) {
                        native[body.substring(0, separator)] =
                            DiffFact(detail = body.substring(separator + 1).ifBlank { null })
                    }
                    recognized = true
                }
                line.startsWith(FIND) -> {
                    decodeFinding(line.removePrefix(FIND))?.let { (key, fact) -> findings.merge(key, fact, ::mergeFact) }
                    recognized = true
                }
                line.startsWith(NET) -> {
                    decodeFinding(line.removePrefix(NET))?.let { (key, fact) -> network.merge(key, fact, ::mergeFact) }
                    recognized = true
                }
                line.startsWith(SIGN) -> {
                    signing = line.removePrefix(SIGN).trim().ifBlank { null }
                    recognized = true
                }
            }
        }
        if (!recognized) return null

        val extended = if (!hasExtension) null else Extended(
            available = available - cut,
            permissions = permissions,
            providers = providers,
            native = native,
            findings = findings,
            network = network,
            signing = signing,
        )
        return Snapshot(version, hosts, routes, legacyFindings, deps, extended, recordedPackage)
    }

    private fun columns(body: String): List<String> =
        if (body.isBlank()) emptyList() else body.split('|')

    private fun findingColumns(body: String): List<String> {
        val items = columns(body)
        // Findings are stored as severity|id pairs, so the field separator
        // collides with the pair separator. Fold pairs back together; older
        // snapshots on disk were written that way and must still diff.
        return if (items.size % 2 == 0) items.chunked(2).map { it.joinToString("|") } else items
    }

    /**
     * `severity|kind|count|id|source` for snapshots written by this build, and
     * the older `severity|kind|id|source` shape. The count is recognised by
     * position, so a source containing `|` still round-trips.
     */
    private fun decodeFinding(body: String): Pair<String, DiffFact>? {
        val parts = body.split('|', limit = 5)
        if (parts.size < 4) return null
        val severity = runCatching { Severity.valueOf(parts[0]) }.getOrNull() ?: return null
        val kind = FindingKind.parse(parts[1]) ?: FindingKind.SUSPECTED
        val count = parts[2].toIntOrNull()
        val id: String
        val source: String
        if (count != null && parts.size == 5) {
            id = parts[3]
            source = parts[4]
        } else {
            id = parts[2]
            source = parts.drop(3).joinToString("|")
        }
        if (id.isBlank()) return null
        return "${id} @ ${source.ifBlank { "artifact" }}" to
            DiffFact(severity = severity, kind = kind, occurrences = (count ?: 1).coerceAtLeast(1))
    }

    private fun mergeFact(a: DiffFact, b: DiffFact): DiffFact = a.copy(occurrences = a.occurrences + b.occurrences)

    private fun factsOf(snapshot: Snapshot): DiffFacts {
        val categories = LinkedHashMap<DiffCategory, Map<String, DiffFact>>()
        categories[DiffCategory.HOSTS] = snapshot.hosts.distinct().associateWith { DiffFact() }
        categories[DiffCategory.ROUTES] = snapshot.routes.distinct().associateWith { DiffFact() }
        categories[DiffCategory.DEPENDENCIES] = snapshot.deps.distinct().associateWith { DiffFact() }
        val unavailable = HashSet<DiffCategory>()
        val extended = snapshot.extended
        if (extended == null) {
            // Legacy snapshot: only the original four categories exist.
            categories[DiffCategory.FINDINGS] = snapshot.legacyFindings.distinct().associateWith { DiffFact() }
            unavailable += EXTENDED_CATEGORIES.filter { it != DiffCategory.FINDINGS }
        } else {
            if (DiffCategory.PERMISSIONS in extended.available) {
                categories[DiffCategory.PERMISSIONS] = extended.permissions.distinct().associateWith { DiffFact() }
            } else unavailable += DiffCategory.PERMISSIONS
            if (DiffCategory.PROVIDERS in extended.available) {
                categories[DiffCategory.PROVIDERS] = extended.providers.distinct().associateWith { DiffFact() }
            } else unavailable += DiffCategory.PROVIDERS
            if (DiffCategory.NATIVE_LIBS in extended.available) {
                categories[DiffCategory.NATIVE_LIBS] = extended.native
            } else unavailable += DiffCategory.NATIVE_LIBS
            if (DiffCategory.FINDINGS in extended.available) {
                categories[DiffCategory.FINDINGS] = extended.findings
            } else unavailable += DiffCategory.FINDINGS
            if (DiffCategory.NETWORK_POLICY in extended.available) {
                categories[DiffCategory.NETWORK_POLICY] = extended.network
            } else unavailable += DiffCategory.NETWORK_POLICY
            if (DiffCategory.SIGNING in extended.available) {
                val signing = extended.signing
                if (signing == null) unavailable += DiffCategory.SIGNING
                else categories[DiffCategory.SIGNING] = mapOf("certificate" to DiffFact(detail = signing))
            } else unavailable += DiffCategory.SIGNING
        }
        return DiffFacts(categories, unavailable)
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
        splitBlocks(text).mapNotNull { block -> parse(block) }

    /**
     * Human diff against the previous entry of a genuinely different version,
     * empty when there is none. A same-version rescan is not a version baseline.
     */
    fun diffForPreviousVersion(entries: List<ScanLogEntry>, index: Int): List<String> {
        val current = entries.getOrNull(index) ?: return emptyList()
        val previousIndex = History.previousDifferentIndex(entries, index) ?: return emptyList()
        return History.diff(entries[previousIndex].snapshot, current.snapshot)
    }

    /**
     * Diff against the immediately previous retained scan, whatever its version.
     * This is the "what did this scan change" view: a same-version rescan can
     * show artifact changes but never a version change line.
     */
    fun diffForPreviousScan(entries: List<ScanLogEntry>, index: Int): List<String> {
        val current = entries.getOrNull(index) ?: return emptyList()
        val previous = entries.getOrNull(index - 1) ?: return emptyList()
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
